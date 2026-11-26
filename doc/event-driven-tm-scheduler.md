# Event-Driven Egress Scheduler

```
Ingress Pipeline → egress queues → Egress Pipeline → transfer buffer → Output Port
```

This document describes the default egress path of v1model and PSA, and the
output queues of PNA. With `EnableVoqFabric`, a v1model switch sends its packets
through the traffic manager instead; see [traffic-manager.md](traffic-manager.md).

The egress queues (`NSQueueingLogicPriRL`) are per port and per priority. As in
BMv2, a queue has no rate limit unless one is set (`set_queue_rate`,
`SetEgressQueueRate()`); then a packet leaves only when the time since the
previous one satisfies the rate. `SwitchRate` limits the ingress instead.

After the egress pipeline, each port has a transfer buffer of
`TransferBufferSize` frames (0 by default): a FIFO that stands for the port queue
of a hardware switch. A port takes its next packet from the egress queues when it
is idle or its transfer buffer has room; the packet passes the egress pipeline
at once and waits in the buffer, in order, for the frames before it. With 0, a
port takes a packet only when it is idle, and the buffer stays empty.

## Events

A port is served only when something changes, so no event runs while the queues
are empty (an earlier version polled the queues with a timer):

1. **A packet is enqueued**: `Enqueue()` calls `ScheduleEgressIfNeeded(port)`.
2. **A port has sent its frame**: `P4SwitchNetDevice` calls `PortTxComplete(port)`.

`P4SwitchNetDevice` puts each frame on the port's channel and ends the
transmission one serialisation time later (the frame size at the channel's
`DataRate`). Then it calls the port-TX-done callback that `DoInitialize()`
registers:

```
P4SwitchNetDevice::SendNs3Packet(port) → TransmitOn(port)    [channel: TransmitStart]
        ... one serialisation time ...
P4SwitchNetDevice::PortTransmitEnd(port)                     [channel: TransmitEnd]
    → port-TX-done callback
    → P4CoreV1model::PortTxComplete(port)
    → ScheduleEgressIfNeeded(port)
```

When the egress drops or recirculates a packet, nothing goes to the port:
`EgressDone()` lets the port take its next packet, and leaves it busy if it is
sending. When the device refuses a frame (an invalid port, a busy channel), the
core calls `PortTxComplete()` itself at once, so that the port is not left busy.

## Functions

**`ScheduleEgressIfNeeded(port)`**, called from `Enqueue()`, `PortTxComplete()`
and after a frame is sent or buffered: returns if the port can take no packet (it
is busy and its transfer buffer is full). Otherwise it cancels a pending dequeue
of this port, asks `get_next_tp_for_port(port)` for the earliest time a packet of
this port may leave, and schedules `EventDrivenEgressDequeue(port)` for then.

**`EventDrivenEgressDequeue(port)`**:
1. Returns if the port can take no packet; `PortTxComplete()` will retry.
2. Takes one rate-eligible packet with `pop_back_for_port(port)`. If there is
   none, it reschedules itself at the next eligible time.
3. Runs the egress pipeline (MAU, deparser, clone, recirculate).
4. `SendOrBuffer()`: appends the frame to the port's transfer buffer and, if the
   port is free, marks it busy and sends the oldest frame with `SendNs3Packet()`;
   then asks for the next packet, which the port takes if its buffer has room.

**`PortTxComplete(port)`**: clears `busy`. If frames wait in the transfer buffer,
it schedules `TransmitFromBuffer(port)` in the same instant, which sends the
oldest one and then asks for the next packet (the device calls `PortTxComplete()`
from its end of transmission and does not expect a new frame from there).
Otherwise it calls `ScheduleEgressIfNeeded(port)` if the port's queues are not
empty.

The state of a port:

```cpp
struct PortTxState {
    bool    busy{false};       // true while a frame is on the wire
    EventId pendingEvent{};    // the next scheduled dequeue attempt
    EventId txCompleteEvent{}; // PortTxComplete() for a frame the device refused
    EventId bufferEvent{};     // the pending TransmitFromBuffer()
};
std::unordered_map<uint32_t, PortTxState> m_portTxState;
// in P4SwitchCore: the transfer buffer of each port, oldest frame first
std::unordered_map<uint32_t, std::deque<TransferFrame>> m_transferBuffers;
```

`m_linkRateBps` is read from port 0's channel when the switch starts. The VOQ
path uses it as the traffic manager's `PortRate`; the default path only logs it.

## Properties

- **One frame per port on the wire.** `busy` is set before `SendNs3Packet()` and
  cleared only in `PortTxComplete()`; both scheduling functions return while it
  is set.
- **Delays.** The ingress and egress pipelines take no simulated time
  themselves. `PipelineDelay` delays every packet once, before it reaches the
  egress queues (again for each recirculated pass). The other delays come from
  `SwitchRate`, the queue rates, the serialisation on the port's channel and the
  channel's propagation delay.
- **Transfer buffer.** It never drops: a port takes a packet only while there is
  room. A frame in it has passed the egress and is not overtaken any more, so a
  high-priority packet that arrives later waits behind it. The backlog of a
  congested port stays in the egress queues, and `enq_qdepth` and `deq_qdepth`
  do not count the frames in the transfer buffer. A program swap (`EnableSwap`)
  waits for these frames too.
- **Clones and recirculation.** Egress clones go through `Enqueue()`, like any
  packet. A recirculated packet goes back to the ingress input buffer
  (`AdmitToIngress()`), and `EgressDone()` lets the port take its next packet.
- **Queue rates.** `push_front()` stamps each packet with
  `send = max(now, prev_send + 1/rate)`, and `pop_back_for_port()` takes a packet
  only when `send <= now`: a leaky bucket without bursts.
- **Priorities.** A packet of P4 priority *p* goes into queue *p*, and
  `pop_back_for_port()` serves the queues from `N-1` down to `0`, so priority 7
  goes first, as in BMv2's `simple_switch`. `enq_qdepth` and `deq_qdepth` count
  the packets of the packet's own priority queue, and `qid` is that queue.
  Strict priority: a queue that is never empty starves the lower ones.

## PNA

PNA has no egress pipeline: its main pipeline puts each frame into a FIFO queue
of the frame's port, after `PipelineDelay` if one is set (`QueueBufferSize`
frames; a frame that finds the queue full is dropped). `ScheduleTxIfNeeded(port)` hands the oldest frame to the device when
the port is free, and the same port-TX-done callback calls `PortTxComplete(port)`.

## Files

| File | Role |
|------|------|
| `model/p4-core-v1model.cc` / `.h` | Scheduler and port state of v1model |
| `model/p4-core-psa.cc` / `.h` | The same for PSA |
| `model/p4-nic-pna.cc` / `.h` | PNA: `ScheduleTxIfNeeded()`, `PortTxComplete()` |
| `model/p4-switch-net-device.cc` / `.h` | `TransmitOn()`, `PortTransmitEnd()`, `SetPortTxDoneCallback()` |
| `utils/p4-queue.h` | `NSQueueingLogicPriRL`: `get_next_tp_for_port()`, `pop_back_for_port()` |
