# Event-Driven Egress Scheduler

```
Ingress Pipeline → egress queues → Egress Pipeline → Output Port
```

This document describes the default egress path of v1model and PSA, and the
output queues of PNA. With `EnableVoqFabric`, a v1model switch sends its packets
through the traffic manager instead; see [traffic-manager.md](traffic-manager.md).

The egress queues (`NSQueueingLogicPriRL`) are per port and per priority. As in
BMv2, a queue has no rate limit unless one is set (`set_queue_rate`,
`SetEgressQueueRate()`); then a packet leaves only when the time since the
previous one satisfies the rate. `SwitchRate` limits the ingress instead.

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

When the device does not send a frame (the drop port, an invalid port, a busy
channel), the core calls `PortTxComplete()` itself at once, so that the port is
not left busy.

## Functions

**`ScheduleEgressIfNeeded(port)`**, called from `Enqueue()` and `PortTxComplete()`:
returns if the port is busy. Otherwise it cancels a pending dequeue of this port,
asks `get_next_tp_for_port(port)` for the earliest time a packet of this port may
leave, and schedules `EventDrivenEgressDequeue(port)` for then.

**`EventDrivenEgressDequeue(port)`**:
1. Returns if the port or its channel is busy; `PortTxComplete()` will retry.
2. Takes one rate-eligible packet with `pop_back_for_port(port)`. If there is
   none, it reschedules itself at the next eligible time.
3. Runs the egress pipeline (MAU, deparser, clone, recirculate).
4. Marks the port busy and calls `SendNs3Packet()`.

**`PortTxComplete(port)`**: clears `busy`, and calls `ScheduleEgressIfNeeded(port)`
if the port's queues are not empty.

The state of a port:

```cpp
struct PortTxState {
    bool    busy{false};      // true while a frame is on the wire
    EventId pendingEvent{};   // the next scheduled dequeue attempt
};
std::unordered_map<uint32_t, PortTxState> m_portTxState;
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
- **Clones and recirculation.** Egress clones go through `Enqueue()`, like any
  packet. A recirculated packet goes back to the ingress input buffer
  (`AdmitToIngress()`), and `PortTxComplete()` releases the port at once.
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
of the frame's port (`QueueBufferSize` frames; a frame that finds the queue full
is dropped). `ScheduleTxIfNeeded(port)` hands the oldest frame to the device when
the port is free, and the same port-TX-done callback calls `PortTxComplete(port)`.

## Files

| File | Role |
|------|------|
| `model/p4-core-v1model.cc` / `.h` | Scheduler and port state of v1model |
| `model/p4-core-psa.cc` / `.h` | The same for PSA |
| `model/p4-nic-pna.cc` / `.h` | PNA: `ScheduleTxIfNeeded()`, `PortTxComplete()` |
| `model/p4-switch-net-device.cc` / `.h` | `TransmitOn()`, `PortTransmitEnd()`, `SetPortTxDoneCallback()` |
| `utils/p4-queue.h` | `NSQueueingLogicPriRL`: `get_next_tp_for_port()`, `pop_back_for_port()` |
