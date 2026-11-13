# Event-Driven Egress Scheduler

## Background

The ns-3 P4 switch follows the standard programmable-switch pipeline:

```
Ingress Pipeline → egress queues → Egress Pipeline → Output Port
```

This document describes the default egress path. With `EnableVoqFabric`, packets go to the
Traffic Manager instead; see [traffic-manager.md](traffic-manager.md).

The egress queues (`NSQueueingLogicPriRL`) are per port and per priority, and each queue can have
a rate limit (pps): a packet may only be dequeued once the time since the previous dequeue
satisfies the queue's rate. As in BMv2, the queues have no rate limit unless one is set with
`SetEgressQueueRate()` and the like; `SwitchRate` limits the ingress pipeline instead (see the
README).

---

## Problem: Polling-Based Scheduler

The original implementation used a **periodic polling timer** started in `start_and_return_()`.
At each tick it called `HandleEgressPipeline()` to scan queues.

| Issue | Description |
|-------|-------------|
| Wasted events | Timer fires even when queues are empty, generating O(ports × queues) useless events per tick. |
| Implicit delay | The polling interval conflated rate shaping, pipeline delay, and link serialisation. |
| No port model | Packets could be dequeued faster than the underlying link speed. |

---

## Solution: Event-Driven Scheduler

Scheduling events are created **only by relevant state changes**:

1. **A packet is enqueued** → `Enqueue()` calls `ScheduleEgressIfNeeded(port)`.
2. **A port finishes transmitting** → `P4SwitchNetDevice` calls `PortTxComplete(port)`.

No timer runs while the queues are empty.

### Transmit-complete chain

`P4SwitchNetDevice` puts each frame on the port's `SwitchedEthernetChannel` and schedules the end
of the transmission one serialisation time later (the frame size at the channel's `DataRate`).
Then it releases the channel and calls the port-TX-done callback that `DoInitialize()` registers:

```
P4SwitchNetDevice::SendNs3Packet(port) → TransmitOn(port)    [channel: TransmitStart]
        ... one serialisation time ...
P4SwitchNetDevice::PortTransmitEnd(port)                     [channel: TransmitEnd]
    → port-TX-done callback
    → P4CoreV1model::PortTxComplete(port)
    → ScheduleEgressIfNeeded(port)
```

When the device does not send a frame (the drop port, an invalid port, a busy channel), the core
calls `PortTxComplete()` itself at once, so that the port is not left marked busy.

### Key Functions

**`ScheduleEgressIfNeeded(port)`**, called from `Enqueue()` and `PortTxComplete()`:
- If the port is **busy**, it returns; `PortTxComplete()` will retry.
- It cancels a pending dequeue event of this port, asks `get_next_tp_for_port(port)` for the
  earliest time a packet of this port may leave, and schedules `EventDrivenEgressDequeue(port)`
  for then.

**`EventDrivenEgressDequeue(port)`**, the core dequeue function:
1. Returns if the port or its channel is busy; `PortTxComplete()` will retry.
2. Calls `pop_back_for_port(port)` for one rate-eligible packet. If there is none, it reschedules
   itself at the next eligible time.
3. Runs the egress pipeline (MAU, deparser, clone, recirculate).
4. Marks the port busy and calls `SendNs3Packet()`. If the port has a QueueDisc, it enqueues the
   packet there instead and calls `TryTransmitFromQueueDisc()`.

**`PortTxComplete(port)`**, the port is free again:
- Clears `busy`.
- Sends the next packet of the port's QueueDisc, if the port has one with packets in it.
- Otherwise calls `ScheduleEgressIfNeeded(port)` if the port's egress queues are not empty.

### Per-Port State

```cpp
struct PortTxState {
    bool    busy{false};      // true while a frame is on the wire
    EventId pendingEvent{};   // the next scheduled dequeue attempt
};
std::unordered_map<uint32_t, PortTxState> m_portTxState;
```

`m_linkRateBps` is read from port 0's channel when the switch starts. The VOQ path uses it as the
Traffic Manager's `PortRate`; on the default path it is only logged.

---

## Comparison

| Property | Polling | Event-driven v1 | Event-driven (current) |
|----------|---------|-----------------|------------------------|
| Idle events | O(1/tick)/port | Zero | Zero |
| Serialisation delay | None | Self-scheduled (`bits/rate`), double-counted | Scheduled once by `P4SwitchNetDevice` from the channel's rate |
| `PortTxComplete` trigger | N/A | `Simulator::Schedule` in the core | Port-TX-done callback from `P4SwitchNetDevice::PortTransmitEnd()` |

---

## Files

| File | Role |
|------|------|
| `model/p4-core-v1model.cc` / `.h` | Event-driven scheduler, per-port state |
| `model/p4-core-psa.cc` / `.h` | The same scheduler for PSA |
| `model/p4-switch-net-device.cc` / `.h` | `TransmitOn()`, `PortTransmitEnd()`, `SetPortTxDoneCallback()` |
| `utils/p4-queue.h` | `NSQueueingLogicPriRL`: `get_next_tp_for_port()`, `pop_back_for_port()` |

v1model and PSA use this path. PNA (`p4-nic-pna`) still schedules its own transmit-complete event
from the link rate and is not migrated yet.

---

## Design Notes

**At-most-one-frame-in-flight guarantee:**
`pstate.busy` is set before `SendNs3Packet` and cleared only in `PortTxComplete`. Guards in
both `ScheduleEgressIfNeeded` and `EventDrivenEgressDequeue` return immediately if the port
is busy. Single-threaded ns-3 ensures no race conditions.

**Pipeline processing delay:**
Ingress and egress pipeline processing take no simulated time, as usual in ns-3. The delays come
from `SwitchRate` (how many packets per second the ingress pipeline takes), the queue rates (via
`QueueInfoPri::pkt_delay_time`), the serialisation on the port's channel, and the channel's
propagation delay.

**Clone and recirculate:**
Egress clones call `Enqueue()` → `ScheduleEgressIfNeeded()`, the same path as any normal
packet. Recirculated packets go back to the ingress input buffer (`AdmitToIngress()`);
`PortTxComplete()` is called at once to release the port.

**Idle behaviour:**
`PortTxComplete` only calls `ScheduleEgressIfNeeded` if the queue is non-empty.
`ScheduleEgressIfNeeded` is only called from `Enqueue` and `PortTxComplete`. When all
queues are empty, there are **zero** pending egress scheduler events.

**Queue rate enforcement:**
At enqueue time, `push_front()` stamps each packet with
`send = max(now, prev_send + 1/rate)`. `pop_back_for_port()` gates on `send <= now`.
This is a strict leaky-bucket model; no burst beyond one packet at the configured rate
is possible.

**Priority scheduling:**
`Enqueue()` puts a packet of P4 priority *p* into queue *p*, and `pop_back_for_port()` scans the
queues from `N-1` down to `0` and takes the first eligible packet. So priority 7 is served first,
as in BMv2's `simple_switch` (main's #37). `enq_qdepth` and `deq_qdepth` count the packets of the
packet's own priority queue, and `qid` is that queue. Scheduling is strict priority: a queue that
is never empty starves the queues served after it.
