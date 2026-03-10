# Event-Driven Traffic Manager Scheduler

## Background

The ns-3 P4 switch follows the standard programmable-switch pipeline:

```
Ingress Pipeline → Traffic Manager (TM) → Egress Pipeline → Output Port
```

The TM (`NSQueueingLogicPriRL`) maintains per-port, per-priority queues with per-queue rate
limits (pps).  A packet may only be dequeued once the elapsed time since the previous dequeue
satisfies the queue's rate constraint.

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

## Solution: Event-Driven Scheduler + PhyTxEnd Integration

Scheduling events are triggered **only by relevant state changes**:

1. **A packet is enqueued** → `Enqueue()` calls `ScheduleEgressIfNeeded()`.
2. **A port finishes transmitting** → the port NetDevice fires its `PhyTxEnd` trace, which
   propagates to `PortTxComplete()`.

No periodic timer is started at simulation launch.

### Architecture: PhyTxEnd Callback Chain

`AddBridgePort()` connects every port's `PhyTxEnd` trace to `OnPortTxEnd()`.
`DoInitialize()` registers the TM's `PortTxComplete` as the port-TX-done callback:

```
NetDevice::PhyTxEnd
    → P4SwitchNetDevice::OnPortTxEnd(srcDevice, packet)   [device ptr → port index]
    → P4CoreV1model::PortTxComplete(portIndex)
    → ScheduleEgressIfNeeded(portIndex)
```

This replaces the previous model where `EventDrivenEgressDequeue` computed
`tx_delay = bytes×8 / m_linkRateBps` and self-scheduled `PortTxComplete` — which
double-counted the serialisation delay already modelled by the NetDevice.

### Key Functions

**`ScheduleEgressIfNeeded(port)`** — called from `Enqueue()`:
- If port is **busy** → returns; `PortTxComplete` will retry.
- Cancels any stale pending event, queries `egress_buffer.get_next_tp_all_ports()` for the
  earliest rate-eligible time, then schedules `EventDrivenEgressDequeue(port)`.

**`EventDrivenEgressDequeue(port)`** — the core dequeue function:
1. Calls `egress_buffer.pop_back()` for one rate-eligible packet.
2. If nothing eligible: reschedules itself at the next eligible timestamp.
3. If a packet is dequeued: runs the full egress pipeline (MAU, deparser, clone, recirc).
4. Sets `pstate.busy = true`, calls `SendNs3Packet()`, then returns.  
   `PortTxComplete` is triggered later by the port's `PhyTxEnd` trace.

**`PortTxComplete(port)`** — triggered by `PhyTxEnd`:
- Sets `pstate.busy = false`.
- Calls `ScheduleEgressIfNeeded(port)` if the queue is non-empty.

### Per-Port State

```cpp
struct PortTxState {
    bool    busy{false};      // true while a packet is in flight on the link
    EventId pendingEvent{};   // handle to the next scheduled dequeue attempt
};
std::unordered_map<uint32_t, PortTxState> m_portTxState;
```

`busy` is set before `SendNs3Packet` and cleared only in `PortTxComplete`.
`m_linkRateBps` (read from port 0's `DataRate` at startup) is retained for
**logging/diagnostics only**; it no longer drives scheduling.

---

## Comparison

| Property | Polling | Event-driven v1 | Event-driven v2 (current) |
|----------|---------|-----------------|---------------------------|
| Idle events | O(1/tick)/port | Zero | Zero |
| Serialisation delay | None | Self-scheduled (`bits/rate`) — double-counted | Port `PhyTxEnd` — no double-counting |
| `PortTxComplete` trigger | N/A | `Simulator::Schedule` | `NetDevice::PhyTxEnd` trace |
| `PortTxState::busyUntil` | N/A | Stored | **Removed** |

---

## Affected Files

| File | Change |
|------|--------|
| `model/p4-core-v1model.cc` / `.h` | Event-driven scheduler; `PortTxState` cleaned up (`busyUntil` removed) |
| `model/p4-switch-net-device.cc` / `.h` | `AddBridgePort` hooks `PhyTxEnd`; `OnPortTxEnd` + `SetPortTxDoneCallback` added; `GetPortNumber` bug fixed |
| `utils/p4-queue.h` | Fixed iterator invalidation bug in queue size queries |

PSA (`p4-core-psa`) and PNA (`p4-nic-pna`) retain their own self-scheduled delay model
and are not yet migrated to the `PhyTxEnd` path.

---

## Design Notes

**Scheduling scope (per-port vs global):**  
Port busy/idle state is per-port (`m_portTxState[port]`), but `get_next_tp_all_ports()`
returns the global earliest eligible time. A port may occasionally wake up and find no
eligible packet for itself, then self-reschedule. This is correct but may generate one
spurious event per dequeue cycle. A per-port `get_next_tp(port)` API is a known future
improvement.

**At-most-one-packet-in-flight guarantee:**  
`pstate.busy` is set before `SendNs3Packet` and cleared only in `PortTxComplete`. Guards in
both `ScheduleEgressIfNeeded` and `EventDrivenEgressDequeue` return immediately if the port
is busy. Single-threaded ns-3 ensures no race conditions.

**Pipeline processing delay:**  
Ingress and egress pipeline processing is synchronous (zero simulated time), consistent with
standard ns-3 modelling convention. The meaningful delays are queue rate-shaping (via
`QueueInfoPri::pkt_delay_time`), link serialisation (via `PhyTxEnd`), and channel
propagation.

**Clone and recirculate:**  
Egress clones call `Enqueue()` → `ScheduleEgressIfNeeded()`, the same path as any normal
packet. Recirculated packets go to the ingress `InputBuffer`; `PortTxComplete` is called
immediately to release the port.

**Idle behaviour:**  
`PortTxComplete` only calls `ScheduleEgressIfNeeded` if the queue is non-empty.
`ScheduleEgressIfNeeded` is only called from `Enqueue` and `PortTxComplete`. When all
queues are empty, there are **zero** pending egress scheduler events.

**Queue rate enforcement:**  
At enqueue time, `push_front()` stamps each packet with
`send = max(now, prev_send + 1/rate)`. `pop_back()` gates on `send <= now`.
This is a strict leaky-bucket model; no burst beyond one packet at the configured rate
is possible.

**Priority scheduling:**  
`pop_back()` iterates queues from index `N-1` down to `0`. Because `Enqueue()` maps
P4 priority *p* to queue index `N-1-p`, queue 0 holds the highest-P4-priority traffic and
is served last in the scan — i.e., first eligible packet wins, with highest priority always
preferred. This is strict priority scheduling; low-priority queues can be starved if a
high-priority queue is continuously non-empty (intentional, consistent with BMv2).
