# Event-Driven Traffic Manager Scheduler

## Background

In the ns-3 P4 switch model, packets are converted from `ns3::Packet` to `bm::Packet` at the
switch ingress and remain in BMv2's internal format throughout the pipeline.  The switch
architecture follows the standard programmable-switch structure:

```
Ingress Pipeline → Traffic Manager (TM) → Egress Pipeline → Output Port
```

The TM, inherited from BMv2 (`NSQueueingLogicPriRL`), maintains per-port, per-priority queues.
Each queue carries a *rate limit* (packets per second): a packet may only be dequeued once the
elapsed time since the previous dequeue satisfies the queue's configured rate constraint.

---

## Problem: Polling-Based Scheduler

The original implementation used a **periodic polling scheduler**.  On startup,
`start_and_return_()` scheduled a recurring `SetEgressTimerEvent()` callback at a fixed interval
(derived from the configured switch rate, e.g. `1/500 s`).  At each tick the callback called
`HandleEgressPipeline()`, which scanned queues from highest to lowest priority and attempted to
dequeue one eligible packet.

**Drawbacks:**

| Issue | Description |
|-------|-------------|
| Wasted events | A timer fires even when all queues are empty or not yet rate-eligible, generating O(ports × queues) useless simulator events per tick. |
| Implicit delay model | The polling interval conflated queue shaping delay, pipeline processing delay, and scheduling behaviour. A packet could wait up to one full polling interval even if the queue was already eligible. |
| No output-port model | The scheduler did not account for the time required to serialise a packet onto the physical link, making it possible to dequeue packets faster than the underlying link speed. |
| Fixed granularity | The polling interval was a global constant that could not adapt to heterogeneous traffic patterns or queue rates. |

---

## Solution: Event-Driven Scheduler

The scheduling mechanism was redesigned so that scheduling events are triggered **only by
relevant state changes**:

1. **A packet is enqueued** into a port's queue (`Enqueue()` → `ScheduleEgressIfNeeded()`).
2. **A packet finishes transmitting** on an output port (`PortTxComplete()`).

No periodic timer is started at simulation launch.

### Key Functions

#### `ScheduleEgressIfNeeded(uint32_t port)`

Called from `Enqueue()` after every enqueue operation.

- If the output port is currently **busy** (transmitting), does nothing — `PortTxComplete()` will
  re-trigger when the link is free.
- If a dequeue event is already **pending** for this port, cancels the stale event and
  reschedules it at the tightest eligible time.
- Queries `egress_buffer.get_next_tp_all_ports()` for the earliest future rate-eligible time,
  then calls `Simulator::Schedule(delay, EventDrivenEgressDequeue, port)`.

#### `EventDrivenEgressDequeue(uint32_t port)`

The core dequeue-and-process function.

1. Calls `egress_buffer.pop_back()` to dequeue one rate-eligible packet.
2. If **no packet is eligible yet**, computes the next eligible timestamp and reschedules itself
   there (self-rescheduling with no work done).
3. If a packet is dequeued, runs the full **egress pipeline** on it (egress MAU, deparser,
   cloning, recirculation).
4. After deparsing, computes the **transmission delay**:
   ```
   tx_delay [ns] = packet_bytes × 8 × 1e9 / m_linkRateBps
   ```
5. Marks the port `busy` and calls
   `Simulator::Schedule(tx_delay, PortTxComplete, port)`.

#### `PortTxComplete(uint32_t port)`

Fired after the serialisation delay expires.

- Marks the port **free**.
- If the port's queue is non-empty, calls `ScheduleEgressIfNeeded(port)` to immediately
  schedule the next dequeue.

### Per-Port State (`PortTxState`)

```cpp
struct PortTxState {
    bool    busy{false};          // true while a packet occupies the link
    Time    busyUntil{Time(0)};   // absolute time when the link becomes free
    EventId pendingEvent{};       // handle to the next scheduled dequeue attempt
};

std::unordered_map<uint32_t, PortTxState> m_portTxState;
```

Entries are created on first use in `ScheduleEgressIfNeeded()`.

### Link Rate (`m_linkRateBps`)

Set during `CalculateScheduleTime()` by reading the `DataRate` attribute of the first bridge
port via `GetAttributeFailSafe("DataRate", drv)`.  Falls back to **1 Gbps** if no port is
attached or the attribute is unavailable.

---

## Affected Architectures

The same three-function pattern (`ScheduleEgressIfNeeded` / `EventDrivenEgressDequeue` /
`PortTxComplete`) was applied to all three switch-core implementations:

| File | Architecture |
|------|-------------|
| `model/p4-core-v1model.cc` / `.h` | v1model |
| `model/p4-core-psa.cc` / `.h`     | PSA     |
| `model/p4-nic-pna.cc` / `.h`      | PNA NIC |

The legacy `SetEgressTimerEvent()` function is retained as a no-op stub for reference but is
**no longer scheduled** by `start_and_return_()`.

---

## Additional Changes in the Same Commit

| File | Change |
|------|--------|
| `utils/p4-queue.h` | Fixed vector iterator invalidation bug in `NSQueueingLogicPriRL` during queue size queries. |
| `utils/primitives-pna.h` | New file — registers PNA-specific primitives (`send_to_port`, `drop_packet`) used by the PNA NIC pipeline. |
| `CMakeLists.txt` | Added `utils/primitives-pna.h` to the build. |
| `examples/p4src/simple_pna/simple_pna.json` | Recompiled from `simple_pna_ipv4.p4` to match the updated PNA pipeline. |

---

## Comparison Summary

| Property | Polling (old) | Event-driven (new) |
|----------|--------------|-------------------|
| Simulator events when idle | O(1/tick) per port | Zero |
| Scheduling latency | Up to 1 polling interval | Immediate (bounded by rate limit) |
| Output-port delay model | None | Explicit serialisation delay (`tx_delay = bits / link_rate`) |
| Link rate source | Not modelled | Read from `NetDevice::DataRate` attribute |
| Separation of concerns | Mixed (rate shaping + delay + scheduling in one timer) | Rate shaping (queue RL), pipeline latency, and link delay are separate |
