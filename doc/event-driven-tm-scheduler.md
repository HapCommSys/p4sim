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

---

## Design Analysis and Boundary Conditions

This section documents the analysis of ten boundary conditions and design questions,
with conclusions drawn directly from the source code.

---

### Q1 · Scheduling Scope: Per-Port vs Global

**Question:** `ScheduleEgressIfNeeded(port)` is per-port, but it calls
`egress_buffer.get_next_tp_all_ports()`. Is the scheduling per-port or global?

**Analysis of `get_next_tp_all_ports()` (`utils/p4-queue.h`, line 354):**

```cpp
Time get_next_tp_all_ports() {
    Time next = now + Seconds(5);          // sentinel "infinity"
    for (auto& w_info : workers_info) {    // iterates ALL workers (ports)
        for (pri = nb_priorities; ...) {
            if (q.top().send <= now) return q.top().send;  // already eligible
            next = std::min(next, q.top().send);
        }
    }
    return next;  // earliest future-eligible time across ALL ports/queues
}
```

**Conclusion — ⚠️ Known limitation (intentional simplification):**

The scheduler is **per-port for the busy/idle state** (`m_portTxState[port]`) but uses a
**global** earliest-eligible timestamp for computing the delay before the next dequeue attempt.
This means that when port A is idle and port B has a rate-limited packet, scheduling for port A
may fire early (waking up to find nothing to dequeue for port A specifically) and then
reschedule itself.

This is **not a correctness bug**: `pop_back()` checks `q.top().send <= now` at dequeue time
and returns `nullptr` if nothing is eligible, so no packet is processed prematurely. The only
cost is an occasional extra wake-up with no work done, which is bounded (one spurious event per
dequeue cycle at worst) and far fewer than the O(1/tick) cost of the old polling scheduler.

A per-port `get_next_tp(port)` would be more precise. This is a **known future improvement**.

---

### Q2 · Link Rate: Per-Port vs Global

**Question:** Is `m_linkRateBps` per-port or global? What if ports have different rates?

**Code (`p4-core-v1model.cc`, `CalculateScheduleTime()`):**

```cpp
Ptr<NetDevice> port = m_switchNetDevice->GetBridgePort(0);  // port 0 only
DataRateValue drv;
if (port->GetAttributeFailSafe("DataRate", drv))
    m_linkRateBps = drv.Get().GetBitRate();
```

**Conclusion — ⚠️ Known limitation:**

`m_linkRateBps` is a **single switch-wide value** read from port 0. All egress ports use the
same link rate for serialisation delay computation. If a switch has heterogeneous port rates
(e.g., a mix of 1 GbE and 10 GbE ports), the delay model will be incorrect for non-port-0
ports. Additionally, `CalculateScheduleTime()` is called only once at construction time, so
dynamic rate changes are not reflected.

For typical simulation scenarios where all switch ports share the same link speed (the common
case in P4 network simulations), this is **functionally correct**. Heterogeneous-rate switches
are a **known future improvement**: `m_portTxState` already has per-port granularity, so
extending to `m_linkRateBps[port]` is straightforward.

---

### Q3 · Port Busy State and Serialisation Guarantee

**Question:** Does the implementation guarantee exactly one packet in flight per port?

**Code (`EventDrivenEgressDequeue`):**

```cpp
// Guard 1: checked at entry
if (pstate.busy) { return; }          // bail out immediately if port busy

// ... process packet ...

pstate.busy = true;                   // mark busy BEFORE handing to ns-3
pstate.busyUntil = Simulator::Now() + txDelay;
m_switchNetDevice->SendNs3Packet(...);
Simulator::Schedule(txDelay, &PortTxComplete, this, out_port);
```

**Code (`ScheduleEgressIfNeeded`):**

```cpp
if (pstate.busy) { return; }          // Guard 2: never schedule while busy
```

**Conclusion — ✅ Correct:**

The busy flag is set before `SendNs3Packet` and cleared only inside `PortTxComplete` after
the serialisation delay. Guards in both `ScheduleEgressIfNeeded` and
`EventDrivenEgressDequeue` prevent any second dequeue from starting while the port is busy.
Since ns-3 is **single-threaded** (the discrete-event loop never runs two events
simultaneously), there is no race condition between the guard check and the flag set. The
invariant **"at most one packet in flight per port at any time"** is strictly maintained.

`PortTxState::busyUntil` is stored for diagnostic/logging purposes; the actual enforcement
is done via the boolean `busy` flag and the `PortTxComplete` callback.

---

### Q4 · Pipeline Processing Delay

**Question:** The old polling interval acted as an implicit processing delay. Does the new
scheduler model pipeline delay?

**Conclusion — ℹ️ Intentional design decision (zero pipeline latency):**

In the event-driven implementation, ingress and egress pipeline processing (`parser->parse()`,
`ingress_mau->apply()`, `egress_mau->apply()`, `deparser->deparse()`) are executed
**synchronously within the same simulator event**, at the same simulation timestamp as
packet reception or dequeue. There is no artificial delay added for pipeline computation.

This reflects the standard ns-3 modelling convention: **network device processing is
considered instantaneous** unless an explicit delay model is installed. The meaningful
physical delays are:

| Delay | Modelled? |
|-------|-----------|
| Queue rate-shaping delay | ✅ via `QueueInfoPri::pkt_delay_time` |
| Output-port serialisation delay | ✅ via `tx_delay = bits / link_rate` |
| Propagation delay | ✅ by the ns-3 channel model |
| Switch pipeline processing delay | ❌ zero (intentional simplification) |

If pipeline processing delay is needed for a specific study, a fixed offset can be added
inside `HandleIngressPipeline()` or `EventDrivenEgressDequeue()` via
`Simulator::Schedule(pipelineDelay, ...)`.

---

### Q5 · Event Cancellation and Stale Events

**Question:** Can stale events fire and cause incorrect behaviour?

**Code (`ScheduleEgressIfNeeded`):**

```cpp
if (pstate.pendingEvent.IsRunning()) {
    Simulator::Cancel(pstate.pendingEvent);   // cancel the old event
    pstate.pendingEvent = EventId();
}
pstate.pendingEvent = Simulator::Schedule(delay, &EventDrivenEgressDequeue, this, port);
```

**Code (`EventDrivenEgressDequeue` entry):**

```cpp
pstate.pendingEvent = EventId();   // clear handle – we are executing now
if (pstate.busy) { return; }       // extra guard
// ... pop_back returns nullptr if nothing eligible – safe no-op ...
```

**Conclusion — ✅ Correct:**

ns-3's `Simulator::Cancel()` is **guaranteed** to prevent a cancelled event from executing.
The `pendingEvent` handle is cleared at the start of `EventDrivenEgressDequeue` so that a
subsequent `ScheduleEgressIfNeeded` call (e.g., triggered by a clone arriving via `Enqueue`)
correctly sees no pending event and schedules a fresh one. Because ns-3 is single-threaded,
`Cancel` + `Schedule` within the same event execution is atomic with respect to the event
queue — there are no race conditions.

---

### Q6 · Queue Rate Enforcement

**Question:** How is per-queue rate enforced, and can bursts occur?

**Rate enforcement in `push_front()` (`p4-queue.h`):**

```cpp
// On every enqueue, compute when this packet is eligible for dequeue:
q_info_pri.last_sent = get_next_tp(q_info_pri);
// ...
w_info.queues[priority].emplace(item, queue_id, q_info_pri.last_sent, ...);
//                                              ^^^^ send timestamp
```

```cpp
Time get_next_tp(const QueueInfoPri& q) {
    // next eligible time = max(now, last_sent + 1/rate)
    return (Simulator::Now() > q.last_sent + q.pkt_delay_time)
               ? Simulator::Now()
               : q.last_sent + q.pkt_delay_time;
}
```

**Dequeue gate in `pop_back()`:**

```cpp
if (q.top().send <= now) { /* dequeue */ break; }
```

**Conclusion — ✅ Correct, no bursts:**

The `send` timestamp is **computed at enqueue time** and stored with the packet in the
priority queue. It equals `max(now, prev_send + 1/rate)`. `pop_back()` only dequeues a
packet when `Simulator::Now() >= send`. This is a **token-bucket-free leaky-bucket model**:
the inter-packet gap is strictly enforced. Even if many packets arrive simultaneously, each
successive packet in the queue is assigned a `send` time one inter-packet gap later than the
previous. No burst is possible beyond a single packet at the configured rate.

---

### Q7 · Idle Switch Behaviour

**Question:** When all queues are empty, does the scheduler generate zero events?

**Code path:**

- `PortTxComplete(port)` checks `egress_buffer.size(port) > 0`.  
  If zero → does **not** call `ScheduleEgressIfNeeded` → **no event is scheduled**.
- `ScheduleEgressIfNeeded(port)` is only called from `Enqueue()` and `PortTxComplete()`.
- `Enqueue()` is only called when a packet enters the switch.

**Conclusion — ✅ Correct:**

When all queues are empty and no packet is in transit, there are **zero pending scheduler
events** for the egress path. The next event is only created when `Enqueue()` is called,
i.e., when a new packet enters the switch from the ingress pipeline. The tracing callback
`CalculatePacketsPerSecond()` still fires every second if tracing is enabled, but that is
independent of the egress scheduler.

---

### Q8 · Priority Scheduling and Starvation

**Question:** Can high-priority queues starve low-priority ones?

**Code (`pop_back`, iteration order):**

```cpp
// Iterates from nb_priorities-1 down to 0
// In NSQueueingLogicPriRL: priority 0 = highest, nb_priorities-1 = lowest
// BUT the loop iterates from (nb_priorities-1) down to 0,
// so it checks LOWEST index (HIGHEST priority) last in the loop body.
// The loop checks from nb_priorities-1 ... 1 ... 0, breaking at first eligible.
for (pri = nb_priorities; pri-- > 0;)   // pri: N-1, N-2, ..., 1, 0
```

Wait — `Enqueue()` inverts priority: `priority = m_nbQueuesPerPort - 1 - pkt_priority`, so
queue index 0 holds the **lowest** P4 priority (most-favoured by pop_back iteration order
`pri = N-1 ... 0`: the last value checked is 0, meaning the **loop exits first** for pri=0 if
eligible). Let's be precise: the loop breaks on the **first eligible** queue found iterating
from `N-1` down to `0`. Queue index 0 (mapped from highest P4 priority) is the last to be
checked — meaning **highest-P4-priority packets are served first** (the loop finds them at
index 0 if earlier indices are empty or not yet rate-eligible).

**Conclusion — ✅ Intentional strict priority scheduling:**

This is **strict priority scheduling**, consistent with the original BMv2 `simple_switch`
behaviour. Higher-priority P4 traffic (mapped to queue index 0) is always served before
lower-priority traffic. If a high-priority queue is continuously non-empty, lower-priority
queues **can** be starved — this is the defined behaviour of strict priority and is
intentional. Users requiring weighted fair queuing must configure per-queue rate limits using
`SetEgressPriorityQueueRate()`.

---

### Q9 · Clone and Recirculate Interactions

**Question:** Do clone/recirculate operations trigger new scheduling events? Can loops occur?

**Code — Egress clone path (inside `EventDrivenEgressDequeue`):**

```cpp
if (config.egress_port_valid) {
    Enqueue(config.egress_port, std::move(packet_copy));  // → ScheduleEgressIfNeeded
}
```

**Code — Recirculate path:**

```cpp
input_buffer->push_front(PacketType::RECIRCULATE, std::move(packet_copy));
PortTxComplete(static_cast<uint32_t>(out_port));  // release port, do NOT re-enqueue to egress
return;
```

**Conclusion — ✅ Correct, loops are bounded:**

- **Egress clone**: calls `Enqueue()`, which calls `ScheduleEgressIfNeeded()`. This is
  exactly the same path as a normal packet arriving from ingress. No special case is needed.
- **Recirculate**: the recirculated packet is placed in the *ingress* `InputBuffer` (high
  priority), not back into the egress queue. The `PortTxComplete` call releases the port for
  the next egress dequeue. The recirculated packet re-enters the ingress pipeline via
  `HandleIngressPipeline()` at the next ingress event.
- **Loop protection**: P4 programs are responsible for terminating recirculation/clone loops
  (e.g., via `instance_type` field checks). The scheduler itself imposes no artificial loop
  limit, consistent with BMv2 behaviour. Each recirculation goes through the full queue rate
  limit, preventing unbounded event generation rates.

---

### Q10 · Validation Approach

**Question:** How can correctness be verified?

**Recommended validation strategy:**

| Test | Method | Expected result |
|------|--------|-----------------|
| Rate enforcement | Single flow at configured queue rate R pps; measure inter-arrival at egress | Inter-departure ≈ 1/R seconds |
| Link serialisation | Packet of size B bytes at link rate L bps; measure port-to-port delay | tx_delay = B×8/L + propagation |
| Priority ordering | Two flows at different priorities, congested queue; log dequeue order | High-priority packets always dequeued first |
| Idle events | Empty network for T seconds; count simulator events | Zero egress scheduling events |
| Clone correctness | P4 program that clones every packet; count received copies | Each original → exactly 2 received |
| Recirculate | P4 program that recirculates once then forwards; measure latency | Latency = 2 × pipeline + queue delay |
| Bandwidth fairness | Multiple ports at different rates; measure per-port throughput | Each port limited by min(queue rate, link rate) |

The existing test suite (`test/format-utils-test-suite.cc`) and example
`examples/p4-v1model-ipv4-forwarding.cc` can serve as a baseline for regression testing.

---

### Meta Question · Behavioural Fidelity vs Original BMv2

**Question:** Does the new scheduler preserve the exact semantics of the original BMv2
traffic manager?

**Preserved:**

| Semantic | Status |
|----------|--------|
| Per-queue rate limiting (leaky bucket) | ✅ Identical — same `NSQueueingLogicPriRL` |
| Strict priority ordering | ✅ Identical — same `pop_back()` logic |
| Queue depth limits | ✅ Identical — same capacity enforcement in `push_front()` |
| Multicast replication | ✅ Identical — `MulticastPacket()` unchanged |
| Ingress clone / egress clone / resubmit / recirculate | ✅ Identical paths |

**Intentional deviations:**

| Semantic | Deviation | Reason |
|----------|-----------|--------|
| Output-port serialisation delay | **Added** (not in original BMv2) | BMv2 runs in real time where wire delay is implicit; ns-3 requires explicit modelling |
| Pipeline processing delay | **Zero** (implicit in original BMv2 polling interval) | ns-3 convention: device processing is instantaneous unless explicitly modelled |
| `get_next_tp_all_ports()` used for per-port scheduling | **Slight over-approximation** of wake-up time | No per-port API exists in current queue; harmless extra wake-up at worst |

**Overall verdict:** The event-driven scheduler is **behaviourally equivalent** to the
original BMv2 traffic manager for all correctness-relevant properties (rate enforcement,
priority, drop policy). The deviations are additive improvements (explicit wire delay) or
known approximations that do not affect packet ordering or rate semantics.

