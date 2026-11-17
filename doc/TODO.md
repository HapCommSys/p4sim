# p4sim: open items and plans

This file lists what is known to be missing or wrong in p4sim, and what is
planned. Most items were found while reviewing the PRs of November 2026. Each
item says what the problem is, what we propose, and where it stands. A PR that
resolves an item removes it from this file.

Branches: `main` is the released line. `switch_channel` is the development line
with the event-driven egress, the traffic manager (TM) and the switched-Ethernet
channel. It has all of main's PRs up to #55 (merged in "phase B", last in #60).

## Design questions

### Where does a congested switch hold its backlog?
- **Today (`switch_channel`).** Packets wait in the TM queues between the
  ingress and the egress (`egress_buffer`, or the VOQs). A port takes the next
  packet from the TM only when it is idle. After the egress, #22 added a per-port
  ns-3 `QueueDisc` (`P4CoreV1model::SetPortQueueDisc()`). Because the port takes
  one packet at a time, that queue disc probably never holds more than one
  packet, so its scheduling and AQM have no effect. This is from reading the
  code and still needs a test.
- **Preferred design.** The backlog builds up in the TM queue between the
  ingress and the egress, where scheduling and AQM belong. After the egress
  comes only a transfer buffer: a plain FIFO that stands for the hardware port
  queue. The #22 queue disc would become that FIFO, with a configurable depth.
- **Literature check (November 2026), Tofino and Tofino 2.** We have not
  measured this on hardware; these are published sources.
  - The backlog of an oversubscribed port sits in the TM's shared buffer
    between the ingress and the egress pipelines; all admission control and
    drop thresholds are in the TM (Tofino Native Architecture application note
    §2, §5.7; Bosshart et al., SIGCOMM 2013, §4; Arista 7170 white paper).
  - The TM scheduler dequeues per port at the port's speed, and the path after
    it (egress parser buffer, egress pipeline, deparser, egress buffer, MAC) is
    flow-controlled by credits: only a few packets are in flight after the
    dequeue, and the egress parser never drops. The sizes of these buffers are
    not public.
  - `enq_qdepth` and `deq_qdepth` are TM queue depths (in 80-byte cells on
    Tofino, 176-byte cells on Tofino 2); packets already dequeued are not
    counted. Whether the dequeued packet itself counts is not documented
    (BurstRadar, APSys 2018, assumes it does; Intel's open-source tofino-model
    and BMv2 do not).
  - So the preferred design matches the hardware.
- **Still to decide.**
  - The size of the FIFO: no public value; a rough estimate is one or two
    full-size frames at 100 Gbps.
  - The queue depth: on `switch_channel`, a TM queue of depth 1 holds one packet
    besides the one that the port is sending, and the dequeued packet does not
    count in `deq_qdepth` (as in BMv2).

### Store and forward, or cut-through?
- **Today.** Every hop is store and forward: a device gets a frame only when its
  last bit has arrived, so each hop adds one serialisation time (120 ns for a
  1500-byte frame at 100 Gbps).
- **Question.** Tofino can also forward cut-through, starting on a frame before
  it has fully arrived (it is store and forward by default). Whether to model
  that is open; it changes the latency, not the throughput.

### The timing model of `main`
- **Problem.** `main` still has the old timing model: a switch-wide egress timer
  driven by `SwitchRate`; a queue without a rate spaces its packets 1 ms apart
  (`rate_to_time(0)`); and the first packet of a queue waits one interval.
  `switch_channel` fixed this in #40.
- **Plan.** No change on `main` for now. It is replaced when `switch_channel` is
  merged into `main`.

## Feature gaps

- **PSA and PNA.**
  - PNA computes its transmit time itself (rounded down to whole
    nanoseconds) instead of using the device's transmit-complete signal, as
    v1model and PSA do.
  - PNA loses frames on a congested port: host 0 sends 20 frames, one per
    microsecond, to a 1 Gbps port (8.1 us per frame); only 3 arrive, the
    second 888 ns late. Found while testing #59; it happens without #59 too.
  - Three zero-delay `Simulator::ScheduleNow(PortTxComplete)` events are not
    cancelled when a switch is destroyed (v1model twice, PSA once). They only
    matter for a switch destroyed in the same instant.
  - PNA and the pipeline core ignore `PipelineDelay`.
  - PSA clones and mirroring sessions have no test.
  - There is no `psa_switch` (or PNA) Thrift service, so the target-specific
    commands of `psa_switch_CLI` do not work.
  - `P4Controller` works on v1model switches only.
- **Link framing on other devices.** Only the switched-Ethernet channel uses
  `LinkFraming` (its `Framing` attribute). The P4 point-to-point device, and the
  TM's estimate of when a frame on a bridge port is sent, use the frame's bytes
  only. ns-3's own CSMA device adds its FCS and a 96-bit gap itself.
- **The default `DataRate`** of the switched-Ethernet channel is 0xffffffff
  bit/s (about 4.29 Gbps), as in ns-3's CSMA channel; the examples set it.
- **`PipelineDelay` follow-ups (#59).**
  - Test it with recirculation and egress clones; the programs for these
    came with #60.
  - Separate ingress and egress delays: needs the FIFO after the egress (see
    above).
  - A model per stage (Tofino's ingress and egress share a fixed number of
    match-action stages; register accesses may add time). BMv2's JSON has no
    stage allocation, so p4sim cannot see the stages.
  - The default is 0. No published figure covers the whole pipeline; the
    attribute's help text gives a measured one for scale.
- **Digests.** `digest()` sends its records to BMv2's notification socket, and
  nothing in the simulation receives them. Proposal: pass learned records to an
  ns-3 trace source that `P4Controller` can subscribe to, so that control-plane
  experiments such as L2 learning can run inside the simulation.
- **The pipeline core and the drop port.** The pipeline core runs the egress for
  a packet that the ingress dropped (`mark_to_drop()`), and it ignores a
  `mark_to_drop()` in the egress, because it sends the `egress_spec` of the
  ingress. Both branches.
- **Thrift handlers.** The Thrift server thread runs until the process ends
  (BMv2 cannot stop it): a CLI that connects after its switch was destroyed uses
  a freed core. A CLI that runs during the simulation works from another thread,
  without synchronisation. Proposal: a locked registry of live cores that the
  handlers check; document that the CLI is for before and after the simulation,
  and `P4Controller` for changes during it.
- **The P4 point-to-point device** (`switch_channel`) gives the switch its own
  port's MAC address as a frame's destination, not the frame's. Programs that
  forward by IP address are not affected; programs that forward by destination
  MAC are.
- **Smaller gaps, to do when a test or user needs them:**
  - byte queue limits on host devices (`TrafficControlHelper::SetQueueLimits()`)
    should work since #42, but are not tested;
  - a configurable drop port (all switches of a simulation would share it);
  - a mirroring session with both a port and a multicast group;
  - the other PRE commands of `simple_switch_CLI` in the STF harness
    (`mc_node_update`, `mc_node_dissociate`, `mc_mgrp_destroy`, ...).

## Bugs and cleanups

- **`main`: `P4CoreV1model::CalculatePacketsPerSecond()`** doubles the counter
  (`m_egressBp += m_egressBp`) and writes to a `static std::ofstream`, which all
  switches of a process share.
- **The `p4-firewall` example** loads `p4_basic/p4_basic.json` and its flow
  tables, not the program in `examples/p4src/firewall/`. Both branches.
- **`main`: resubmit and recirculate** call `HandleIngressPipeline()`
  recursively, one level per pass. `switch_channel` schedules the next pass
  instead; this goes away when `switch_channel` is merged into `main`.
- **The branches `ns-3.39` and `ns-3.49`** lack main's PRs after #35 (#37, #39,
  #43, #50 to #55).
- **BMv2.**
  - Upstream fix for BMv2's bundled spdlog (`registry.h`), which GCC rejects from
    C++20 on; the `ns-3.49` README patches the installed header instead.
  - Build BMv2 with optimisation (-O2).
  - Find BMv2 with CMake imported targets instead of the fixed `/usr/local/lib`.
- **The last lost packet of the examples** (PDR 99.911 %) is ns-3's ARP: its
  pending queue holds 3 packets. Not p4sim; the examples could enlarge
  `ArpCache::PendingQueueSize`.
