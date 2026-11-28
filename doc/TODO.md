# p4sim: open items and plans

This file lists what is known to be missing or wrong in p4sim, and what is
planned. Most items were found while reviewing the PRs of November 2026. Each
item says what the problem is, what we propose, and where it stands. A PR that
resolves an item removes it from this file.

Branches: `main` holds P4sim 2.0 and later. `main-deprecated` keeps the 1.x
line (bridge ports only, the old timing model) and gets no more changes.

## Design questions

### Where does a congested switch hold its backlog?
- **Today.** The backlog builds up in the TM queues between the ingress and the
  egress (`egress_buffer`, or the VOQs), where scheduling and AQM belong. After
  the egress, each port has a transfer buffer (`TransferBufferSize` frames): a
  plain FIFO that stands for the hardware port queue. A port takes packets from
  the TM while it is idle or its transfer buffer has room; the buffer never
  drops, and its frames are not overtaken. The default, 0, keeps the earlier
  behaviour: a port takes the next packet only when it is idle. (#22's per-port
  ns-3 `QueueDisc` after the egress was removed before 2.0: as the port took one
  packet at a time, it never held more than one.)
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
  - So this design matches the hardware.
- **Still open.**
  - The default size of the transfer buffer: no public value; a rough
    estimate is one or two full-size frames at 100 Gbps. It is 0 for now.
  - The transfer buffer does not work with `EnableVoqFabric` yet: the VOQ
    traffic manager hands each port one frame at a time itself.
  - The queue depth: the dequeued packet does not count in `deq_qdepth` (as in
    BMv2), and neither do the frames in the transfer buffer.

### Store and forward, or cut-through?
- **Today.** Every hop is store and forward: a device gets a frame only when its
  last bit has arrived, so each hop adds one serialisation time (120 ns for a
  1500-byte frame at 100 Gbps). The exception is a switch with the
  `cut-through-reference` target profile ([latency-model.md](latency-model.md)),
  a zero-buffer cut-through switch.
- **Question.** Tofino can also forward cut-through, starting on a frame before
  it has fully arrived (it is store and forward by default). Cut-through with a
  queue is not modelled: no published data covers it.

## Feature gaps

- **PSA and PNA.**
  - PNA has no Thrift service of its own (BMv2's `pna_nic` has one, for the
    time commands of `pna_nic_CLI`); its `FlowTablePath` runs in `bm_CLI`.
  - PSA and PNA give no digest records: BMv2's `psa_switch` and `pna_nic` do
    not pass digests on either.
  - PNA has no `recirculate()` and no `mirror_packet()`, as `pna_nic` has
    neither; a PNA program that calls one is rejected when it loads.
  - A program swap on PNA does not wait for the frames in its output queues,
    although `EnableSwap` promises that the switch swaps once it holds no
    packet: PNA turns a frame into an ns-3 packet before it queues it, so the
    frame no longer holds a PHV, which is what `HoldsPackets()` counts besides
    the transfer buffers. These frames have passed the whole pipeline, so they
    are not processed again either way.
  - Externs (`utils/psa_externs`): `Counter`, `Meter`, `Hash`,
    `InternetChecksum` and `Random` work in PSA and PNA programs. p4c does not
    compile the rest for BMv2: p4c 1.2.5.17 leaves a PSA `DirectCounter` out of
    the JSON and stops on a `DirectMeter`; p4c 1.2.5.17 and 1.2.5.19 stop with a
    compiler bug on a PNA `Counter` (`PNA_CounterType_t`). Report these to p4c.
    The flow-table file of a PNA switch (`bm_CLI`) does not know the meter
    externs; `P4RuntimeApi` and `P4Controller` do.
- **The pipeline core** (`P4SwitchArch` 3) ignores `mcast_grp`, clones,
  resubmit and recirculation: a v1model program that floods (L2 learning, for
  example) sends nothing. It warns on stderr, once per switch for each of them.
  Proposal: give it the packet replication engine of v1model (the
  `McSimplePreLAG` component, so that the `mc_*` commands of `simple_switch_CLI`
  work) and an egress pass per copy.
- **`PipelineDelay` follow-ups (#59).**
  - No separate egress delay (decided November 2026): one delay before the TM is
    enough. With the same total and a port that takes its packets early enough
    to keep the line busy, a second delay after the TM would send the same frames
    in the same order at the same times (by analysis, not measured). Only the
    timestamps that the P4 program sees and the timing of egress clones would
    differ.
  - A model per stage (Tofino's ingress and egress share a fixed number of
    match-action stages; register accesses may add time). BMv2's JSON has no
    stage allocation, so p4sim cannot see the stages.
  - The default is 0. No published figure covers the whole pipeline; the
    attribute's help text gives a measured one for scale.
- **Direct meters count wall-clock time.** BMv2's match tables execute a
  `direct_meter` in its core with the wall clock, out of reach of P4sim, so its
  colors depend on how fast the simulation runs. `meter.execute_meter()` and
  the `Meter` extern of PSA and PNA count simulation time. A fix needs a way to
  give BMv2's meters another clock.
- **Runtime CLI during the simulation.** The Thrift server of a switch runs in
  its own thread, so a CLI that runs during the simulation changes the switch
  without synchronisation with it. The CLIs are for before and after the
  simulation, `P4Controller` for changes during it. (A CLI that connects after
  its switch was destroyed gets an error: the services of a switch stop before
  it is destroyed.)
- **Target profiles** ([latency-model.md](latency-model.md)).
  - Cut-through works with v1model, switched-Ethernet ports and no buffer only;
    Tofino's cut-through with a queue, PSA and bridge ports have no model.
  - No egress pipeline model, no Model A data for 25G and 40G, means only (the
    DPTP ranges are in the profile but not used for jitter).
  - The fixed time from the ingress pipeline into the queue (between Model A's
    T2 and DPTP's Q) has no value; no control-plane delay for Tofino.
- **Smaller gaps, to do when a test or user needs them:**
  - a configurable drop port (all switches of a simulation would share it);
  - a mirroring session with both a port and a multicast group;
  - the other PRE commands of `simple_switch_CLI` in the STF harness
    (`mc_node_update`, `mc_node_dissociate`, `mc_mgrp_destroy`, ...).

## Bugs and cleanups

- **BMv2.**
  - Upstream fix for BMv2's bundled spdlog (`registry.h`), which GCC rejects from
    C++20 on; until then, P4sim builds with a fixed copy of these headers
    (`CMakeLists.txt`, `patches/bmv2-spdlog-cxx20.patch`).
  - Build BMv2 with optimisation (-O2).
  - Find BMv2 with CMake imported targets instead of the fixed `/usr/local/lib`.
  - `set_pkg_config_env.sh` also writes `boost_system.pc` (Boost 1.83,
    `-lboost_system`), which P4sim does not use; Ubuntu 26.04 has Boost 1.90 and
    no `libboost_system`. Drop it, or derive the Boost version.
  - Upstream fix for `psa_switch_CLI` (1.15.8): `mirroring_delete` calls
    `mirroring_mapping_delete`, which the `psa_switch` service does not have;
    and the CLI does not import `InvalidMirroringOperation`, so any failed
    mirroring command raises a `NameError`. Both end the CLI.
  - Upstream fix for BMv2's install (1.15.8): `include/Makefile.am` does not
    install `bm/bm_sim/event_observer.h`, which the installed `event_logger.h`
    includes; P4sim carries a copy (`utils/bm-event-observer.h`).
  - Upstream fix for BMI (1.15.8): `bmi_port_destroy_mgr()` joins the port
    manager's thread even when the manager was never started, which crashes
    with glibc 2.43 (Ubuntu 26.04). P4sim is not affected: its switches have a
    device manager without ports instead of BMI.
- **Deprecated, to remove in the next major version:** the attributes
  `ChannelType` and `EnableTracing`, and the meter-array overloads of
  `P4Controller::SetMeterRates()`, `GetMeterRates()` and `ResetMeterRates()`
  (replaced by `MeterSetRates()`, `MeterGetRates()` and `MeterResetRates()`).
