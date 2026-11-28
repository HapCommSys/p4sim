# Target profiles and latency models

P4 has no timing semantics: how long a packet takes through a switch is a
property of the hardware target, not of the program. A **target profile** holds
that property, apart from the P4 program: its latency model, forwarding mode,
buffering and lookup limits, and the limits of its learning tables. Changing
the hardware means changing the profile, not the program. No number of a model
is written in P4sim's code; each comes from the profile, a JSON file.

P4sim ships two profiles in [`profiles/`](../profiles):

| Profile | Models | Forwarding | Buffer |
|---|---|---|---|
| `tofino-like` | A (ingress pipeline, Franco et al. 2024 [1]) and B (MAC receive and egress, DPTP 2019 [2]) | store-and-forward | P4sim's queues |
| `cut-through-reference` | C (a 100 Mbps switch ASIC, from its RTL [3]) | cut-through | none |

The numbers in brackets refer to the [references](#references) at the end.

Without a profile (the default), a switch behaves as before: `PipelineDelay`
gives every packet the same latency.

## Use

```cpp
sw->SetAttribute("TargetProfile", StringValue("tofino-like")); // or a path to a JSON file
```

| Device attribute or trace | Meaning |
|---|---|
| `TargetProfile` | the profile's name in `profiles/`, or a JSON file |
| `LearningTable`, `LearningAction` | an exact-match table that the switch fills from the program's digests, with the profile's table limits (below) |
| `ControlPlaneDelay` | digest to installed entry, on the control-plane learning path; negative (default): the profile's value |
| trace `FrameArrival` | each frame with its ingress port, first-bit and last-bit time |
| `GetCore()->GetEgressBusyDrops()`, `GetLookupDrops()` | frames dropped at a busy port without a queue, or by the lookup arbiter |

The switch prints a warning, once per switch, whenever a model is used outside
what it was fitted on.

## When a packet reaches the traffic manager

Every frame arrives whole, with its last bit; the switch also knows when its
first bit arrived (its time on the wire earlier, preamble included on a link with
`Framing` set to `Ethernet`). With a profile, each packet that passes the ingress
reaches the egress queues at its own time:

- **store-and-forward**: last bit + the profile's latency;
- **cut-through**: first bit + the profile's latency (below).

With `SwitchRate`, a packet can wait in the input buffer until the pipeline
takes it. It then gets the pipeline's part of the latency after the wait, as
`PipelineDelay` is added after it: for tofino-like, the time it reaches the
queues is max(last bit + MAC receive, the time the pipeline takes it) + Model A
+ egress; for a fixed store-and-forward latency, the time the pipeline takes it
+ the latency. A cut-through switch has no input buffer and needs `SwitchRate`
0.

Packets keep their order: none leaves the pipeline before a packet that entered
it earlier (in hardware the pipeline is in order; with a per-packet latency a
short packet right behind a long one would otherwise overtake it). Copies of a
packet (multicast, clones) leave with it. A packet that passes the ingress again
(resubmit, recirculation) counts from that pass; an egress clone, which does not
pass the ingress, gets `PipelineDelay`.

## `tofino-like`: Models A and B

The latency from the last bit to the traffic manager is

    MAC receive (Model B) + ingress pipeline (Model A) + egress (Model B)

### Model A: the ingress pipeline

Franco et al. [1], Table 2: the mean latency from the start of the ingress
parser to the traffic manager (T1 to T2: ingress parser, control and deparser)
on an APS BF2556X-1T (Tofino, TNA):

    L = a * p + b  +  sum over the parse states after Ethernet of (c * h_n + d)
                   +  sum over the tables matched of e(match type, key)

| | a (per byte) | b | c (per header byte) | d (per state) | exact 8-bit | exact 16/32-bit | LPM 8-bit | LPM 16/32-bit |
|---|---|---|---|---|---|---|---|---|
| 10G | 0.237 | 152.42 | 0.221 | 2.886 | 0.492 | 0.601 | 0.692 | 0.887 |
| 100G | 0.056 | 143.441 | 0.105 | 1.431 | 0.607 | 0.685 | 0.749 | 0.896 |

All in ns; checked digit for digit against Table 2 of [1] and its appendix.
How P4sim gets the inputs, and where the paper leaves a choice:

- **p** is the frame as P4sim carries it: Ethernet header and payload, without
  the FCS. The paper does not say whether p includes the FCS (4 bytes, about
  1 ns at 10G).
- **Parse states** come from BMv2's pipeline events (`EventObserverRegistry`):
  the headers that the ingress parser extracted, grouped into the states of the
  program (consecutive headers of one state are one visit). The first state is
  in the baseline b ("the influence of extracting the Ethernet header is
  considered to be our baseline"). d counts once per state: the paper prints it
  without brackets, but its Table 9 and Fig. 6(b) define it per state, and only
  that reading reproduces its Table 6.
- **Tables**: the tables that matched an entry. The paper fitted the control
  term on matched tables only; a table applied without a match adds nothing,
  with a warning. Tables without a key (p4c's `tbl_*`, which run the actions of
  a control) are no lookups. A table with several keys uses the 8-bit
  coefficient; a single key of 16 bits or more the 16/32-bit one. A match type
  other than exact and LPM uses the LPM coefficient, with a warning (inference:
  Tofino matches both in TCAM).
- **A mix of table kinds** is summed, as the paper's generalized formula does,
  although each coefficient was fitted on one kind of table (warning).
- **Port speed**: the coefficients of 10G and 100G. Another speed uses the
  nearest set, without interpolation, with a warning.
- **Range**: 100 to 1400 bytes, up to 10 states of 2 to 20 header bytes, up to
  10 tables with keys of 8, 16 or 32 bits and up to 3 keys. At 10G the data turn
  non-linear above 800 bytes, 5 states or 5 bytes per state (the paper also
  names 1000 bytes); P4sim carries only the linear model. Outside these, the
  switch warns.
- The model gives the mean; there is no jitter. It was trained with one action
  (set the egress port).

### Model B: MAC receive and egress

Kannan, Joshi and Chan [2] (DPTP), Table 1 (10G, idle links; checked against
the paper):

| Segment | From, to | min-max (mean), ns | Used |
|---|---|---|---|
| MacD | the whole packet at the Rx MAC, to the ingress pipeline | 0-55 (27) | MAC receive, 27 ns |
| ReqQ | ingress pipeline and queueing | 306-313 (307) | no: it contains the ingress pipeline (Model A) |
| ReqTx | egress pipeline, deparser, Tx MAC, to the start of serialization | 304-356 (340.8) | egress, 340.8 ns |
| ReqWD | the wire, 1 m DAC: from the start of serialization to the whole packet at the receiver, so (inference) with the probe's serialization | 67-79 (72.6) | no: P4sim's link gives serialization and `Delay` |

DPTP's Tx timestamp is the instant serialization starts ([2], section 3.1,
*Measuring ReqTx and RespTx*), so Tx does not contain the serialization of the
probe itself (60 bytes); P4sim adds the serialization on the link. The same
section also lists serialization among the parts of RespTx; P4sim reads that as
the wait for serialization under load (inference). The oversubscribed values
(RespQ about 1.554 ms) are a full queue, which P4sim's own queues produce.

The egress delay is fixed, so P4sim adds it before the traffic manager, not
after: a port that takes its next packet only when it is idle would otherwise
idle for the egress delay between back-to-back frames, while hardware takes the
next packet early enough to keep the line busy. With the delay before the
traffic manager, the frames start on the wire at the same times; only the
timestamps that the P4 program reads differ.

## `cut-through-reference`: Model C

A zero-buffer cut-through Ethernet switch ASIC at 100 Mbps [3], as its RTL
behaves in simulation (Icarus Verilog), not measured silicon:

- **Clock**: one 50 MHz clock for all ports (20 ns, 2 bits per cycle). Arrivals
  and decisions count at its edges.
- **Latency**: 63 cycles (1260 ns) from the first preamble bit in to the first
  preamble bit out, whatever the frame length.
- **Decision**: once the 8 bytes of preamble and delimiter and the 6-byte
  destination address have arrived (14 bytes). The channel gives the switch the
  frame at that time (`P4SwitchNetDevice::ReceiveHeaders()`), so the frame can
  leave before its last bit has arrived.
- **No buffer**: a frame goes out on a port only if it would start there at
  least 51 cycles (1020 ns) after the port's previous frame ended; otherwise it
  is dropped on that port. A flooded frame goes out on the free ports and is
  dropped on the busy ones.
- **Lookups**: one per cycle. Frames that are decided in the same cycle are
  served lowest port first; the others are dropped on all ports (`MacRxDrop`).
- **Address table**: 4 entries, learned from every frame's source address with
  that frame (data plane), the entry refreshed least recently replaced when the
  table is full, an entry aged out 300 s after its last frame. The 4-bit steps of
  the RTL's age counter are not modelled.

The forwarding decision is the P4 program's. `test/p4src/cut_through` has one:
a known destination goes to its port (or nowhere, if that is the ingress port),
an unknown one or a group address is flooded through multicast group
`ingress port + 1`, and every frame's source and port become a digest, which
`LearningTable` installs. A cut-through switch needs v1model, switched-Ethernet
ports, links with `Framing` set to `Ethernet` and a fixed latency.

## Learning tables

`LearningTable` and `LearningAction` name an exact-match table and its action.
Each digest of the program gives one entry: its first field is the key, its
other fields the action's parameters. The profile sets:

| Field | Meaning |
|---|---|
| `table_capacity` | entries; null: the P4 table's size (the table is also full when the P4 table is) |
| `eviction` | `replace_oldest`: a full table replaces the entry refreshed least recently; null: new keys are not learned |
| `entry_lifetime_s` | an entry not refreshed for this long is removed; null: never |
| `learning_path` | `data_plane`: installed with the frame; `control_plane`: `ControlPlaneDelay` later |

A program swap empties the tables: the learning table forgets its entries and
learns them again from the next frames.

The tofino-like profile learns through the control plane and gives no delay:
no value for Tofino was found (the handoff spec cites Harkous et al. for
milliseconds on other P4 targets; not read for P4sim), so `ControlPlaneDelay`
must be set.

## Profile fields

| Field | tofino-like | cut-through-reference |
|---|---|---|
| `forwarding_mode` | `store_and_forward` | `cut_through` |
| `line_rate_bps` | null (any; Model A has 10G and 100G) | 100e6 (warns on other port speeds) |
| `clock_period_ns` | null | 20 |
| `ingress_latency_model` | `franco_linear` | `fixed` |
| `franco_linear` | coefficients per port speed, rules, validity | |
| `fixed_latency_ns` | | 1260 |
| `decision_header_bytes` | | 14 |
| `mac_rx_delay_ns`, `egress_delay_ns` | 27, 340.8 (DPTP, with min, max, port speed, source) | in the fixed latency |
| `queue_capacity` | null (P4sim's queues, `QueueBufferSize`) | 0 |
| `preamble_bytes`, `ipg_bytes` | 8, 12 | 8, 12 |
| `egress_guard_ns` | null | 1020 |
| `lookups_per_cycle` | null (unlimited) | 1 |
| `table_capacity`, `eviction`, `entry_lifetime_s` | null | 4, `replace_oldest`, 300 |
| `learning_path`, `control_plane_update_delay_ns` | `control_plane`, null | `data_plane` |
| `fcs_check` | true (assumed, not verified) | false |

A profile can be any JSON file with these fields. `queue_capacity` above 0
sets the size of each output queue, as `QueueBufferSize` does; 0 means no
queue: a frame for a busy port is dropped there (the guard above). The wire
bytes come from each link's `Framing`; `preamble_bytes` only lets the switch
warn about a link without framing. `fcs_check` describes the target: P4sim's
frames carry no FCS, so it checks none.

## Validation

The suite `p4-latency`:

- A1-A8: Model A's three terms within 0.01 ns of the vectors of the handoff spec.
- C1-C9: the RTL scenarios, cycle for cycle (3 ports; C1 and C6 also with 4).
- Model A end to end on a v1model switch at 10 Gbps, also with `SwitchRate`,
  the features of a packet from BMv2's events, the order of the packets, the
  first and last bit of a frame, `queue_capacity`, and the learning tables
  (capacity from the profile or the P4 table, eviction, aging, both paths, a
  program swap).

## Known gaps

No source gives a complete, public latency model of a P4 hardware switch; the
tofino-like profile is assembled from partial measurements.

- **Models A and B do not add up.** They come from different switches, port
  speeds and probe packets. DPTP's Q [2] (about 307 ns) contains the ingress
  pipeline; Model A alone gives about 176 ns for a 100-byte packet at 10G. The
  fixed time from the ingress pipeline into the queue has no value here.
- **The packet-size term has no stated cause.** Its slope is about 30% of the
  serialization time per byte at 10G and 70% at 100G; pure store-and-forward
  inside T1 to T2 would give 100%, pure cut-through 0% (inference). It was
  measured near line rate (9.5 and 95 Gb/s).
- **The forwarding mode of the measured switches is not stated**, and DPTP did
  not test cut-through. tofino-like is store-and-forward.
- **No egress pipeline model, no data for 25G or 40G in Model A, means only.**
  DPTP's ranges are in the profile for jitter, but not used.
- **Control-plane delay has no number** for Tofino.
- **Model C is RTL behaviour**; according to the handoff spec, the author's
  write-up of November 2026 says the silicon had not been tested yet. No FCS
  check: corrupted frames are forwarded.
- **Cut-through** works with v1model, switched-Ethernet ports and no buffer
  only; cut-through with a queue has no data.
- **BMv2 events**: Model A needs BMv2 built with its event logger (the
  default). BMv2 1.15.8 does not install `bm/bm_sim/event_observer.h`; P4sim
  carries a copy (`utils/bm-event-observer.h`).

## References

1. D. Franco, E. Ollora Zaballa, M. Zang, A. Atutxa, J. Sasiain, A. Pruski,
   E. Rojas, M. Higuero, E. Jacob, "A comprehensive latency profiling study of
   the Tofino P4 programmable ASIC-based hardware," *Computer Communications*,
   vol. 218, pp. 14-30, 2024.
   [doi:10.1016/j.comcom.2024.01.010](https://doi.org/10.1016/j.comcom.2024.01.010)
   (open access). Model A.
2. P. G. Kannan, R. Joshi, M. C. Chan, "Precise Time-synchronization in the
   Data-Plane using Programmable Switching ASICs," in *Proc. ACM Symposium on
   SDN Research (SOSR '19)*, San Jose, CA, USA, 2019.
   [doi:10.1145/3314148.3314353](https://doi.org/10.1145/3314148.3314353)
   ([authors' PDF](https://www.comp.nus.edu.sg/~chanmc/papers-by-year/2019-DPTP_SOSR.pdf)).
   Model B.
3. Essenceia, *ethernet_switch_asic*: RTL of a 100 Mbps cut-through Ethernet
   switch ASIC, commit a14e3e1.
   <https://github.com/Essenceia/ethernet_switch_asic/tree/a14e3e1>. Model C.
