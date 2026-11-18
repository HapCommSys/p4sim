# P4sim tests

## Run

From the ns-3 root, with `./ns3 configure --enable-tests --enable-examples`:

```bash
./test.py -s p4sim                               # one suite
./ns3 run "test-runner --suite=p4sim --verbose"  # one suite, with each test case
./ns3 run "p4-basic-example --ns3::P4SwitchNetDevice::BmLogLevel=off"  # one example
```

No environment variable is needed, and suites can run in parallel. `./test.py -e`
runs an example without the arguments in `examples-to-run.py`, so it writes the
full BMv2 log to `/tmp`.

## Suites

| Suite | Checks | Needs BMv2 |
|---|---|---|
| `format-utils` | string and number conversion helpers | no |
| `p4-topology-reader` | reading a topology file | no |
| `p4-p2p-channel` | the P4 point-to-point channel; short frames on a 100 Gbps link keep the exact line rate | no |
| `p4-queue` | egress queue: capacity, rate, FIFO, per-port rate, priorities | no |
| `p4sim` | v1model, PSA and PNA load their program; Thrift ports; `BmLogLevel` | yes |
| `p4-controller` | flow entries, action profiles and mirroring sessions, read back from the switch; the commands of `simple_switch_CLI` and `psa_switch_CLI` for mirroring, queues and time | yes, `simple_switch_CLI` and `psa_switch_CLI` |
| `p4-packet` | frames sent into a switch and the frames that leave it, on v1model, PNA, PSA and the pipeline core | yes |
| `p4-egress` | switched-Ethernet ports: a congested port sends back to back at its line rate; a switch with a full egress queue, or one whose port just refused a frame, can be destroyed | yes |
| `p4-switch-rate` | `SwitchRate` limits the whole pipeline, 0 means no limit, a full input buffer drops | yes |
| `p4-pipeline-delay` | `PipelineDelay` delays every packet by the same time without lowering the throughput (default egress path, VOQ, PSA, pipeline core, with `SwitchRate`, on a congested port), once per pass for recirculated frames and clones; a switch with packets in its pipeline can be destroyed | yes |
| `p4-bridge-port` | CSMA and point-to-point bridge ports next to a switched-Ethernet port | yes |
| `p4-pna` | a PNA switch forwards, and drops what its program does not send; a full output queue drops | yes |
| `p4-traffic-manager` | the VOQ + fabric Traffic Manager | no |
| `channel-state-test-suite` | the states of the switched-Ethernet channel | no |
| `switched-ethernet-host` | the transmit queue of a host device; short frames keep the exact line rate on 100 and 400 Gbps links and at the default rate, 10 Gbps | no |
| `link-framing` | Ethernet framing (preamble, FCS, padding, interframe gap) on the switched-Ethernet channel and the P4 point-to-point device; between two hosts, through a switch, and in a switch's estimate for a point-to-point bridge port | yes |
| `p4-switch-queue-item-test-suite` | the items in the queue discs of the switch ports | no |

[`examples-to-run.py`](examples-to-run.py) lists the examples that `test.py` runs
as smoke tests: each must exit with 0. It keeps the examples from breaking unnoticed.

## Test data

Each P4 program has a directory under [`p4src/`](p4src) with its source, compiled
JSON and, if used, flow table (`flowtable_*.txt`) and topology (`topo.txt`). The
tests never read `examples/p4src`. The JSON is committed, so p4c is not needed; to
regenerate it, run `p4c-bm2-ss` (v1model), `p4c-bm2-psa` or `p4c-bm2-pna` with
`--p4v 16 -o <name>.json <name>.p4`, then run the tests again (another p4c version
can change details such as generated names).

## Packet tests

`p4-packet` runs the `.stf` files in [`p4src/forward`](p4src/forward) on a switch
with three ports, once per architecture: `forward_v1model.p4`, `forward_pna.p4` and
`forward_psa.p4` behave the same, and the pipeline core (`P4SwitchArch` 3) runs
`forward_v1model.p4`. [`p4src/drop`](p4src/drop) checks `mark_to_drop()` in the
ingress and in the egress, on v1model and the pipeline core. [`p4src/priority`](p4src/priority) checks the
priority queues of v1model, [`p4src/resubmit`](p4src/resubmit) and
[`p4src/recirculate`](p4src/recirculate) its resubmit and recirculation,
[`p4src/clone`](p4src/clone) its clones (also to a multicast group) and those of PSA, [`p4src/primitives`](p4src/primitives)
`digest()`, `hash()` with max 0 and `random()` with lo > hi, and [`p4src/lag`](p4src/lag)
the LAG member that its multicast picks. The format is a subset of p4c's STF:

```
# comment
mirroring_add 5 2                             # clones of mirroring session 5 leave port 2
mirroring_add_mc 6 1                          # v1model: clones of session 6 go to multicast group 1
mc_set_lag_membership 3 1 2                   # v1model: LAG 3 has the ports 1 and 2
mc_mgrp_create 1                              # multicast group 1
mc_node_create 0 2 | 3                        # node 0 (rid 0): port 2 and LAG 3
mc_node_associate 1 0                         # node 0 is in group 1
packet 0 0000000000fe 000000000010 0800 ...   # send this frame into port 0
expect 1 000000000011 0000000000fe 0800 ...   # this frame leaves port 1
register MyEgress.egress_frames 0 2           # after the run, this register holds 2
```

Frames are Ethernet frames in hex; spaces are ignored and `*` in `expect` matches
any nibble. A test passes if each port sends exactly the frames expected on it, in
that order. All frames are sent at the same time, so frames to one port queue up.
To add a case, add an `.stf` file and its name in `p4-packet-test-suite.cc`; a new
program goes in its own directory as `<dir>/<dir>_<arch>.p4`.

## Writing a test

- Find data with `SetDataDir(NS_TEST_SOURCEDIR)` and `CreateDataDirFilename()`.
- Set `BmLogLevel` to `off`; the BMv2 log is written for every packet.
- Leave `ThriftPort` at 0. A switch reserves a free port starting at
  `$P4SIM_THRIFT_PORT_BASE` (9090) with a lock on `/tmp/p4sim-thrift-<port>.lock`,
  so parallel runs never share a port.
- Keep tests small: every packet runs through the BMv2 pipeline.
- Call `Simulator::Destroy()` in `DoTeardown()`, which also runs after a failed check.
- A P4 JSON that fails to load aborts the process (`NS_FATAL_ERROR`), so it can
  only be tested in a separate process.
