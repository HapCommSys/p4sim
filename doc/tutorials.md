# The p4lang tutorials in P4sim

[p4lang/tutorials](https://github.com/p4lang/tutorials/tree/master/exercises) teaches P4
with exercises: a P4 program, its table entries and a Mininet network of BMv2 switches.
P4sim runs P4 programs on the same BMv2, inside an ns-3 simulation, so most exercises
have an example here. This page lists them and shows what changes on the way from
Mininet to ns-3.

## Exercises and examples

| Exercise | Example | P4 program in `examples/p4src/` |
|---|---|---|
| `basic` | `p4-basic-example` | the solution, changed (\*) |
| `basic_tunnel` | `p4-basic-tunnel` | the solution, changed (\*); the tunnel EtherType is 0xDC instead of 0x1212 |
| `calc` | `p4-calc` | the solution, unchanged |
| `ecn` | `p4-ecn` | the solution, unchanged; the exercise's network and table entries |
| `firewall` | `p4-firewall` | the solution, changed (\*) |
| `flowcache` | – | needs PacketIn/PacketOut and idle timeouts of table entries, which P4sim does not have |
| `link_monitor` | `p4-link-monitoring` | the solution, changed (\*) |
| `load_balance` | `p4-spine-leaf-topo` | the solution, changed (\*), in a spine-leaf network: it hashes UDP ports instead of TCP ports, keeps the destination address, and applies `ecmp_nhop` whether `ecmp_group` hit or not |
| `mri` | `p4-mri` | the solution, unchanged; the exercise's network and table entries |
| `multicast` | `p4-multicast` | the solution, unchanged; the exercise's network and the table entries of its solution, whose multicast group already has port 4 (step 6 of the exercise) |
| `p4runtime` | `p4-basic-controller` | P4sim has no P4Runtime server: `P4Controller` changes the tables from the simulation |
| `qos` | `p4-queue-test`, `p4-voq-fabric-priority` | an own program, `qos.p4`, with priority queues instead of the exercise's DSCP marking |
| `source_routing` | `p4-source-routing` | the solution, but its `drop()` does not drop |

(\*) The program forwards ARP, and its IPv4 table is an exact-match table with another
name (`ipv4_nhop` or `ipv4_exact` instead of the solution's `ipv4_lpm`), so the
exercise's runtime files do not fit it; the example has its own flow tables. Its
`drop()` sets the egress port to 511 itself, as `mark_to_drop` does in BMv2.

Every example checks its result: it prints `[PASS]` or `[FAIL]` and exits with 1 if a
check fails ([examples.md](examples.md)).

## From Mininet to ns-3

| In the exercise | In P4sim |
|---|---|
| `topology.json` | the ns-3 script builds the network, in C++ ([`examples/tutorial-triangle.h`](../examples/tutorial-triangle.h)) or from a `topo.txt` |
| ports from 1 (`s1-p1`) | ports from 0, in the order in which they are connected: port n of the exercise is port n-1 |
| `s1-runtime.json` (P4Runtime) | a flow table per switch: `simple_switch_CLI` commands, run when the switch starts |
| static ARP entries on the hosts | the script sets the ARP entries, or the P4 program forwards ARP |
| `send.py`, `receive.py` | frames built in the script, or ns-3 applications; a handler on the device reads the frames that arrive |
| `iperf -u`, `ping` | `OnOffApplication`, `UdpEchoClient` |
| link bandwidth in `topology.json` | the `DataRate` of the channel |
| timing depends on the host computer | simulation time: the same queues, marks and records in every run |

The last row matters for `ecn` and `mri`: in Mininet the queue of `s1` builds up only
while both senders run at the same time, so the `ecn` exercise asks to start them
together. In P4sim the congestion starts at a fixed time of the simulation, and the
examples check the marks and queue depths that it causes.

An entry of a runtime file

```json
{"table": "MyIngress.ipv4_lpm", "match": {"hdr.ipv4.dstAddr": ["10.0.2.0", 24]},
 "action_name": "MyIngress.ipv4_forward",
 "action_params": {"dstAddr": "08:00:00:00:02:00", "port": 3}}
```

becomes the line

```
table_add MyIngress.ipv4_lpm MyIngress.ipv4_forward 10.0.2.0/24 => 08:00:00:00:02:00 2
```

A default entry (`"default_action": true`) becomes `table_set_default <table> <action>
<parameters>`, and a multicast group (`multicast_group_entries`) becomes
`mc_mgrp_create`, `mc_node_create` and `mc_node_associate`; see
`examples/p4src/{ecn,mri,multicast}/flowtable*.txt`.

## Your own solution

`p4-ecn`, `p4-mri` and `p4-multicast` take your own solution of the exercise and run
their checks on it, with the network and table entries of the table above:

```bash
p4c-bm2-ss --p4v 16 -o ecn.json ecn.p4   # your ecn.p4
./ns3 run "p4-ecn --json=$PWD/ecn.json"
```

The checks show what is missing: for an `ecn.p4` that marks nothing, `p4-ecn` reports
`[FAIL] 0 packets were marked with ECN 3 while the queue was long`. `p4-hello` runs any
v1model program on one switch ([getting-started.md](getting-started.md)).
