# Examples

Run an example from the ns-3 folder:

```bash
./ns3 run p4-v1model-ipv4-forwarding
./ns3 run "p4-basic-example --ns3::P4SwitchNetDevice::BmLogLevel=trace"  # with the BMv2 log in /tmp
./ns3 run "p4-source-routing --PrintHelp"                                 # the options of an example
```

Each example checks its result: it prints `[PASS]` or `[FAIL]`, and exits with 1 if a check
fails. `--MinDelivery=0` turns off the check that the packets arrive, for experiments that
lose packets on purpose. `./test.py` runs every example below, with the arguments in
[`test/examples-to-run.py`](../test/examples-to-run.py).

## List

The architecture is the value of the `P4SwitchArch` attribute. A switch has two kinds of
port ([switch.md](switch.md)): **switched Ethernet**, a `SwitchedEthernetChannel` per
port, set up by `SwitchedEthernetHelper`; and **bridge** ports, ordinary ns-3 devices
(CSMA, or the P4 point-to-point device of `P4PointToPointHelper`) added with
`P4Helper::Install(node, devices)`.

| Example | What it shows | Architecture | Ports | P4 files (`examples/p4src/`) |
|---|---|---|---|---|
| `p4-hello` | The first example, and a test bed for own P4 programs: `--json`, `--flowTable`, `--hosts` ([getting-started.md](getting-started.md)) | v1model | switched Ethernet | `hello` |
| `p4-v1model-ipv4-forwarding` | Two hosts and a switch with IPv4 forwarding; `--model=1` runs an ns-3 bridge instead, as a baseline | v1model | switched Ethernet | `simple_v1model` |
| `p4-v1model-ipv4-forwarding-bridge` | The same over bridge ports: `--channelType=p2p` (default) or `csma` | v1model | P4 point-to-point or CSMA | `simple_v1model` |
| `p4-psa-ipv4-forwarding` | Two hosts and a switch with IPv4 forwarding | PSA | CSMA | `simple_psa` |
| `p4-psa-meter` | A policer: a two-rate three-color `Meter` per port drops the frames over the peak rate, and a `Counter` counts each color; the control plane sets the rates and reads the counter with `P4RuntimeApi` | PSA | switched Ethernet | `psa_meter` |
| `p4-psa-ecmp` | ECMP: the CRC-16 of the 5-tuple (`Hash`) spreads the flows over two links, all packets of a flow on one; a `Counter` of the next switch shows which link each flow took | PSA | switched Ethernet | `psa_ecmp` |
| `p4-pna-ipv4-forwarding` | Two hosts and a NIC-style switch with IPv4 forwarding | PNA | CSMA | `simple_pna` |
| `p4-basic-example` | Four hosts and four switches with IPv4 forwarding and ARP (tutorial `basic` [1]) | v1model | CSMA | `p4_basic` |
| `p4-basic-controller` | `p4-basic-example` with flow entries that `P4Controller` changes during the simulation | v1model | CSMA | `p4_basic` |
| `p4-controller-action-profile` | `P4Controller` with an action profile (indirect table) | v1model | CSMA | `action_profile` |
| `p4-l2-learning` | L2 learning: the switch floods frames to unknown addresses and sends a digest for each unknown source; `P4Controller` learns the ports from the digests and fills the tables. `--learn=0` ignores the digests | v1model | switched Ethernet | `l2_learning` |
| `p4-basic-tunnel` | A tunnel with a custom header (tutorial `basic_tunnel` [2]) | v1model | P4 point-to-point | `basic_tunnel` |
| `p4-firewall` | A stateful TCP firewall: connections opened from inside pass, those opened from outside are dropped (tutorial `firewall` [3]) | v1model | CSMA | `firewall` |
| `p4-calc` | The switch answers calculator requests (tutorial `calc` [4]) | v1model | CSMA | `calc` |
| `p4-l3-router` | Three routers in a line with L3 forwarding | v1model | CSMA | `l3_router` |
| `p4-link-monitoring` | In-band probes that collect link utilisation (tutorial `link_monitor` [5]) | v1model | CSMA | `link_monitor` |
| `p4-source-routing` | Source routing with a header stack; `--path` gives the egress ports (tutorial `source_routing` [6]) | v1model | CSMA | `source_routing` |
| `p4-queue-test` | Three UDP flows with different priorities through one switch | v1model | P4 point-to-point | `qos` |
| `p4-priority-queues` | Strict-priority queues: the P4 program maps a UDP port to priority 7, so a small flow passes a congested port without queueing delay; the egress counts time in the queue and queue depth per queue in registers. `--priority=0` puts both flows in one queue | v1model | switched Ethernet | `queueing` |
| `p4-latency` | What makes up the one-way delay through a switch: serialisation, propagation, `PipelineDelay` and queueing, which the P4 program measures itself (`deq_timedelta`) | v1model | switched Ethernet | `queueing` |
| `p4-spine-leaf-topo` | A spine-leaf network with ECMP load balancing (tutorial `load_balance` [7]) | v1model | CSMA and P4 point-to-point | `load_balance` |
| `p4-topo-fattree` | A k-ary fat tree with generated flow tables (`FattreeTopoHelper`, `BuildFlowtableHelper`); `--model=1` runs ns-3 bridges instead | v1model | CSMA and P4 point-to-point | `fat-tree` |
| `topo-fattree` | The same fat tree from plain ns-3 nodes, without P4, as a baseline | – | CSMA | – |
| `p4-ipv4-animation` | IPv4 forwarding with a NetAnim trace (`p4-ipv4-animation.xml`); needs the ns-3 module `netanim`, which the quick installation does not build | v1model | CSMA | `simple_v1model` |
| `p4-voq-fabric-integration` | The VOQ + fabric traffic manager (`EnableVoqFabric`) end to end, and the default path | v1model | switched Ethernet | `simple_v1model` |
| `p4-voq-fabric-throughput` | Goodput of the traffic manager path under overload | v1model | switched Ethernet | `simple_v1model` |
| `p4-voq-fabric-priority` | Strict priority in the traffic manager: two flows into one port | v1model | switched Ethernet | `qos` |
| `p4-custom-header-test` | Builds, serialises and parses a `CustomHeader` (no switch) | – | – | – |
| `p4-p2p-custom-header-test` | Two P4 point-to-point devices add and parse a custom header (no switch) | – | P4 point-to-point | – |

[traffic-manager.md](traffic-manager.md) explains the three `p4-voq-fabric-*` examples.
Results of the examples in the paper are in
[p4sim-artifact-icns3](https://github.com/HapCommSys/p4sim-artifact-icns3).

## P4 files

Each folder of `examples/p4src/` holds:

- the P4 program (`.p4`) and the program compiled by `p4c` for BMv2 (`.json`);
- one flow table per switch, `flowtable_<i>.txt`: commands of `simple_switch_CLI`
  (v1model), `psa_switch_CLI` (PSA) or `bm_CLI` (PNA), run when the switch starts;
- `topo.txt`, if the example reads its topology from a file (`P4TopologyReaderHelper`).

`topo.txt` starts with the numbers of switches, hosts and links. The switches are nodes
`0` to `switches - 1`, the hosts follow. Then comes one line per link,
`<node> <h|s> <node> <h|s> <data rate> <delay>`, and one line per switch,
`<switch> <function>`. The ports of a switch are numbered in the order of its links.

An example reads its files through `GetP4ExamplePath()` (`ns3/format-utils.h`), which
returns `examples/p4src` in the p4sim folder of the build, so no path needs to be set.

Contributions are welcome: a new example needs its program in `examples/p4src/`, an entry
in `examples/CMakeLists.txt`, and a line in `test/examples-to-run.py`.

## References

1. [p4lang/tutorials: basic](https://github.com/p4lang/tutorials/tree/master/exercises/basic)
2. [p4lang/tutorials: basic_tunnel](https://github.com/p4lang/tutorials/tree/master/exercises/basic_tunnel)
3. [p4lang/tutorials: firewall](https://github.com/p4lang/tutorials/tree/master/exercises/firewall)
4. [p4lang/tutorials: calc](https://github.com/p4lang/tutorials/tree/master/exercises/calc)
5. [p4lang/tutorials: link_monitor](https://github.com/p4lang/tutorials/tree/master/exercises/link_monitor)
6. [p4lang/tutorials: source_routing](https://github.com/p4lang/tutorials/tree/master/exercises/source_routing)
7. [p4lang/tutorials: load_balance](https://github.com/p4lang/tutorials/tree/master/exercises/load_balance)
