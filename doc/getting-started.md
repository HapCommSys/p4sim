# Getting started

Your first half hour with P4sim, after the [installation](installation.md) or in the
[Docker image](docker.md). All commands run in the ns-3 folder. `p4-hello` needs
only a P4 program and a flow table, no C++:

```
host 0 ── port 0 ┐
host 1 ── port 1 ┼── P4 switch
host 2 ── port 2 ┘
```

Host *i* is on port *i* and has the address `10.0.0.<i+1>` and the MAC address
`00:00:00:00:00:0<i+1>`. Every host sends three UDP echo requests to every other one.

## 1. Run it

```console
$ ./ns3 run p4-hello
host 0: port 0, 10.0.0.1, 00:00:00:00:00:01
host 1: port 1, 10.0.0.2, 00:00:00:00:00:02
host 2: port 2, 10.0.0.3, 00:00:00:00:00:03
P4 switch 1 thrift port: 9090

replies     to 0  to 1  to 2
  host 0      -   3/3   3/3
  host 1     3/3    -   3/3
  host 2     3/3   3/3    -
[PASS] 6 of 6 pairs of hosts reach each other
```

The program, [`hello.p4`](../examples/p4src/hello/hello.p4), has one table, `dmac`. The
flow table, [`flowtable.txt`](../examples/p4src/hello/flowtable.txt), fills it.

## 2. Change the flow table

Copy the three files, so that the originals stay as they are:

```bash
mkdir my-switch
cp contrib/p4sim/examples/p4src/hello/hello.p4 my-switch/my.p4
cp contrib/p4sim/examples/p4src/hello/hello.json my-switch/my.json
cp contrib/p4sim/examples/p4src/hello/flowtable.txt my-switch/my.txt
```

Delete the line of `00:00:00:00:00:02` in `my-switch/my.txt`. Nobody reaches host 1 any
more, so host 1 gets no replies either:

```console
$ ./ns3 run "p4-hello --json=my-switch/my.json --flowTable=my-switch/my.txt"
...
replies     to 0  to 1  to 2
  host 0      -   0/3   3/3
  host 1     0/3    -   0/3
  host 2     3/3   0/3    -
[FAIL] 2 of 6 pairs of hosts reach each other
```

A flow table holds commands of `simple_switch_CLI` (v1model), `psa_switch_CLI` (PSA) or
`bm_CLI` (PNA), one per line; empty lines and lines that start with `#` are skipped.
P4sim prints each command that fails, with its file and line, and continues:

```
my-switch/my.txt:3: table_add dmac foward 00:00:00:00:00:02 => 1
    Error: Table dmac has no action foward
```

## 3. Change the P4 program

In `my-switch/my.p4`, drop what port 0 sends to port 2:

```p4
    apply {
        dmac.apply();
        if (smeta.ingress_port == 0 && smeta.egress_spec == 2) {
            drop();
        }
    }
```

The simulation reads the compiled JSON, not the `.p4` file, so compile after each change
(no rebuild of ns-3 is needed). With the flow table of step 1:

```console
$ p4c-bm2-ss --p4v 16 -o my-switch/my.json my-switch/my.p4
$ ./ns3 run "p4-hello --json=my-switch/my.json"
...
  host 0      -   3/3   0/3
  host 1     3/3    -   3/3
  host 2     0/3   3/3    -
[FAIL] 4 of 6 pairs of hosts reach each other
```

Use `p4c-bm2-psa` for PSA and `p4c-bm2-pna` for PNA, and tell P4sim the architecture:
`--ns3::P4SwitchNetDevice::P4SwitchArch=1` (PSA) or `2` (PNA).

## 4. Look inside

```bash
./ns3 run "p4-hello --ns3::P4SwitchNetDevice::BmLogLevel=trace"
grep "Table 'MyIngress" /tmp/bmv2-9090-pipeline.log.txt   # the Thrift port of the output
```

```
[16:16:50.415] [bmv2] [D] [thread 121605] [0.0] [cxt 0] Table 'MyIngress.dmac': hit with handle 1
```

`[0.0]` is the packet. `--pcap=true` writes the frames of each host to
`p4-hello-<host>-0.pcap`, for Wireshark or `tcpdump -r`.

## 5. Write your own simulation

Copy [`p4-hello.cc`](../examples/p4-hello.cc) to `scratch/my-sim.cc` and run
`./ns3 run my-sim`; ns-3 compiles it. Its five parts are: the switch, the links, the
addresses, the traffic, the result. The rules that most first programs miss:

- **Ports** are numbered in the order in which the links are added to the switch.
- **MAC addresses** in a flow table must be those of the hosts: set them with
  `SetAddress()`, as `p4-hello` does. Otherwise ns-3 numbers them in the order in which
  the devices are created.
- **ARP** reaches the P4 program like every other frame. Either the program forwards it
  (as in `p4-v1model-ipv4-forwarding`), or the hosts get their neighbours' addresses
  beforehand (as in `p4-hello`).

## 6. Where to go next

| | Example | What is new |
|---|---|---|
| First | `p4-v1model-ipv4-forwarding` | IPv4 and ARP tables, TTL and checksum, throughput |
| | `p4-basic-example` | several switches, a topology file, a flow table per switch |
| | `p4-calc` | the switch answers a packet with its own header |
| Next | `p4-firewall` | state in registers |
| | `p4-basic-tunnel`, `p4-source-routing` | own headers on the hosts |
| | `p4-basic-controller`, `p4-l2-learning` | tables changed during the simulation, digests |
| | `p4-psa-ipv4-forwarding`, `p4-pna-ipv4-forwarding` | other architectures |
| | `p4-v1model-ipv4-forwarding-bridge` | CSMA and point-to-point links as ports |
| | `p4-multicast` | multicast groups; your own solution of the p4lang exercise with `--json` |
| Advanced | `p4-priority-queues`, `p4-latency` | queues and timing |
| | `p4-ecn`, `p4-mri` | queue depth in the P4 program: ECN marks, in-band records |
| | `p4-spine-leaf-topo`, `p4-topo-fattree` | ECMP, generated topologies and tables |
| | `p4-voq-fabric-*` | the traffic manager |

[examples.md](examples.md) lists all examples, and [test/Readme.md](../test/Readme.md)
shows how to test a P4 program with packets (`.stf` files).

## If it does not work

| You see | Likely cause |
|---|---|
| `cannot open the flow table ...` | Wrong path. Relative paths start at the ns-3 folder |
| `Error: Invalid table name`, `has no action`, `needs N parameters`, `needs N key fields` | The flow table does not match the program; print its names with `grep '"name" : "My' my.json` |
| `Invalid table operation (IMMUTABLE_TABLE_ENTRIES)` | The table has `const entries` in the program; run without a flow table: `--flowTable=none` |
| `Invalid table operation (NO_TABLE_KEY)`, `needs 0 key fields` | The table has no key: use `table_set_default` |
| `failed to load P4 JSON ...` | The JSON is missing, or compiled for another architecture than `P4SwitchArch` |
| No error, but no replies | Read the pipeline log (step 4): a table that misses, a wrong port, or a destination MAC address that no host has |
| A change of the program has no effect | It is not compiled, or the simulation reads another JSON |
