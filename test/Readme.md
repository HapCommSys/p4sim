# P4sim tests

P4sim runs the packet processing of its switches in the BMv2 behavioral model, an
external library. The tests are therefore split into layers, from fast unit tests
without BMv2 to whole examples.

## Running the tests

ns-3 has to be configured with tests and examples enabled
(`./ns3 configure --enable-tests --enable-examples`). From the ns-3 root:

```bash
./test.py -s p4sim                 # one suite
./test.py -s p4-queue -v           # one suite, with the names of its test cases
./test.py -e p4-basic-example      # one example (as a smoke test)
./build/utils/ns3.39-test-runner-default --suite=p4sim --verbose   # without test.py
```

No environment variable is needed: the tests find their data through
`NS_TEST_SOURCEDIR`. Suites can run in parallel (test.py does), see
[Thrift ports](#thrift-ports).

## Test suites

| Suite | Kind | What it checks | Needs BMv2 |
|---|---|---|---|
| `format-utils` | unit | string and number conversion helpers | no |
| `p4-topology-reader` | unit | reading a topology file | no |
| `p4-p2p-channel-test-suite` | unit | the P4 point-to-point channel | no |
| `p4-queue` | unit | egress queue `NSQueueingLogicPriRL`: capacity, rate, FIFO, priorities, per-port rate | no |
| `p4sim` | unit | switch set-up: v1model, PSA and PNA load their P4 program; Thrift port allocation; `BmLogLevel` | yes |
| `p4-controller` | unit | `P4Controller`: flow entries and action profiles (v1model) | yes, plus `simple_switch_CLI` |

Smoke tests: [`examples-to-run.py`](examples-to-run.py) lists the examples that
test.py runs when it runs the examples. Each must exit with 0.

## Test data

Every test owns its data under [`p4src/`](p4src), one directory per P4 program.
The tests do not read `examples/p4src`, so the examples can change freely.

| Directory | Architecture | Used by |
|---|---|---|
| `simple_v1model/` | v1model | `p4sim`, `p4-controller` |
| `action_profile_v1model/` | v1model | `p4-controller` |
| `simple_psa/` | PSA | `p4sim` |
| `simple_pna/` | PNA | `p4sim` |
| `topology-files/` | - | `p4-topology-reader` |

A directory holds the P4 source, the compiled JSON and, if the test loads one, a
flow table (`flowtable_*.txt`, runtime CLI commands) and a topology (`topo.txt`).
The JSON is committed, so p4c is not needed to run the tests. To regenerate it
(from the directory of the program):

```bash
p4c-bm2-ss   --p4v 16 -o simple_v1model.json simple_v1model.p4   # v1model
p4c-bm2-psa  --p4v 16 -o simple_psa.json     simple_psa.p4       # PSA
p4c-bm2-pna  --p4v 16 -o simple_pna.json     simple_pna_ipv4.p4  # PNA
```

Another p4c version can change details of the JSON, such as generated action
names or metadata fields, so run the tests again after regenerating it.

## Writing a test

- Locate data with `SetDataDir(NS_TEST_SOURCEDIR)` and
  `CreateDataDirFilename("p4src/<program>/<file>")`, not with `P4SIM_DIR` or
  `GetP4ExamplePath()`.
- Turn the BMv2 pipeline log off, unless the test is about it:
  `Config::SetDefault("ns3::P4SwitchNetDevice::BmLogLevel", StringValue("off"))`.
  The log is written for every packet and slows the test down.
- Do not hard-code Thrift ports; leave `ThriftPort` at 0 (automatic).
- Keep the number of packets small: every packet runs through the BMv2 pipeline.
- Call `Simulator::Destroy()` at the end of every test case.
- A P4 JSON that fails to load stops the simulation with `NS_FATAL_ERROR`, which
  aborts the test runner. Such errors can only be tested in a separate process.

## Thrift ports

A switch that loads a flow table starts a Thrift server for the runtime CLI. The
port is chosen when the switch is initialized:

- `ThriftPort` (attribute of `ns3::P4SwitchNetDevice`): `0` (default) picks the
  first free port starting at `$P4SIM_THRIFT_PORT_BASE` (9090 if unset); another
  value is used as is, and the simulation stops if it is in use.
- A port is free if no other p4sim process has reserved it and no program listens
  on it. The reservation is a lock on `/tmp/p4sim-thrift-<port>.lock`, held until
  the process exits (also on a crash).
- The port also names the BMv2 IPC sockets and the pipeline log
  (`/tmp/bmv2-<port>-*`), so parallel simulations do not share those either.

## Not covered yet

- Packet processing results (which port, which bytes) for each architecture:
  STF-style tests with hand-written expected packets.
- The timing and queueing model of the switches.
- Examples compared against reference output.
