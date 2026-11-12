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
| `p4-p2p-channel` | the P4 point-to-point channel | no |
| `p4-queue` | egress queue: capacity, rate, FIFO, per-port rate, priorities | no |
| `p4sim` | v1model, PSA and PNA load their program; Thrift ports; `BmLogLevel` | yes |
| `p4-controller` | flow entries and action profiles, read back from the switch | yes, and `simple_switch_CLI` |

[`examples-to-run.py`](examples-to-run.py) lists the examples that `test.py` runs
as smoke tests: each must exit with 0. It keeps the examples from breaking unnoticed.

## Test data

Each P4 program has a directory under [`p4src/`](p4src) with its source, compiled
JSON and, if used, flow table (`flowtable_*.txt`) and topology (`topo.txt`). The
tests never read `examples/p4src`. The JSON is committed, so p4c is not needed; to
regenerate it, run `p4c-bm2-ss` (v1model), `p4c-bm2-psa` or `p4c-bm2-pna` with
`--p4v 16 -o <name>.json <name>.p4`, then run the tests again (another p4c version
can change details such as generated names).

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
