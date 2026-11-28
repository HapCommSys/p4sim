# The externs of PSA and PNA programs

The PSA externs of BMv2 1.15.8, from
[targets/psa_switch/externs](https://github.com/p4lang/behavioral-model/tree/1.15.8/targets/psa_switch/externs),
under the Apache License 2.0 with the notices of their authors:

| Extern | Files |
|---|---|
| `Counter` | `psa_counter.{h,cpp}` |
| `Hash` | `psa_hash.{h,cpp}` |
| `InternetChecksum` | `psa_internet_checksum.{h,cpp}` |
| `Meter` | `psa_meter.{h,cpp}` |
| `Random` | `psa_random.{h,cpp}` |

BMv2 builds them into the `psa_switch` program, not into the libraries that
P4sim links. Without them, a PSA program that uses one of them does not load
("Invalid reference to extern type"). They register themselves under their
P4 names when the P4sim library is loaded; `psa-externs.h` makes the PSA and
PNA cores reference them, so that a static build keeps them too.

The examples `p4-psa-meter` (`Meter`, `Counter`) and `p4-psa-ecmp` (`Hash`,
`Counter`) use them, and set or read them with `P4RuntimeApi`.

**PNA** uses the same ones: BMv2's `pna_nic` has copies of these files that
differ only in their names and copyright lines, and registers them under the
same P4 names. So one set serves both; two sets in one program would collide.

**Changes in P4sim**, everything else is as in BMv2 1.15.8:
- `psa_meter.cpp` measures simulation time instead of the wall clock (`init()`
  and `execute()`), so that a meter's rates refer to the simulated traffic.
- `psa_random.cpp` draws from the random number engine of its switch
  (`P4SwitchCore::GetRandomEngine()`), which follows ns-3's seed and run,
  instead of an engine seeded with the thread id.
- `Counter.count()` and `Meter.execute()` check the index in every build. BMv2
  checks it only without `NDEBUG` (BMv2 issue #1459), and an index out of range
  then writes past the array: p4c's sample `psa-counter3.p4` corrupted the heap.
  Out of range, a counter counts nothing and a meter leaves its result unset;
  the BMv2 log (`BmLogLevel`) says so.

The runtime API reaches these counters and meters by their names, as in
BMv2's `psa_switch` (`P4SwitchCore::read_counters()` and the other counter and
meter calls): `counter_read` or `meter_array_set_rates` in the flow-table file
of a PSA switch (`psa_switch_CLI`), and `P4RuntimeApi` / `P4Controller` on PSA
and PNA. The flow-table file of a PNA switch runs in `bm_CLI`, which does not
know these meters.

Not available, because p4c does not compile them for BMv2:
- `DirectCounter` and `DirectMeter` in PSA programs: p4c 1.2.5.17 leaves a
  `DirectCounter` out of the JSON (with a warning, also when a table owns it)
  and stops on a `DirectMeter`.
- A `Counter` in a PNA program: p4c 1.2.5.17 and 1.2.5.19 stop with a compiler
  bug for BMv2's PNA (`PNA_CounterType_t`).
- `Random` is compiled by p4c into BMv2's `modify_field_rng_uniform`, as in a
  v1model program; `psa_random.cpp` is kept for programs that use the extern.
