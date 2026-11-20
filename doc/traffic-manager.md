# Traffic Manager: VOQ + fabric + strict-priority egress

With `EnableVoqFabric`, a v1model switch sends its packets through a traffic
manager (TM, `P4TrafficManager`) instead of its output queues
(`NSQueueingLogicPriRL`): **virtual output queues (VOQs)** on the input side, a
**fabric scheduler** that matches inputs to outputs, and **strict-priority
egress queues** per output port. The attribute is off by default, and the
default path ([event-driven-tm-scheduler.md](event-driven-tm-scheduler.md)) is
unchanged.

## 1. Concepts

| Concept | What it decides | In the TM |
| --- | --- | --- |
| **VOQ** | Where a packet waits on the input side: one queue per `[inPort][outPort][priority]`, so a busy output does not block packets to other outputs (no head-of-line blocking) | `EnqueueToVoq()`, `m_voq` |
| **Fabric scheduling** | Which input sends to which output in a round | `RunFabricScheduler()` |
| **Strict priority** | Which of the 8 egress queues of a port is served first: the highest priority (7) | `SelectEgressPriority()` |
| **FIFO** | Order within one queue: arrival order | a `std::deque` per `[outPort][priority]` |

## 2. Datapath

```
   ingress pipeline
        │  (outPort, priority chosen by the P4 program)
        ▼
   EnqueueToVoq  ──►  VOQ[inPort][outPort][priority]     (input-buffered)
                            │
                            ▼
                     fabric scheduler                    (priority-first
                       grants in→out                      maximal matching)
                            │
                            ▼
                     egress[outPort][priority]           (per-port SP + FIFO)
                            │
                            ▼
                     egress pipeline + deparse
                            │
                            ▼
                     TransmitCallback  ──►  ns-3 NetDevice ──► wire
                            ▲                                    │
                            └──── NotifyEgressTxComplete ◄───────┘
                                  (frame finished serialising)
```

**Fabric policy.** Priority-first maximal matching: for each priority from 7
down to 0, each input that has no grant yet gets the first free output for which
it has a packet at that priority. An input sends and an output receives at most
one packet per round. The policy is one virtual method,
`DoRunFabricScheduler()`, so iSLIP or round robin can replace it.

**Modes.** In manual mode (the default of the object), the caller runs
`RunFabricScheduler()` and `DequeueFromVoq()`; the unit tests use it. With
`EventDriven=true`, `EnqueueToVoq()` starts a loop of ns-3 events that moves
packets from the VOQs to the egress queues and the wire at the fabric and port
rates. The v1model core uses this mode.

**Completion-driven egress.** With `EgressCompletionDriven=true`, as set by the
core, the TM hands a frame to the `TransmitCallback` and waits. The core runs
the egress pipeline, sends the frame, and reports the outcome with
`NotifyEgressTxComplete(outPort, outcome)`; only then does the TM count the
frame and serve the next one of that port:

- `TRANSMITTED`: the frame is on the wire (`totalTransmitted`,
  `perPriorityTransmitted`, `perPortTxBytes`).
- `DROPPED`: the egress pipeline dropped it, or the port could not send it
  (`totalDropped`, `dropsByReason[EGRESS_POST_DEQUEUE_DROP]`).
- `RECIRCULATED`: the frame went back to the ingress (`totalRecirculated`); it
  is counted when it is sent on a later pass.

So `totalTransmitted` counts only frames that reached the wire. Buffer release,
queueing delays and the `EgressDequeue` trace happen at the dequeue.

## 3. Enabling the TM

```cpp
P4Helper p4;
p4.SetDeviceAttribute("JsonPath",        StringValue(jsonPath));
p4.SetDeviceAttribute("FlowTablePath",   StringValue(flowTablePath));
p4.SetDeviceAttribute("P4SwitchArch",    UintegerValue(0));      // v1model
p4.SetDeviceAttribute("EnableVoqFabric", BooleanValue(true));
```

At start-up the core creates the TM for the number of ports, sets `PortRate` to
the `DataRate` of port 0's channel, connects the `TransmitCallback` to its send
path, and sets `EventDriven` and `EgressCompletionDriven`. It disposes of the TM
before it is destroyed itself.

## 4. Attributes

Attributes of `ns3::P4TrafficManager`. Buffer limits are in bytes; 0 means no
limit. Those that the core does not set can be changed with
`Config::SetDefault()`.

| Attribute | Type | Default | Meaning |
| --- | --- | --- | --- |
| `NumPorts` | uint32 | 0 | Number of ports N, for N·N·8 VOQs; set by the core |
| `GlobalBufferLimit` | uint64 | 0 | All VOQs and egress queues together |
| `InputBufferLimit` | uint64 | 0 | Per input port |
| `VoqLimit` | uint64 | 0 | Per VOQ `[in][out][prio]` |
| `EgressPortLimit` | uint64 | 0 | Egress queues of one output port |
| `EgressQueueLimit` | uint64 | 0 | Per egress queue `[out][prio]` |
| `PortRate` | DataRate | 1Gbps | Serialisation rate of an output port; set by the core |
| `FabricRate` | DataRate | 10Gbps | Transfer rate of the fabric |
| `IngressPipelineDelay` | Time | 0 | Fixed delay before a fabric round |
| `FabricArbitrationDelay` | Time | 0 | Fixed delay of each fabric round |
| `EgressPipelineDelay` | Time | 0 | Fixed egress delay |
| `EventDriven` | bool | false | Move packets with ns-3 events; set by the core |
| `EgressCompletionDriven` | bool | false | Wait for `NotifyEgressTxComplete()` before counting a frame (needs `EventDriven`); set by the core |

The latency of the P4 pipeline is the switch's `PipelineDelay`, which also
applies on this path; the three delays above are the TM's own and add to it.

## 5. Statistics, traces and drop reasons

`GetStats()` returns the cumulative `TmStats`:

| Counter | Meaning |
| --- | --- |
| `totalReceived` | packets offered to `EnqueueToVoq()` |
| `totalVoqEnqueued` | accepted into a VOQ |
| `totalMovedToEgress` | moved from a VOQ to an egress queue by the fabric |
| `totalEgressEnqueued` | accepted into an egress queue |
| `totalTransmitted` | put on the wire (counted after the transmission) |
| `totalRecirculated` | recirculated after the egress dequeue |
| `totalDropped` | dropped for any reason |
| `dropsByReason[6]` | drops per `TmDropReason` |
| `perPriorityTransmitted[8]` | transmitted per priority |
| `perPortTxBytes[]` | bytes transmitted per output port |
| `AvgVoqDelay`, `AvgEgressDelay`, `AvgTotalDelay`, `maxQueueingDelay` | queueing delays |

Trace sources: `VoqEnqueue`, `VoqDequeue`, `EgressEnqueue`, `EgressDequeue`,
`Drop`, `VoqWaitingDelay`, `EgressWaitingDelay`, `TotalDelay`.

Drop reasons (`TmDropReason`); 1 to 5 are checked in this order when a packet is
admitted, 6 is reported by the core after the dequeue:

1. `VOQ_GLOBAL_BUFFER_FULL`: the global buffer would overflow
2. `VOQ_INPUT_BUFFER_FULL`: the buffer of the input port would overflow
3. `VOQ_QUEUE_FULL`: the VOQ `[in][out][prio]` would overflow
4. `EGRESS_PORT_BUFFER_FULL`: the egress buffer of the output port would overflow
5. `EGRESS_QUEUE_FULL`: the egress queue would overflow
6. `EGRESS_POST_DEQUEUE_DROP`: the egress pipeline dropped the frame, or the port
   could not send it

## 6. Tests and examples

`./test.py -s p4-traffic-manager` runs 9 unit tests of the TM alone: enqueue and
dequeue, priority scheduling, VOQs that share an output, fabric matching, buffer
drops, delay measurement, event-driven drain, egress strict priority and egress
drops. The three examples below check their results and exit with 1 if one is
wrong; `test.py` runs them with their defaults. Each run starts one simulation,
because BMv2 cannot be initialised twice in a process.

**`p4-voq-fabric-integration`**: two hosts and a v1model switch with
`simple_v1model`, on the TM path (`--run=voq`, default) or the default path
(`--run=legacy`).

```
$ ./ns3 run "p4-voq-fabric-integration --run=voq"
  rxBytes=298000  tmPresent=1  tmReceived=300  tmVoqEnqueued=300  tmTransmitted=300  tmDropped=0
$ ./ns3 run "p4-voq-fabric-integration --run=legacy"
  rxBytes=298000  tmPresent=0
```

Both paths deliver the same bytes; on the TM path every packet received is
transmitted.

**`p4-voq-fabric-throughput`**: one UDP flow at 1.2 times the line rate of the
egress port (`--linkRate`), from a host on a 10 Gbps link. With 1400-byte
payloads, the headers limit the goodput to 1400 / (1400 + 42) = 97.09 % of the
line rate.

| `--linkRate` | Goodput | Drops in the TM |
| --- | --- | --- |
| 100Mbps | 97.13 Mbps (97.13 %) | 0 |
| 1000Mbps | 970.92 Mbps (97.09 %) | 0 |

**`p4-voq-fabric-priority`**: two UDP flows from two hosts into one 100 Mbps
port, each at 0.7 times the port's line rate. The `qos` program gives UDP port
4000 priority 3 (HIGH) and port 2000 priority 1 (LOW).

| Flow | Offered | Delivered |
| --- | --- | --- |
| HIGH (priority 3) | 70 Mbps | 67.26 Mbps (96.1 %) |
| LOW (priority 1) | 70 Mbps | 29.57 Mbps |

HIGH keeps almost all of its load, LOW gets what is left, and the TM drops the
692 frames that do not fit into the egress buffer (`--egressBufferBytes`, 65536 by default).

## 7. Files

| File | Role |
| --- | --- |
| `utils/p4-traffic-manager.{h,cc}` | VOQs, fabric scheduler, egress queues, statistics and traces |
| `model/p4-core-v1model.{h,cc}` | Creates, connects and disposes of the TM; the send path and the completion signal |
| `model/p4-switch-net-device.{h,cc}` | The `EnableVoqFabric` attribute |
| `test/p4-traffic-manager-test-suite.cc` | The unit tests |
| `examples/p4-voq-fabric-{integration,throughput,priority}.cc` | The examples |
