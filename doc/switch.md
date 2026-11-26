# Switched Ethernet: switch and host devices

A switched-Ethernet port connects a P4 switch to one device over its own
full-duplex `SwitchedEthernetChannel`. A switch can also have bridge ports
(see the [README](../README.md#switch-ports)).

## Devices and helpers

- **`P4SwitchNetDevice`** (on the switch node) runs the P4 program. A frame that
  arrives on a port goes through the pipeline, and the program picks the output
  ports. `P4Helper` creates it; its attributes are the P4 ones (`JsonPath`,
  `FlowTablePath`, `P4SwitchArch`, `SwitchRate`, ...).
- **`SwitchedEthernetHostDevice`** (on each host) is a plain Ethernet NIC. It adds
  the Ethernet header, puts the frames on the channel one at a time from its
  transmit queue, and passes received payloads up to the IP stack.
  `SwitchedEthernetHelper` creates it.

`SwitchedEthernetHelper::Install(sw, hosts)` creates, for each host, a channel
(the switch at one end, the host at the other) and the host's device, and returns
the host devices. Its channel attributes are `DataRate`, `Delay` and `Framing`.

```cpp
P4Helper p4;
p4.SetDeviceAttribute("JsonPath",      StringValue(jsonPath));
p4.SetDeviceAttribute("FlowTablePath", StringValue(flowTable));
p4.SetDeviceAttribute("P4SwitchArch",  UintegerValue(0));  // v1model
Ptr<P4SwitchNetDevice> sw =
    DynamicCast<P4SwitchNetDevice>(p4.Install(switchNode).Get(0));

SwitchedEthernetHelper eth;
eth.SetChannelAttribute("DataRate", StringValue("1Gbps"));
eth.SetChannelAttribute("Delay",    StringValue("0.01ms"));
NetDeviceContainer hostDevs = eth.Install(sw, terminals);
// hostDevs.Get(i) is the device of terminals.Get(i)
```

## Pipeline and queues of the switch

On v1model and PSA, a frame that arrives on a port enters the input buffer of
the pipeline (`InputBufferSizeLow` packets), passes the P4 pipeline and waits in
the output queues (`QueueBufferSize` packets each) until its port is free;
[event-driven-tm-scheduler.md](event-driven-tm-scheduler.md) describes how a port
takes its next frame. PNA takes the same path with an input buffer of 1024
packets. The pipeline core sends a frame to its port after the pipeline (and
`PipelineDelay`), without input buffer or output queues. The attributes of
`P4SwitchNetDevice` set the timing:

- **`SwitchRate`** (v1model and PSA) models a slower switch, such as a software
  switch: an idle pipeline takes a packet at once, and packets that arrive while
  it is busy wait in the input buffer, or are dropped (`MacRxDrop`) when it is
  full. Resubmitted and recirculated passes count too. With the default, 0, only
  the links limit the traffic, as in a hardware switch.
- **`PipelineDelay`** adds a fixed latency to every packet instead and does not
  change the throughput.
- **`TransferBufferSize`** stands for the port queue after the egress of a
  hardware switch (v1model and PSA): a port takes packets from the output queues
  while this buffer has room, and they pass the egress then. A frame in the
  buffer is not overtaken any more: a high-priority packet that arrives later
  waits behind it. The backlog of a congested port stays in the output queues,
  where the priorities apply, and `enq_qdepth`/`deq_qdepth` count only those. On
  v1model, `deq_timedelta` likewise ends when the packet leaves its output queue:
  it does not contain the wait in this buffer. A port can hold
  `TransferBufferSize` more frames than `QueueBufferSize` allows.
- **`EnableSwap`** allows swapping the P4 program at run time. The swap waits
  until the switch holds no packet, the frames in the transfer buffers included;
  frames that arrive meanwhile wait and use the new program. On PNA it does not
  wait for the frames in the output queues ([TODO.md](TODO.md)).

The flow-table file (`FlowTablePath`) runs in `simple_switch_CLI` (v1model and
the pipeline core), `psa_switch_CLI` (PSA) or `bm_CLI` (PNA). On v1model and PSA,
besides the table commands, it can use `mirroring_add`, `mirroring_add_mc`,
`set_queue_depth` and `set_queue_rate`, and on v1model `mirroring_delete`: BMv2 1.15.8's
`psa_switch_CLI` stops at `mirroring_delete`, as at any failed mirroring command,
and skips the rest of the file. P4sim prints the commands that fail, with the file
and the line; a flow-table file that cannot be opened ends the simulation. Empty
lines and lines that start with `#` are skipped.

## Timing on the wire

A frame takes (its bytes × 8 / `DataRate`) on the wire, then `Delay` to reach
the far end, which gets it whole (store and forward). The defaults are 10 Gbps
and no delay. The sender can start the next frame as soon as the last bit of
the previous one has left; it does not wait for the propagation delay. The
channel keeps the exact times, so that rounding to the simulator's 1 ns
resolution does not add up over back-to-back frames.

By default a frame takes only its own bytes. Real Ethernet puts more on the
wire; set `Framing` to `Ethernet` to model it (IEEE 802.3, the same for every
data rate):

| On the wire | Bytes |
|---|---|
| preamble and start-of-frame delimiter | 8 |
| frame check sequence (FCS) | 4 |
| padding of a frame shorter than 60 bytes (64 with the FCS) | up to 60 |
| interframe gap before the next frame | 12 |

```cpp
eth.SetChannelAttribute("Framing", StringValue("Ethernet"));
```

A 1500-byte IP packet (a 1514-byte frame) then takes 1526 bytes on the wire and
a 12-byte gap, and a 100 Gbps link carries at most 148.8 million minimum frames
per second. These bytes only take time: the far end receives the frame as it was
sent. The line coding and FEC of the physical layer (8b/10b, 64b/66b, RS-FEC)
are not added: Ethernet runs the line faster to absorb them, so the data rate is
the nominal one, on copper and fibre alike.

The P4 point-to-point device (`CustomP2PNetDevice`, installed by
`P4PointToPointHelper`) has the same `Framing` attribute; set it on both ends of
the link. A P4 switch also uses it to estimate when a frame on such a bridge port
has been sent:

```cpp
p2p.SetDeviceAttribute("Framing", StringValue("Ethernet"));
```

## Queues and traffic control on hosts

A host device sends one frame at a time; the frames handed to it meanwhile wait
in its transmit queue, a `DropTailQueue<Packet>` of 100 packets by default.

Like `PointToPointHelper` and `CsmaHelper`, `SwitchedEthernetHelper` enables
flow control on the host devices: when the transmit queue is full, the device
stops the ns-3 traffic control layer, and the packets wait in the queue disc of
the device, which decides what is sent next. `Ipv4AddressHelper` installs
`FqCoDelQueueDisc` on each host device; choose another one with
`TrafficControlHelper` before assigning the addresses:

```cpp
SwitchedEthernetHelper eth;
eth.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue("5p"));
NetDeviceContainer hostDevs = eth.Install(sw, terminals);

InternetStackHelper internet;
internet.Install(terminals);
TrafficControlHelper tch;
tch.SetRootQueueDisc("ns3::PfifoFastQueueDisc");
tch.Install(hostDevs);
Ipv4AddressHelper ipv4;
ipv4.SetBase("10.1.1.0", "255.255.255.0");
ipv4.Assign(hostDevs);
```

A queue disc can only schedule packets that wait in it, so a small device queue
leaves it more to do. `eth.DisableFlowControl()` turns flow control off: no
queue disc is then installed by default, and an installed one passes every
packet on at once.
