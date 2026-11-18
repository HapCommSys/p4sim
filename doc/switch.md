# Switched Ethernet: switch and host devices

## The Two Devices

**P4SwitchNetDevice (on switch node)**
Runs a P4 pipeline
Has N ports — each port is one SwitchedEthernetChannel
When a frame arrives on port K → P4 program decides which port(s) to forward it out
Configured with: JsonPath, FlowTablePath, P4SwitchArch, SwitchRate

**SwitchedEthernetHostDevice (on each host node)**
A plain Ethernet NIC — no P4 knowledge at all
Send path: IP stack → queue disc → Send() → adds Ethernet header → transmit queue → channel, one frame at a time → arrives at switch port
Receive path: switch forwards a frame → channel delivers to ReceiveFrame() → strips Ethernet header → passes payload up to IP stack
Configured with: a MAC address; SwitchedEthernetHelper sets its transmit queue and flow control (see below)

## The Two Helpers (clean separation)

```
P4Helper                         SwitchedEthernetHelper
────────────────────             ────────────────────────────────────
Owns: P4SwitchNetDevice factory  Owns: SwitchedEthernetChannel factory
                                       SwitchedEthernetHostDevice creation

SetDeviceAttribute(...)          SetChannelAttribute(...)
  → JsonPath, FlowTablePath,       → DataRate, Delay, Framing
    P4SwitchArch, SwitchRate

Install(switchNode)              Install(sw, hosts)
  → creates P4SwitchNetDevice      → for each host:
    on switchNode                     creates SwitchedEthernetChannel,
    returns it                        attaches sw to slot 0,
                                      creates SwitchedEthernetHostDevice on host,
                                      attaches host to slot 1,
                                      returns host devices
```

## Example usage

```
// Switch: P4 parameters only
P4Helper p4;
p4.SetDeviceAttribute("JsonPath",      StringValue(jsonPath));
p4.SetDeviceAttribute("FlowTablePath", StringValue(flowTable));
p4.SetDeviceAttribute("P4SwitchArch",  UintegerValue(0));  // V1Model
Ptr<P4SwitchNetDevice> sw =
    DynamicCast<P4SwitchNetDevice>(p4.Install(switchNode).Get(0));

// Hosts: channel/NIC parameters only
SwitchedEthernetHelper eth;
eth.SetChannelAttribute("DataRate", StringValue("1Gbps"));
eth.SetChannelAttribute("Delay",    StringValue("0.01ms"));
NetDeviceContainer hostDevs = eth.Install(sw, terminals);
// hostDevs[0] = NIC on terminals[0], hostDevs[1] = NIC on terminals[1]
```

## Timing on the wire

A frame takes (its bytes × 8 / `DataRate`) on the wire, then `Delay` to reach
the far end, which gets it whole (store and forward). The defaults are 10 Gbps
and no delay. The channel computes this
for both ends and keeps the exact times, so that rounding to the simulator's
1 ns resolution does not add up over back-to-back frames.

By default a frame takes only its own bytes. Real Ethernet puts more on the
wire; set `Framing` to `Ethernet` to model it (IEEE 802.3, the same for every
data rate):

| On the wire | Bytes |
|---|---|
| preamble and start-of-frame delimiter | 8 |
| frame check sequence (FCS) | 4 |
| padding of a frame shorter than 60 bytes (64 with the FCS) | up to 60 |
| interframe gap before the next frame | 12 |

```
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
the link. A P4 switch uses it also for its estimate of when a frame on such a
bridge port is sent:

```
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

```
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

The key insight: the host device is intentionally dumb — it only adds/strips Ethernet headers and passes frames to/from the channel. All intelligence (routing, forwarding) lives in the P4 program on the switch. The two helpers enforce this separation so P4 parameters never bleed into host setup and vice versa.
