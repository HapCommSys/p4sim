# intro

## The Two Devices

**P4SwitchNetDevice (on switch node)**
Runs a P4 pipeline
Has N ports — each port is one SwitchedEthernetChannel
When a frame arrives on port K → P4 program decides which port(s) to forward it out
Configured with: JsonPath, FlowTablePath, P4SwitchArch, SwitchRate

**SwitchedEthernetHostDevice (on each host node)**
A plain Ethernet NIC — no P4 knowledge at all
Send path: IP stack → Send() → adds Ethernet header → hands to channel → arrives at switch port
Receive path: switch forwards a frame → channel delivers to ReceiveFrame() → strips Ethernet header → passes payload up to IP stack
Configured with: just a MAC address

## The Two Helpers (clean separation)

```
P4Helper                         SwitchedEthernetHelper
────────────────────             ────────────────────────────────────
Owns: P4SwitchNetDevice factory  Owns: SwitchedEthernetChannel factory
                                       SwitchedEthernetHostDevice creation

SetDeviceAttribute(...)          SetChannelAttribute(...)
  → JsonPath, FlowTablePath,       → DataRate, Delay
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

The key insight: the host device is intentionally dumb — it only adds/strips Ethernet headers and passes frames to/from the channel. All intelligence (routing, forwarding) lives in the P4 program on the switch. The two helpers enforce this separation so P4 parameters never bleed into host setup and vice versa.

Does this match your intent? If so I can verify the current code matches this design (or fix any gaps).