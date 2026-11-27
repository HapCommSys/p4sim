/*
 * Copyright (c) 2026 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * Multicast, the "multicast" exercise of p4lang/tutorials:
 * https://github.com/p4lang/tutorials/tree/master/exercises/multicast
 * The P4 program is the reference solution of the exercise, unchanged, and the
 * flow table is the runtime file of the solution (examples/p4src/multicast), whose
 * multicast group already has port 4, step 6 of the exercise.
 *
 *   h1 ── port 0 ┐
 *   h2 ── port 1 ┤
 *   h3 ── port 2 ┼── s1 (multicast.p4)
 *   h4 ── port 3 ┘
 *
 * The ports are the tutorial's minus one; the hosts have its addresses
 * (10.0.0.<host>) and MAC addresses (08:00:00:00:0<host>:<host><host>). The switch
 * forwards a frame by its destination MAC address. A frame to any other address,
 * such as an ARP request to the broadcast address, goes to multicast group 1, all
 * ports; the egress drops the copy for the port that the frame came from.
 *
 * Unlike in p4-ecn and p4-mri, the hosts know no MAC addresses in advance: they
 * learn them with ARP, whose requests reach the other hosts through the multicast
 * group. Each host sends three UDP echo requests to every other host, and h1 sends
 * one broadcast frame of its own EtherType. The program checks that all hosts
 * reach each other, and that the broadcast frame reaches every host but h1 once.
 */

#include "example-check.h"

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-helper.h"

using namespace ns3;

namespace
{

const uint32_t N_HOSTS = 4;
const uint32_t N_REQUESTS = 3;      ///< echo requests per pair of hosts
const uint16_t PROBE_TYPE = 0x88b5; ///< EtherType of h1's broadcast frame (local experimental)

/// Count a reply that an echo client received
void
CountReply(uint32_t* replies, Ptr<const Packet>)
{
    ++*replies;
}

/// Count a broadcast frame of h1 that a host received
void
CountProbe(uint32_t* probes,
           Ptr<NetDevice>,
           Ptr<const Packet>,
           uint16_t,
           const Address&,
           const Address&,
           NetDevice::PacketType)
{
    ++*probes;
}

/// h1 sends its broadcast frame
void
SendProbe(Ptr<NetDevice> device)
{
    device->Send(Create<Packet>(46), Mac48Address::GetBroadcast(), PROBE_TYPE);
}

} // namespace

int
main(int argc, char* argv[])
{
    std::string dir = GetP4ExamplePath() + "/multicast";
    std::string json = dir + "/multicast.json";
    bool pcap = false;
    CommandLine cmd(__FILE__);
    cmd.AddValue("json", "The compiled P4 program, e.g. your own solution of the exercise", json);
    cmd.AddValue("pcap", "Write a pcap file per host (p4-multicast-<node>-0.pcap)", pcap);
    cmd.Parse(argc, argv);

    // A switch with the program and its flow table; host i+1 on port i
    P4Helper p4;
    p4.SetDeviceAttribute("JsonPath", StringValue(json));
    p4.SetDeviceAttribute("FlowTablePath", StringValue(dir + "/flowtable.txt"));
    Ptr<Node> switchNode = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = DynamicCast<P4SwitchNetDevice>(p4.Install(switchNode).Get(0));
    NodeContainer hosts(N_HOSTS);
    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    eth.SetChannelAttribute("Delay", StringValue("10us"));
    NetDeviceContainer devices = eth.Install(sw, hosts);

    // The tutorial's addresses; no ARP entries: the hosts ask
    for (uint32_t i = 0; i < N_HOSTS; i++)
    {
        std::string h = std::to_string(i + 1);
        devices.Get(i)->SetAddress(Mac48Address(("08:00:00:00:0" + h + ":" + h + h).c_str()));
    }
    InternetStackHelper internet;
    internet.Install(hosts);
    Ipv4AddressHelper ipv4("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ip = ipv4.Assign(devices);

    // Every host sends echo requests to every other host
    UdpEchoServerHelper server(9);
    server.Install(hosts);
    std::vector<std::vector<uint32_t>> replies(N_HOSTS, std::vector<uint32_t>(N_HOSTS, 0));
    for (uint32_t i = 0; i < N_HOSTS; i++)
    {
        for (uint32_t j = 0; j < N_HOSTS; j++)
        {
            if (i != j)
            {
                UdpEchoClientHelper client(ip.GetAddress(j), 9);
                client.SetAttribute("MaxPackets", UintegerValue(N_REQUESTS));
                client.SetAttribute("Interval", TimeValue(MilliSeconds(100)));
                ApplicationContainer app = client.Install(hosts.Get(i));
                app.Start(Seconds(1));
                app.Get(0)->TraceConnectWithoutContext(
                    "Rx",
                    MakeBoundCallback(&CountReply, &replies[i][j]));
            }
        }
    }

    // h1's broadcast frame, and who receives it
    std::vector<uint32_t> probes(N_HOSTS, 0);
    for (uint32_t i = 0; i < N_HOSTS; i++)
    {
        hosts.Get(i)->RegisterProtocolHandler(MakeBoundCallback(&CountProbe, &probes[i]),
                                              PROBE_TYPE,
                                              devices.Get(i));
    }
    Simulator::Schedule(Seconds(2), &SendProbe, devices.Get(0));
    if (pcap)
    {
        eth.EnablePcap("p4-multicast", devices, true);
    }

    Simulator::Stop(Seconds(3));
    Simulator::Run();
    Simulator::Destroy();

    uint32_t reached = 0;
    std::cout << "Echo replies (of " << N_REQUESTS << ") and h1's broadcast frame:\n";
    for (uint32_t i = 0; i < N_HOSTS; i++)
    {
        std::cout << "  h" << i + 1 << ":";
        for (uint32_t j = 0; j < N_HOSTS; j++)
        {
            if (i != j)
            {
                std::cout << "  from h" << j + 1 << " " << replies[i][j];
                reached += (replies[i][j] == N_REQUESTS);
            }
        }
        std::cout << "  | broadcast frames received: " << probes[i] << "\n";
    }
    uint32_t pairs = N_HOSTS * (N_HOSTS - 1);
    int failed = p4sim_example::Check(reached == pairs,
                                      std::to_string(reached) + " of " + std::to_string(pairs) +
                                          " pairs of hosts reach each other, after ARP through "
                                          "the multicast group");
    bool copies = probes[0] == 0 && probes[1] == 1 && probes[2] == 1 && probes[3] == 1;
    failed |= p4sim_example::Check(copies,
                                   "h1's broadcast frame reached h2, h3 and h4 once each, "
                                   "and not h1, the port it came from");
    return failed;
}
