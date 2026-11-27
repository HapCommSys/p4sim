/*
 * Copyright (c) 2026 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * Three P4 routers in a line, each with a host in its own subnet.
 *
 *   host 0 ── router 0 ── router 1 ── router 2 ── host 2
 *   10.0.2.2                 │                    10.0.4.2
 *                         host 1
 *                         10.0.3.2
 *
 * A router looks up the next hop of a packet (ipv4_lpm), decrements the TTL, and
 * writes the MAC addresses of the next hop (switching_table) and of its own port
 * (mac_rewriting_table). Each host knows its gateway, the router port at 10.0.x.1,
 * and its MAC address; the routers do not answer ARP.
 *
 * Every host sends three UDP echo requests to every other one. The program checks
 * that all replies come back, and that each router on the way took 1 off the TTL.
 */

#include "example-check.h"

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"

using namespace ns3;

namespace
{

uint32_t g_replies = 0;                       ///< echo replies received by the clients
uint32_t g_packets = 0;                       ///< IPv4 packets delivered to the hosts
uint32_t g_wrongTtl = 0;                      ///< those with an unexpected TTL
std::map<Ipv4Address, uint32_t> g_hostOfAddr; ///< the host with an address

void
EchoReply(Ptr<const Packet>)
{
    g_replies++;
}

/// A packet reached \p host: each router on the way must have taken 1 off its TTL
void
Delivered(uint32_t host, const Ipv4Header& header, Ptr<const Packet>, uint32_t)
{
    uint32_t from = g_hostOfAddr.at(header.GetSource());
    uint32_t routers = (from > host ? from - host : host - from) + 1;
    g_packets++;
    g_wrongTtl += (header.GetTtl() != 64 - routers);
}

} // namespace

int
main(int argc, char* argv[])
{
    bool pcap = true;
    CommandLine cmd(__FILE__);
    cmd.AddValue("pcap", "Write pcap files", pcap);
    cmd.Parse(argc, argv);

    NodeContainer routers(3);
    NodeContainer hosts(3);
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("5Mbps"));
    csma.SetChannelAttribute("Delay", StringValue("2ms"));

    // The links; the order of the devices gives their MAC addresses, 00:..:01 to 00:..:0a,
    // which the flow tables use
    std::vector<NetDeviceContainer> ports(3); // of each router, in the order of the port numbers
    auto connect = [&](Ptr<Node> a, Ptr<Node> b) { return csma.Install(NodeContainer(a, b)); };
    NetDeviceContainer r0r1 = connect(routers.Get(0), routers.Get(1));
    NetDeviceContainer r1r2 = connect(routers.Get(1), routers.Get(2));
    NetDeviceContainer r0h0 = connect(routers.Get(0), hosts.Get(0));
    NetDeviceContainer r1h1 = connect(routers.Get(1), hosts.Get(1));
    NetDeviceContainer r2h2 = connect(routers.Get(2), hosts.Get(2));
    ports[0] = NetDeviceContainer(r0r1.Get(0), r0h0.Get(0));
    ports[1] = NetDeviceContainer(r0r1.Get(1), r1r2.Get(0));
    ports[1].Add(r1h1.Get(0));
    ports[2] = NetDeviceContainer(r1r2.Get(1), r2h2.Get(0));

    // The routers
    std::string p4Dir = GetP4ExamplePath() + "/l3_router";
    P4Helper p4;
    p4.SetDeviceAttribute("JsonPath", StringValue(p4Dir + "/l3_router.json"));
    for (uint32_t i = 0; i < 3; i++)
    {
        p4.SetDeviceAttribute("FlowTablePath",
                              StringValue(p4Dir + "/flowtable_" + std::to_string(i) + ".txt"));
        p4.Install(routers.Get(i), ports[i]);
    }

    // The hosts: address 10.0.<2+i>.2, default route to the gateway 10.0.<2+i>.1
    InternetStackHelper internet;
    internet.Install(hosts);
    const NetDeviceContainer hostLinks[] = {r0h0, r1h1, r2h2};
    std::vector<Ipv4Address> addresses;
    for (uint32_t i = 0; i < 3; i++)
    {
        std::string subnet = "10.0." + std::to_string(2 + i) + ".";
        Ipv4Address gateway((subnet + "1").c_str());
        Ipv4AddressHelper ipv4((subnet + "0").c_str(), "255.255.255.0", "0.0.0.2");
        Ipv4InterfaceContainer interface = ipv4.Assign(hostLinks[i].Get(1));
        addresses.push_back(interface.GetAddress(0));
        g_hostOfAddr[addresses[i]] = i;

        Ptr<Ipv4> ip = hosts.Get(i)->GetObject<Ipv4>();
        Ipv4StaticRoutingHelper().GetStaticRouting(ip)->SetDefaultRoute(gateway, 1);
        ArpCache::Entry* entry =
            hosts.Get(i)->GetObject<Ipv4L3Protocol>()->GetInterface(1)->GetArpCache()->Add(gateway);
        entry->SetMacAddress(hostLinks[i].Get(0)->GetAddress());
        entry->MarkPermanent();
        ip->TraceConnectWithoutContext("LocalDeliver", MakeBoundCallback(&Delivered, i));
    }

    // The traffic
    UdpEchoServerHelper server(9);
    server.Install(hosts);
    for (uint32_t i = 0; i < 3; i++)
    {
        for (uint32_t j = 0; j < 3; j++)
        {
            if (i != j)
            {
                UdpEchoClientHelper client(addresses[j], 9);
                client.SetAttribute("MaxPackets", UintegerValue(3));
                client.SetAttribute("Interval", TimeValue(Seconds(1)));
                client.SetAttribute("PacketSize", UintegerValue(1024));
                ApplicationContainer app = client.Install(hosts.Get(i));
                app.Start(Seconds(1));
                app.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&EchoReply));
            }
        }
    }
    if (pcap)
    {
        csma.EnablePcapAll("p4-l3-router");
    }

    Simulator::Stop(Seconds(6));
    Simulator::Run();
    Simulator::Destroy();

    int failed =
        p4sim_example::Check(g_replies == 18, std::to_string(g_replies) + " of 18 echo replies");
    failed |= p4sim_example::Check(g_packets == 36 && g_wrongTtl == 0,
                                   "the TTL of " + std::to_string(g_packets - g_wrongTtl) +
                                       " of 36 packets is 64 minus the routers on the way");
    return failed;
}
