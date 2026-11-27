/*
 * Copyright (c) 2026 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * \file
 * The network of the "ecn" and "mri" exercises of p4lang/tutorials, for p4-ecn
 * and p4-mri:
 *
 *    h11 ── 0 ┐                         ┌ 0 ── h22
 *              s1 2 ─────────────── 2 s2
 *     h1 ── 1 ┘ 3      512 kbps      3 └ 1 ── h2
 *                \                  /
 *                 1 ─── s3 ─────── 2
 *                       0
 *                       │
 *                       h3
 *
 * The numbers are the ports: P4sim numbers them from 0, the tutorial from 1, so
 * port n here is port n+1 there. The link from s1 to s2 is the bottleneck of the
 * tutorial, 512 kbps; the other links have 100 Mbps. Each host has the address
 * and the MAC address of the tutorial, 10.0.<switch>.<host> and
 * 08:00:00:00:<switch>:<host>. As there, a host sends every IPv4 packet to the
 * MAC address of its switch, 08:00:00:00:<switch>:00, and each switch rewrites
 * the destination address on the way (ipv4_forward), so the P4 program does not
 * have to handle ARP.
 */

#ifndef P4SIM_TUTORIAL_TRIANGLE_H
#define P4SIM_TUTORIAL_TRIANGLE_H

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/switched-ethernet-helper.h"

#include <string>
#include <vector>

namespace p4sim_example
{

/// The hosts of the triangle, in the order h1, h11, h2, h22, h3
enum TriangleHost
{
    H1,
    H11,
    H2,
    H22,
    H3
};

/// The triangle: hosts, their devices and addresses (index: TriangleHost), switches
struct Triangle
{
    ns3::NodeContainer hosts;
    ns3::NetDeviceContainer devices;
    std::vector<ns3::Ipv4Address> addresses;
    std::vector<ns3::Ptr<ns3::P4SwitchNetDevice>> switches; ///< s1, s2, s3
};

/// Build the triangle. Every switch runs the P4 program \p json with the flow table
/// \p dir/flowtable_<i>.txt, where i is 0 for s1, 1 for s2 and 2 for s3.
inline Triangle
BuildTriangle(const std::string& json, const std::string& dir)
{
    using namespace ns3;
    Triangle t;

    P4Helper p4;
    p4.SetDeviceAttribute("JsonPath", StringValue(json));
    for (uint32_t s = 0; s < 3; s++)
    {
        p4.SetDeviceAttribute("FlowTablePath",
                              StringValue(dir + "/flowtable_" + std::to_string(s) + ".txt"));
        Ptr<Node> node = CreateObject<Node>();
        t.switches.push_back(DynamicCast<P4SwitchNetDevice>(p4.Install(node).Get(0)));
    }

    struct Host
    {
        uint32_t sw; ///< index of its switch
        const char* address;
        const char* mac;
    };

    const std::vector<Host> hosts = {{0, "10.0.1.1", "08:00:00:00:01:01"},
                                     {0, "10.0.1.11", "08:00:00:00:01:11"},
                                     {1, "10.0.2.2", "08:00:00:00:02:02"},
                                     {1, "10.0.2.22", "08:00:00:00:02:22"},
                                     {2, "10.0.3.3", "08:00:00:00:03:03"}};

    // The ports of a switch are numbered in the order in which they are
    // connected: the hosts first (h11 before h1, h22 before h2), then the links
    t.hosts.Create(hosts.size());
    std::vector<Ptr<NetDevice>> devices(hosts.size());
    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    eth.SetChannelAttribute("Delay", StringValue("10us"));
    for (uint32_t h : {H11, H1, H22, H2, H3})
    {
        devices[h] = eth.ConnectHost(t.switches[hosts[h].sw], t.hosts.Get(h)).Get(0);
    }
    auto link = [](Ptr<P4SwitchNetDevice> a, Ptr<P4SwitchNetDevice> b, const std::string& rate) {
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        channel->SetAttribute("DataRate", StringValue(rate));
        channel->SetAttribute("Delay", StringValue("10us"));
        a->Attach(channel);
        b->Attach(channel);
    };
    link(t.switches[0], t.switches[1], "512kbps"); // s1 port 2, s2 port 2
    link(t.switches[0], t.switches[2], "100Mbps"); // s1 port 3, s3 port 1
    link(t.switches[2], t.switches[1], "100Mbps"); // s3 port 2, s2 port 3

    InternetStackHelper internet;
    internet.Install(t.hosts);
    std::vector<uint32_t> interfaces(hosts.size());
    for (uint32_t h = 0; h < hosts.size(); h++)
    {
        devices[h]->SetAddress(Mac48Address(hosts[h].mac));
        t.devices.Add(devices[h]);
        t.addresses.emplace_back(hosts[h].address);
        Ptr<Ipv4> ipv4 = t.hosts.Get(h)->GetObject<Ipv4>();
        interfaces[h] = ipv4->AddInterface(devices[h]);
        ipv4->AddAddress(interfaces[h],
                         Ipv4InterfaceAddress(t.addresses[h], Ipv4Mask("255.0.0.0")));
        ipv4->SetUp(interfaces[h]);
    }
    // Every other host is reached through the MAC address of the own switch
    for (uint32_t h = 0; h < hosts.size(); h++)
    {
        Mac48Address gateway(("08:00:00:00:0" + std::to_string(hosts[h].sw + 1) + ":00").c_str());
        Ptr<ArpCache> arp =
            t.hosts.Get(h)->GetObject<Ipv4L3Protocol>()->GetInterface(interfaces[h])->GetArpCache();
        for (uint32_t o = 0; o < hosts.size(); o++)
        {
            if (o != h)
            {
                ArpCache::Entry* entry = arp->Add(t.addresses[o]);
                entry->SetMacAddress(gateway);
                entry->MarkPermanent();
            }
        }
    }
    return t;
}

/// The traffic of both exercises from \p start to \p stop: 1 Mbps of UDP from h11 to
/// h22, as iperf -u sends it (1470-byte datagrams). It fills the queue of s1 to s2.
inline void
StartCongestion(Triangle& t, ns3::Time start, ns3::Time stop)
{
    using namespace ns3;
    InetSocketAddress h22(t.addresses[H22], 5001);
    PacketSinkHelper sink("ns3::UdpSocketFactory", h22);
    sink.Install(t.hosts.Get(H22));
    OnOffHelper iperf("ns3::UdpSocketFactory", h22);
    iperf.SetConstantRate(DataRate("1Mbps"), 1470);
    ApplicationContainer app = iperf.Install(t.hosts.Get(H11));
    app.Start(start);
    app.Stop(stop);
}

} // namespace p4sim_example

#endif // P4SIM_TUTORIAL_TRIANGLE_H
