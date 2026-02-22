/*
 * Copyright (c) 2025 TU Dresden
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * @file p4-l3-router.cc
 * @brief NS-3 simulation of multi-hop IPv4 routing using P4 software routers.
 *
 * Overview
 * --------
 * This example models a three-router linear chain where each router is
 * implemented as a P4 switch running the "l3_router" P4 program.  The P4
 * program performs exact-match IPv4 longest-prefix routing and rewrites the
 * destination MAC address on each hop — exactly what a hardware L3 router does.
 *
 * Unlike the basic forwarding examples (which use a single switch and a flat
 * subnet), each router-to-router and router-to-host link is assigned its own
 * /24 subnet so that the P4 flow tables can distinguish per-hop next-hops.
 *
 * Topology
 * --------
 *
 *   H0 ──── R0 ──── R1 ──── R2 ──── H2
 *                    │
 *                   H1
 *
 *   Subnet assignments (CSMA links):
 *     R0 <-> R1 :  10.0.0.0/24   (R0=.1, R1=.2)
 *     R1 <-> R2 :  10.0.1.0/24   (R1=.1, R2=.2)
 *     R0 <-> H0 :  10.0.2.0/24   (R0=.1, H0=.2)
 *     R1 <-> H1 :  10.0.3.0/24   (R1=.1, H1=.2)
 *     R2 <-> H2 :  10.0.4.0/24   (R2=.1, H2=.2)
 *
 * Expected topology print-out (reference):
 * -----------------------------------------
 *   Host 0 -> NodeId 3 :  10.0.2.2 / 255.255.255.0  MAC 00:00:00:00:00:06
 *   Host 1 -> NodeId 4 :  10.0.3.2 / 255.255.255.0  MAC 00:00:00:00:00:08
 *   Host 2 -> NodeId 5 :  10.0.4.2 / 255.255.255.0  MAC 00:00:00:00:00:0a
 *   Router 0 -> NodeId 0 :  10.0.0.1 / …, 10.0.2.1 / …
 *   Router 1 -> NodeId 1 :  10.0.0.2 / …, 10.0.1.1 / …, 10.0.3.1 / …
 *   Router 2 -> NodeId 2 :  10.0.1.2 / …, 10.0.4.1 / …
 *
 * Traffic model
 * -------------
 * A UDP echo client on H0 sends 5 packets to H2 (echoed back by a UDP echo
 * server on H2).  The full round-trip traverses R0 -> R1 -> R2 and back.
 *
 * Usage
 * -----
 * @code
 *   ./ns3 run "p4-l3-router        \
 *       --linkRate=5Mbps           \
 *       --linkDelay=2ms            \
 *       --maxPackets=5             \
 *       --echoInterval=1           \
 *       --pktSize=1024             \
 *       --simDuration=11           \
 *       --pcap=true"
 * @endcode
 */

#include "ns3/applications-module.h"
#include "ns3/arp-cache.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/net-device.h"
#include "ns3/network-module.h"
#include "ns3/node.h"
#include "ns3/p4-helper.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4L3Router");

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4L3Router", LOG_LEVEL_INFO);

    // Zero out the ARP dead-timeout so stale ARP entries never block traffic.
    Config::SetDefault("ns3::ArpCache::DeadTimeout", TimeValue(Seconds(0)));

    // -----------------------------------------------------------------------
    // Simulation parameters – all adjustable via the command line
    // -----------------------------------------------------------------------
    std::string linkRate = "5Mbps"; ///< CSMA channel data rate.
    std::string linkDelay = "2ms";  ///< CSMA channel one-way propagation delay.
    uint32_t maxPackets = 5;        ///< Number of echo packets to send.
    double echoInterval = 1.0;      ///< Inter-packet interval for the echo client (s).
    uint32_t pktSize = 1024;        ///< Echo packet payload size (bytes).
    double simDuration = 11.0;      ///< Total simulation time (s).
    bool enablePcap = true;         ///< Enable PCAP trace output.

    // Paths resolved via P4SIM_DIR environment variable (portable).
    std::string p4SrcDir = GetP4ExamplePath() + "/l3_router";
    std::string p4JsonPath = p4SrcDir + "/l3_router.json";
    std::string flowTableDirPath = p4SrcDir + "/";

    // -----------------------------------------------------------------------
    // Command-line interface
    // -----------------------------------------------------------------------
    CommandLine cmd;
    cmd.AddValue("linkRate", "CSMA link data rate (default 5Mbps)", linkRate);
    cmd.AddValue("linkDelay", "CSMA link one-way delay (default 2ms)", linkDelay);
    cmd.AddValue("maxPackets", "Number of UDP echo packets to send (default 5)", maxPackets);
    cmd.AddValue("echoInterval",
                 "Interval between echo packets in seconds (default 1)",
                 echoInterval);
    cmd.AddValue("pktSize", "Echo packet payload size in bytes (default 1024)", pktSize);
    cmd.AddValue("simDuration", "Total simulation duration in seconds (default 11)", simDuration);
    cmd.AddValue("pcap", "Enable PCAP packet capture (true/false)", enablePcap);
    cmd.Parse(argc, argv);

    // -----------------------------------------------------------------------
    // Create nodes: 3 P4 routers (R0, R1, R2) and 3 hosts (H0, H1, H2)
    // -----------------------------------------------------------------------
    NodeContainer routers;
    routers.Create(3); // R0, R1, R2

    NodeContainer hosts;
    hosts.Create(3); // H0, H1, H2

    // Each router accumulates its attached NetDevices for later P4 installation.
    std::vector<NetDeviceContainer> routerPorts(3);

    // -----------------------------------------------------------------------
    // Install CSMA links (one subnet per link)
    // -----------------------------------------------------------------------
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(linkRate));
    csma.SetChannelAttribute("Delay", StringValue(linkDelay));

    // R0 <-> R1  (backbone link)
    NetDeviceContainer ndcR0R1 = csma.Install(NodeContainer(routers.Get(0), routers.Get(1)));

    // R1 <-> R2  (backbone link)
    NetDeviceContainer ndcR1R2 = csma.Install(NodeContainer(routers.Get(1), routers.Get(2)));

    // R0 <-> H0  (access link)
    NetDeviceContainer ndcR0H0 = csma.Install(NodeContainer(routers.Get(0), hosts.Get(0)));

    // R1 <-> H1  (access link)
    NetDeviceContainer ndcR1H1 = csma.Install(NodeContainer(routers.Get(1), hosts.Get(1)));

    // R2 <-> H2  (access link)
    NetDeviceContainer ndcR2H2 = csma.Install(NodeContainer(routers.Get(2), hosts.Get(2)));

    // Populate per-router port containers in the order the P4 flow tables expect.
    routerPorts[0].Add(ndcR0R1.Get(0)); // R0 port 0: towards R1
    routerPorts[0].Add(ndcR0H0.Get(0)); // R0 port 1: towards H0

    routerPorts[1].Add(ndcR0R1.Get(1)); // R1 port 0: towards R0
    routerPorts[1].Add(ndcR1R2.Get(0)); // R1 port 1: towards R2
    routerPorts[1].Add(ndcR1H1.Get(0)); // R1 port 2: towards H1

    routerPorts[2].Add(ndcR1R2.Get(1)); // R2 port 0: towards R1
    routerPorts[2].Add(ndcR2H2.Get(0)); // R2 port 1: towards H2

    // -----------------------------------------------------------------------
    // Internet stack & IP address assignment
    // -----------------------------------------------------------------------
    InternetStackHelper stack;
    stack.Install(routers);
    stack.Install(hosts);

    Ipv4AddressHelper address;

    // R0 <-> R1
    address.SetBase("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR0R1 = address.Assign(ndcR0R1);

    // R1 <-> R2
    address.SetBase("10.0.1.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR1R2 = address.Assign(ndcR1R2);

    // R0 <-> H0
    address.SetBase("10.0.2.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR0H0 = address.Assign(ndcR0H0);

    // R1 <-> H1
    address.SetBase("10.0.3.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR1H1 = address.Assign(ndcR1H1);

    // R2 <-> H2
    address.SetBase("10.0.4.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR2H2 = address.Assign(ndcR2H2);

    // -----------------------------------------------------------------------
    // Install P4 routers
    // -----------------------------------------------------------------------
    P4Helper p4Helper;
    p4Helper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4Helper.SetDeviceAttribute("ChannelType", UintegerValue(0));
    p4Helper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0)); // V1Model

    for (uint32_t i = 0; i < 3; ++i)
    {
        std::string ftPath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        p4Helper.SetDeviceAttribute("FlowTablePath", StringValue(ftPath));
        NS_LOG_INFO("*** Installing P4 router " << i << ": table=" << ftPath);
        p4Helper.Install(routers.Get(i), routerPorts[i]);
    }

    // -----------------------------------------------------------------------
    // Print IP / MAC topology for verification
    // -----------------------------------------------------------------------
    NS_LOG_INFO("=== Host IP / MAC interface summary ===");
    for (uint32_t i = 0; i < hosts.GetN(); ++i)
    {
        Ptr<Node> node = hosts.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        NS_LOG_INFO("Host " << i << " (NodeId=" << node->GetId() << ")  " << ipv4->GetNInterfaces()
                            << " interfaces");
        for (uint32_t ifIdx = 0; ifIdx < ipv4->GetNInterfaces(); ++ifIdx)
        {
            for (uint32_t adIdx = 0; adIdx < ipv4->GetNAddresses(ifIdx); ++adIdx)
            {
                Ipv4InterfaceAddress iaddr = ipv4->GetAddress(ifIdx, adIdx);
                if (iaddr.GetLocal() == Ipv4Address::GetLoopback())
                    continue;
                Mac48Address mac =
                    Mac48Address::ConvertFrom(ipv4->GetNetDevice(ifIdx)->GetAddress());
                NS_LOG_INFO("  If " << ifIdx << ": " << iaddr.GetLocal() << " / " << iaddr.GetMask()
                                    << "  MAC " << mac);
            }
        }
    }

    NS_LOG_INFO("=== Router IP / MAC interface summary ===");
    for (uint32_t i = 0; i < routers.GetN(); ++i)
    {
        Ptr<Node> node = routers.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        NS_LOG_INFO("Router " << i << " (NodeId=" << node->GetId() << ")  "
                              << ipv4->GetNInterfaces() << " interfaces");
        for (uint32_t ifIdx = 0; ifIdx < ipv4->GetNInterfaces(); ++ifIdx)
        {
            for (uint32_t adIdx = 0; adIdx < ipv4->GetNAddresses(ifIdx); ++adIdx)
            {
                Ipv4InterfaceAddress iaddr = ipv4->GetAddress(ifIdx, adIdx);
                if (iaddr.GetLocal() == Ipv4Address::GetLoopback())
                    continue;
                Mac48Address mac =
                    Mac48Address::ConvertFrom(ipv4->GetNetDevice(ifIdx)->GetAddress());
                NS_LOG_INFO("  If " << ifIdx << ": " << iaddr.GetLocal() << " / " << iaddr.GetMask()
                                    << "  MAC " << mac);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Application layer: UDP echo H0 -> H2 (round trip via R0 -> R1 -> R2)
    // -----------------------------------------------------------------------
    const uint16_t echoPort = 9;

    UdpEchoServerHelper echoServer(echoPort);
    ApplicationContainer serverApps = echoServer.Install(hosts.Get(2)); // H2
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(simDuration - 1.0));

    UdpEchoClientHelper echoClient(iicR2H2.GetAddress(1), echoPort);
    echoClient.SetAttribute("MaxPackets", UintegerValue(maxPackets));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(echoInterval)));
    echoClient.SetAttribute("PacketSize", UintegerValue(pktSize));

    ApplicationContainer clientApps = echoClient.Install(hosts.Get(0)); // H0
    clientApps.Start(Seconds(2.0));
    clientApps.Stop(Seconds(simDuration - 2.0));

    NS_LOG_INFO("UDP echo: H0 -> H2 (" << iicR2H2.GetAddress(1) << ":" << echoPort << ")  "
                                       << maxPackets << " packets");

    // -----------------------------------------------------------------------
    // PCAP tracing
    // -----------------------------------------------------------------------
    if (enablePcap)
    {
        csma.EnablePcapAll("p4-l3-router");
        NS_LOG_INFO("PCAP tracing enabled: p4-l3-router-*.pcap");
    }

    // -----------------------------------------------------------------------
    // Run simulation
    // -----------------------------------------------------------------------
    NS_LOG_INFO("Starting simulation (stop at t=" << simDuration << " s)...");
    Simulator::Stop(Seconds(simDuration));
    Simulator::Run();
    Simulator::Destroy();
    NS_LOG_INFO("Simulation complete.");

    return 0;
}