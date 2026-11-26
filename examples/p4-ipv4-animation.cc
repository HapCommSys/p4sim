/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * IPv4 forwarding between two hosts with a trace for NetAnim (p4-ipv4-animation.xml):
 * host 0 sends five UDP echo requests to host 1, over a P4 switch with CSMA links.
 */

#include "example-check.h"

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"

using namespace ns3;

namespace
{

uint32_t g_replies = 0; ///< echo replies received

void
EchoReply(Ptr<const Packet>)
{
    g_replies++;
}

} // namespace

int
main(int argc, char* argv[])
{
    std::string animFile = "p4-ipv4-animation.xml";
    CommandLine cmd(__FILE__);
    cmd.AddValue("animFile", "The trace file for NetAnim", animFile);
    cmd.Parse(argc, argv);

    // Two hosts, linked to ports 0 and 1 of the switch
    NodeContainer hosts(2);
    Ptr<Node> switchNode = CreateObject<Node>();
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("1Gbps"));
    csma.SetChannelAttribute("Delay", StringValue("10us"));
    NetDeviceContainer hostDevs;
    NetDeviceContainer ports;
    for (uint32_t i = 0; i < hosts.GetN(); i++)
    {
        // Host first: the hosts get the MAC addresses 00:..:01 and 00:..:03 of the flow table
        NetDeviceContainer link = csma.Install(NodeContainer(hosts.Get(i), switchNode));
        hostDevs.Add(link.Get(0));
        ports.Add(link.Get(1));
    }
    InternetStackHelper internet;
    internet.Install(hosts);
    Ipv4AddressHelper ipv4("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer addresses = ipv4.Assign(hostDevs);

    std::string p4Dir = GetP4ExamplePath() + "/simple_v1model";
    P4Helper p4;
    p4.SetDeviceAttribute("JsonPath", StringValue(p4Dir + "/simple_v1model.json"));
    p4.SetDeviceAttribute("FlowTablePath", StringValue(p4Dir + "/flowtable_bridge.txt"));
    p4.Install(switchNode, ports);

    UdpEchoServerHelper server(9);
    server.Install(hosts.Get(1));
    UdpEchoClientHelper client(addresses.GetAddress(1), 9);
    client.SetAttribute("MaxPackets", UintegerValue(5));
    ApplicationContainer app = client.Install(hosts.Get(0));
    app.Start(Seconds(1));
    app.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&EchoReply));

    AnimationInterface anim(animFile);
    anim.SetConstantPosition(hosts.Get(0), 10, 10);
    anim.SetConstantPosition(switchNode, 30, 20);
    anim.SetConstantPosition(hosts.Get(1), 50, 10);
    anim.UpdateNodeDescription(switchNode, "P4 switch");

    Simulator::Stop(Seconds(10));
    Simulator::Run();
    Simulator::Destroy();
    return p4sim_example::Check(g_replies == 5, std::to_string(g_replies) + " of 5 echo replies");
}
