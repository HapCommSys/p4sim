/*
 * Copyright (c) 2026 TU Dresden
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

NS_LOG_COMPONENT_DEFINE("RoutingTest");

int
main(int argc, char* argv[])
{
    LogComponentEnable("RoutingTest", LOG_LEVEL_INFO);

    // P4 parameters
    // Use P4SIM_DIR environment variable for portable paths
    std::string p4SrcDir = GetP4ExamplePath() + "/routing_test";
    std::string p4JsonPath = p4SrcDir + "/routing_test.json";
    std::string flowTableDirPath = p4SrcDir + "/";

    NodeContainer routers;
    routers.Create(1); // R0, R1, R2

    NodeContainer hosts;
    hosts.Create(3); // H0, H1, H2

    // 2. Create CSMA NetDevices for each link
    //    (1) R0 <-> H0
    //    (2) R0 <-> H1
    //    (3) R0 <-> H2

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("5Mbps"));
    csma.SetChannelAttribute("Delay", StringValue("2ms"));

    // R0 <-> H0
    NodeContainer R0H0;
    R0H0.Add(routers.Get(0));
    R0H0.Add(hosts.Get(0));
    NetDeviceContainer ndcR0H0 = csma.Install(R0H0);

    // R0 <-> H1
    NodeContainer R0H1;
    R0H1.Add(routers.Get(0));
    R0H1.Add(hosts.Get(1));
    NetDeviceContainer ndcR0H1 = csma.Install(R0H1);

    // R0 <-> H2
    NodeContainer R0H2;
    R0H2.Add(routers.Get(0));
    R0H2.Add(hosts.Get(2));
    NetDeviceContainer ndcR0H2 = csma.Install(R0H2);

    // Collect NetDevices attached to R0
    NetDeviceContainer routersnetdevices;
    routersnetdevices.Add(ndcR0H0.Get(0));
    routersnetdevices.Add(ndcR0H1.Get(0));
    routersnetdevices.Add(ndcR0H2.Get(0));

    // 3. Install the Internet stack (TCP/IP) on routers and hosts
    InternetStackHelper stack;
    stack.Install(routers);
    stack.Install(hosts);

    // 4. Assign IP addresses (one subnet per link)
    Ipv4AddressHelper address;

    // R0 <-> H0
    address.SetBase("10.0.1.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR0H0 = address.Assign(ndcR0H0);

    // R0 <-> H1
    address.SetBase("10.0.2.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR0H1 = address.Assign(ndcR0H1);

    // R0 <-> H2
    address.SetBase("10.0.3.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR0H2 = address.Assign(ndcR0H2);

    // 5. Populate global static routing tables
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // P4 Switch Configuration
    // P4Helper p4SwitchHelper;
    // p4SwitchHelper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    // p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(0));
    // p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));
    // std::string flowTablePath = flowTableDirPath + "flowtable_0.txt";
    // p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
    // NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", \n " << flowTablePath);
    // p4SwitchHelper.Install(routers.Get(0), routersnetdevices);

    // Print out the IP and MAC of each interface on each host node
    NS_LOG_INFO("=== Print Host & IP/MAC Interface Info ===");
    for (uint32_t i = 0; i < hosts.GetN(); i++)
    {
        Ptr<Node> node = hosts.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();

        NS_LOG_INFO("Host node " << i << " -> real NodeId: " << node->GetId() << ", "
                                 << ipv4->GetNInterfaces() << " Ipv4 Interfaces");

        // Iterate over each interface
        for (uint32_t ifIndex = 0; ifIndex < ipv4->GetNInterfaces(); ifIndex++)
        {
            // Each interface may have multiple IP addresses
            for (uint32_t adIndex = 0; adIndex < ipv4->GetNAddresses(ifIndex); adIndex++)
            {
                Ipv4InterfaceAddress iaddr = ipv4->GetAddress(ifIndex, adIndex);
                Ipv4Address ipAddr = iaddr.GetLocal();

                // Skip loopback interface
                if (ipAddr == Ipv4Address::GetLoopback())
                    continue;

                // Retrieve the NetDevice that corresponds to 'ifIndex'
                Ptr<NetDevice> dev = ipv4->GetNetDevice(ifIndex);
                // Convert the generic Address to a Mac48Address (if it's that kind)
                Address genericMac = dev->GetAddress();
                Mac48Address mac = Mac48Address::ConvertFrom(genericMac);

                NS_LOG_INFO("  Interface " << ifIndex << " IP: " << ipAddr
                                           << " Mask: " << iaddr.GetMask() << " MAC: " << mac);
            }
        }
    }
    // Print out the IP and MAC of each interface on each host node
    NS_LOG_INFO("=== Print Router & IP/MAC Interface Info ===");
    for (uint32_t i = 0; i < routers.GetN(); i++)
    {
        Ptr<Node> node = routers.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();

        NS_LOG_INFO("Router node " << i << " -> real NodeId: " << node->GetId() << ", "
                                   << ipv4->GetNInterfaces() << " Ipv4 Interfaces");

        // Iterate over each interface
        for (uint32_t ifIndex = 0; ifIndex < ipv4->GetNInterfaces(); ifIndex++)
        {
            // Each interface may have multiple IP addresses
            for (uint32_t adIndex = 0; adIndex < ipv4->GetNAddresses(ifIndex); adIndex++)
            {
                Ipv4InterfaceAddress iaddr = ipv4->GetAddress(ifIndex, adIndex);
                Ipv4Address ipAddr = iaddr.GetLocal();

                // Skip loopback interface
                if (ipAddr == Ipv4Address::GetLoopback())
                    continue;

                // Retrieve the NetDevice that corresponds to 'ifIndex'
                Ptr<NetDevice> dev = ipv4->GetNetDevice(ifIndex);
                // Convert the generic Address to a Mac48Address (if it's that kind)
                Address genericMac = dev->GetAddress();
                Mac48Address mac = Mac48Address::ConvertFrom(genericMac);

                NS_LOG_INFO("  Interface " << ifIndex << " IP: " << ipAddr
                                           << " Mask: " << iaddr.GetMask() << " MAC: " << mac);
            }
        }
    }

    uint16_t echoPort = 9;
    UdpEchoServerHelper echoServer(echoPort);
    ApplicationContainer serverApps = echoServer.Install(hosts.Get(2)); // H2
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(10.0));

    // Install a UDP Echo Client on H0, targeting H2's address
    UdpEchoClientHelper echoClient(iicR0H2.GetAddress(1), echoPort);
    echoClient.SetAttribute("MaxPackets", UintegerValue(5));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    echoClient.SetAttribute("PacketSize", UintegerValue(1024));

    ApplicationContainer clientApps = echoClient.Install(hosts.Get(0)); // H0
    clientApps.Start(Seconds(2.0));
    clientApps.Stop(Seconds(9.0));

    csma.EnablePcapAll("routing-test");

    NS_LOG_INFO("Running simulation...");
    Simulator::Stop(Seconds(11.0));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
