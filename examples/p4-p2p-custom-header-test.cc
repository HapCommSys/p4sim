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
 *
 */

/**
 * \brief This example demonstrates how to add a custom header to the packets
 * and parse the custom header at the receiver side.

For the printing, you may need to uncommand the following lines in the custom-p2p-net-device.cc
file, marked with @PrintHD:

    // @PrintHD
    std::cout << "*** [Sender] before adding the custom header and Eth header " << std::endl;
    p->Print(std::cout);
    std::cout << " " << std::endl;

[Sender] before adding the custom header and Eth header
ns3::Ipv4Header (tos 0x0 DSCP Default ECN Not-ECT ttl 64 id 0 protocol 17 offset (bytes) 0 flags
[none] length: 1028 10.1.1.1 > 10.1.1.2) ns3::UdpHeader (length: 1008 49153 > 12000) Payload
(size=1000)

[Sender] After adding custom header
ns3::EthernetHeader ( length/type=0x12, source=00:00:00:00:00:01, destination=ff:ff:ff:ff:ff:ff)
ns3::CustomHeader (CustomHeader { }) ns3::Ipv4Header (tos 0x0 DSCP Default ECN Not-ECT ttl 64 id 0
protocol 17 offset (bytes) 0 flags [none] length: 1028 10.1.1.1 > 10.1.1.2) ns3::UdpHeader (length:
1008 49153 > 12000) Payload (size=1000)

[Receiver] Custom header detected, start parsering the custom header
ns3::EthernetHeader ( length/type=0x12, source=00:00:00:00:00:01, destination=ff:ff:ff:ff:ff:ff)
ns3::CustomHeader (CustomHeader { }) ns3::Ipv4Header (tos 0x0 DSCP Default ECN Not-ECT ttl 64 id 0
protocol 17 offset (bytes) 0 flags [none] length: 1028 10.1.1.1 > 10.1.1.2) ns3::UdpHeader (length:
1008 49153 > 12000) Payload (size=1000)

[Receiver] After reverse parsing to normal packet:
ns3::Ipv4Header (tos 0x0 DSCP Default ECN Not-ECT ttl 64 id 0 protocol 17 offset (bytes) 0 flags
[none] length: 1028 10.1.1.1 > 10.1.1.2) ns3::UdpHeader (length: 1000 49153 > 12000) Payload
(size=1000)
 */
#include "ns3/core-module.h"
#include "ns3/custom-p2p-net-device.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/network-module.h"
#include "ns3/on-off-helper.h"
#include "ns3/p4-p2p-channel.h"
#include "ns3/p4-p2p-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4PointToPointCustomHeaderTest");

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4PointToPointCustomHeaderTest", LOG_LEVEL_INFO);
    ns3::PacketMetadata::Enable(); // Enable packet metadata tracing support

    // simulation parameters
    uint16_t pktSize = 1000;
    std::string appDataRate = "2.0Mbps";

    // simulation time configuration
    double global_start_time = 1.0;
    double sink_start_time = global_start_time + 1.0;
    double client_start_time = global_start_time + 2.0;
    double client_stop_time = client_start_time + 10;
    double sink_stop_time = client_stop_time + 10;
    double global_stop_time = client_stop_time + 10;

    Ptr<Node> a = CreateObject<Node>();
    Ptr<Node> b = CreateObject<Node>();

    P4PointToPointHelper p2phelper;
    p2phelper.SetChannelAttribute("Delay", TimeValue(MilliSeconds(0.01)));

    NetDeviceContainer devices = p2phelper.Install(a, b);

    Ptr<CustomP2PNetDevice> devA = DynamicCast<CustomP2PNetDevice>(devices.Get(0));
    NS_ASSERT(devA != nullptr);
    devA->SetWithCustomHeader(true);

    Ptr<CustomP2PNetDevice> devB = DynamicCast<CustomP2PNetDevice>(devices.Get(1));
    NS_ASSERT(devB != nullptr);
    devB->SetWithCustomHeader(true);

    //// Custom defined header for P4 switch (for the p4 code)
    // Step 1: Create an instance of CustomHeader for myTunnel_t
    // [ethernet] [myTunnelHeader] [ipv4] [udp] [payload ---- 1000 bytes]
    CustomHeader myTunnelHeader;
    myTunnelHeader.SetLayer(HeaderLayer::LAYER_3);
    myTunnelHeader.SetOperator(HeaderLayerOperator::ADD_BEFORE);

    // Step 2: Define the fields for myTunnel_t
    myTunnelHeader.AddField("proto_id", 16); // 16-bit field
    myTunnelHeader.AddField("dst_id", 16);   // 16-bit field

    // Step 3: Set values for the fields
    myTunnelHeader.SetField("proto_id", 0x0800); // Example: IPv4 protocol
    myTunnelHeader.SetField("dst_id", 0x22);     // Example: Destination ID

    // Set for the sender and receiver side NetDevice
    devA->SetCustomHeader(myTunnelHeader);
    devB->SetCustomHeader(myTunnelHeader);
    //// End of custom defined header

    //   devA->PrintPacketHeaders ();
    InternetStackHelper internet;
    internet.Install(a);
    internet.Install(b);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");

    // FIXED: Assign IPs properly
    Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

    uint16_t servPort = 12000;

    Ipv4Address serverAddr1 = interfaces.GetAddress(1);
    InetSocketAddress dst1 = InetSocketAddress(serverAddr1, servPort);
    PacketSinkHelper sink1("ns3::UdpSocketFactory", dst1);
    ApplicationContainer sinkApp1 = sink1.Install(b);

    sinkApp1.Start(Seconds(sink_start_time));
    sinkApp1.Stop(Seconds(sink_stop_time));

    OnOffHelper onOff1("ns3::UdpSocketFactory", dst1);
    onOff1.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff1.SetAttribute("DataRate", StringValue(appDataRate));
    onOff1.SetAttribute("MaxBytes", UintegerValue(1000)); // Limit to 1000 Bytes, 1 packets
    onOff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer app1 = onOff1.Install(a);
    app1.Start(Seconds(client_start_time));
    app1.Stop(Seconds(client_stop_time));

    p2phelper.EnablePcapAll("p4-p2p-custom-header-test");

    Simulator::Stop(Seconds(global_stop_time));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
