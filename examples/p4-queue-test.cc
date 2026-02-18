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
 *          ┌────────────────┐
 *          │    Switch 0    │
 *          └─▲────────────┬─┘
 *            │            │
 *  ┌─────────┼─┐        ┌─▼─────────┐
 *  │  Host 1   │        │  Host     │
 *  └───────────┘        └───────────┘
 */

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/custom-p2p-net-device.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-p2p-helper.h"
#include "ns3/p4-topology-reader-helper.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4QueueTest");

unsigned long start = getTickCount();
double global_start_time = 0.0;
double sink_start_time = global_start_time;
double client_start_time = sink_start_time;
double client_stop_time = client_start_time + 10; // sending time 100s
double sink_stop_time = client_stop_time + 5;
double global_stop_time = sink_stop_time + 5;

// Convert IP address to hexadecimal format
std::string
ConvertIpToHex(Ipv4Address ipAddr)
{
    std::ostringstream hexStream;
    uint32_t ip = ipAddr.Get(); // Get the IP address as a 32-bit integer
    hexStream << "0x" << std::hex << std::setfill('0') << std::setw(2)
              << ((ip >> 24) & 0xFF)                 // First byte
              << std::setw(2) << ((ip >> 16) & 0xFF) // Second byte
              << std::setw(2) << ((ip >> 8) & 0xFF)  // Third byte
              << std::setw(2) << (ip & 0xFF);        // Fourth byte
    return hexStream.str();
}

// Convert MAC address to hexadecimal format
std::string
ConvertMacToHex(Address macAddr)
{
    std::ostringstream hexStream;
    Mac48Address mac = Mac48Address::ConvertFrom(macAddr); // Convert Address to Mac48Address
    uint8_t buffer[6];
    mac.CopyTo(buffer); // Copy MAC address bytes into buffer

    hexStream << "0x";
    for (int i = 0; i < 6; ++i)
    {
        hexStream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buffer[i]);
    }
    return hexStream.str();
}

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4QueueTest", LOG_LEVEL_INFO);

    // ============================ parameters ============================

    uint16_t pktSize = 1000; // each packets 1000 bytes

    // 900 pps * 1000 * 8 bits = 7.2Mbps, 1000pps = 8Mbps
    std::string appDataRate_1 = "3Mbps";
    std::string appDataRate_2 = "4Mbps";
    std::string appDataRate_3 = "5Mbps"; // total 1500 pps = 12Mbps

    int running_number = 0;
    std::string ns3_link_rate = "1000Mbps";
    bool enableTracePcap = true;

    // Use P4SIM_DIR environment variable for portable paths
    std::string p4SrcDir = GetP4ExamplePath() + "/qos";
    std::string p4JsonPath = p4SrcDir + "/qos.json";
    std::string flowTablePath = p4SrcDir + "/flowtable_0.txt";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat("P2PTopo");

    // ============================  command line ============================
    CommandLine cmd;
    cmd.AddValue("runnum", "running number in loops", running_number);
    cmd.AddValue("pktSize", "Packet size in bytes (default 1000)", pktSize);
    cmd.AddValue("pcap", "Trace packet pacp [true] or not[false]", enableTracePcap);
    cmd.Parse(argc, argv);

    // ============================ topo -> network ============================

    P4TopologyReaderHelper p4TopoHelper;
    p4TopoHelper.SetFileName(topoInput);
    p4TopoHelper.SetFileType(topoFormat);
    NS_LOG_INFO("*** Reading topology from file: " << topoInput << " with format: " << topoFormat);

    // Get the topology reader, and read the file, load in the m_linksList.
    Ptr<P4TopologyReader> topoReader = p4TopoHelper.GetTopologyReader();

    if (topoReader->LinksSize() == 0)
    {
        NS_LOG_ERROR("Problems reading the topology file. Failing.");
        return -1;
    }

    // get switch and host node
    NodeContainer terminals = topoReader->GetHostNodeContainer();
    NodeContainer switchNode = topoReader->GetSwitchNodeContainer();

    const unsigned int hostNum = terminals.GetN();
    const unsigned int switchNum = switchNode.GetN();
    NS_LOG_INFO("*** Host number: " << hostNum << ", Switch number: " << switchNum);

    // set default network link parameter
    P4PointToPointHelper p4p2p;
    p4p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate(ns3_link_rate)));
    p4p2p.SetChannelAttribute("Delay", TimeValue(MicroSeconds(10)));

    NetDeviceContainer hostDevices;
    NetDeviceContainer switchDevices;
    P4TopologyReader::ConstLinksIterator_t iter;
    for (iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); iter++)
    {
        NetDeviceContainer link =
            p4p2p.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

        if (iter->GetFromType() == 's' && iter->GetToType() == 's')
        {
            switchDevices.Add(link.Get(0));
            switchDevices.Add(link.Get(1));
        }
        else if (iter->GetFromType() == 's' && iter->GetToType() == 'h')
        {
            switchDevices.Add(link.Get(0));
            hostDevices.Add(link.Get(1));
        }
        else if (iter->GetFromType() == 'h' && iter->GetToType() == 's')
        {
            hostDevices.Add(link.Get(0));
            switchDevices.Add(link.Get(1));
        }
        else
        {
            NS_LOG_ERROR("link error!");
            abort();
        }
    }

    // ========================Print the Channel Type and NetDevice Type========================

    InternetStackHelper internet;
    internet.Install(terminals);
    internet.Install(switchNode);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    std::vector<Ipv4InterfaceContainer> terminalInterfaces(hostNum);
    std::vector<std::string> hostIpv4(hostNum);

    for (unsigned int i = 0; i < hostNum; i++)
    {
        terminalInterfaces[i] = ipv4.Assign(terminals.Get(i)->GetDevice(0));
        hostIpv4[i] = Uint32IpToHex(terminalInterfaces[i].GetAddress(0).Get());
    }

    //===============================  Print IP and MAC addresses===============================
    NS_LOG_INFO("Node IP and MAC addresses:");
    for (uint32_t i = 0; i < terminals.GetN(); ++i)
    {
        Ptr<Node> node = terminals.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        Ptr<NetDevice> netDevice = node->GetDevice(0);

        // Get the IP address
        Ipv4Address ipAddr =
            ipv4->GetAddress(1, 0)
                .GetLocal(); // Interface index 1 corresponds to the first assigned IP

        // Get the MAC address
        Ptr<NetDevice> device = node->GetDevice(0); // Assuming the first device is the desired one
        Mac48Address mac = Mac48Address::ConvertFrom(device->GetAddress());

        NS_LOG_INFO("Node " << i << ": IP = " << ipAddr << ", MAC = " << mac);

        // Convert to hexadecimal
        std::string ipHex = ConvertIpToHex(ipAddr);
        std::string macHex = ConvertMacToHex(mac);
        NS_LOG_INFO("Node " << i << ": IP = " << ipHex << ", MAC = " << macHex);
    }

    P4Helper p4SwitchHelper;
    p4SwitchHelper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4SwitchHelper.SetDeviceAttribute("EnableTracing", BooleanValue(true));
    p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(1)); // P2P channel
    p4SwitchHelper.SetDeviceAttribute("SwitchRate", UintegerValue(1200));
    p4SwitchHelper.SetDeviceAttribute("QueueBufferSize", UintegerValue(1000));
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch",
                                      UintegerValue(0)); // v1model 0, psa 1, pna 2

    for (unsigned int i = 0; i < switchNum; i++)
    {
        p4SwitchHelper.Install(switchNode.Get(i), switchDevices);
    }

    // === Configuration for Link: h0 -----> h1 ===
    unsigned int serverI = 1;
    unsigned int clientI = 0;
    uint16_t servPort = 2000; // UDP port for the server

    // === Retrieve Server Address ===
    Ptr<Node> node = terminals.Get(serverI);
    Ptr<Ipv4> ipv4_adder = node->GetObject<Ipv4>();
    Ipv4Address serverAddr1 = ipv4_adder->GetAddress(1, 0).GetLocal();
    InetSocketAddress dst1 = InetSocketAddress(serverAddr1, servPort);

    // === Setup Packet Sink on Server ===
    PacketSinkHelper sink1("ns3::UdpSocketFactory", dst1);
    ApplicationContainer sinkApp1 = sink1.Install(terminals.Get(serverI));
    sinkApp1.Start(Seconds(sink_start_time));
    sinkApp1.Stop(Seconds(sink_stop_time));

    // === Setup OnOff Application on Client ===
    OnOffHelper onOff1("ns3::UdpSocketFactory", dst1);
    onOff1.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff1.SetAttribute("DataRate", StringValue(appDataRate_1));
    onOff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer app1 = onOff1.Install(terminals.Get(clientI));
    app1.Start(Seconds(client_start_time));
    app1.Stop(Seconds(client_stop_time));

    // Normal Stream == Second == send link h0 -----> h1
    servPort = 3000; // change the application port

    InetSocketAddress dst2 = InetSocketAddress(serverAddr1, servPort);
    PacketSinkHelper sink2 = PacketSinkHelper("ns3::UdpSocketFactory", dst2);
    ApplicationContainer sinkApp2 = sink2.Install(terminals.Get(serverI));

    sinkApp2.Start(Seconds(sink_start_time));
    sinkApp2.Stop(Seconds(sink_stop_time));

    OnOffHelper onOff2("ns3::UdpSocketFactory", dst2);
    onOff2.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff2.SetAttribute("DataRate", StringValue(appDataRate_2));
    onOff2.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff2.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer app2 = onOff2.Install(terminals.Get(clientI));
    app2.Start(Seconds(client_start_time));
    app2.Stop(Seconds(client_stop_time));

    // Normal Stream == Second == send link h0 -----> h1
    servPort = 4000; // change the application port

    InetSocketAddress dst3 = InetSocketAddress(serverAddr1, servPort);
    PacketSinkHelper sink3 = PacketSinkHelper("ns3::UdpSocketFactory", dst3);
    ApplicationContainer sinkApp3 = sink3.Install(terminals.Get(serverI));

    sinkApp3.Start(Seconds(sink_start_time));
    sinkApp3.Stop(Seconds(sink_stop_time));

    OnOffHelper onOff3("ns3::UdpSocketFactory", dst3);
    onOff3.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff3.SetAttribute("DataRate", StringValue(appDataRate_3));
    onOff3.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff3.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer app3 = onOff3.Install(terminals.Get(clientI));
    app3.Start(Seconds(client_start_time));
    app3.Stop(Seconds(client_stop_time));

    if (enableTracePcap)
    {
        p4p2p.EnablePcapAll("p4-queue-test");
    }

    // Run simulation
    NS_LOG_INFO("Running simulation...");
    unsigned long simulate_start = getTickCount();
    Simulator::Stop(Seconds(global_stop_time));
    Simulator::Run();
    Simulator::Destroy();

    unsigned long end = getTickCount();
    NS_LOG_INFO("Simulate Running time: " << end - simulate_start << "ms" << std::endl
                                          << "Total Running time: " << end - start << "ms"
                                          << std::endl
                                          << "Run successfully!");

    // PrintFinalThroughput();

    return 0;
}
