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
 * This example is same with "firewall exerciese" in p4lang/tutorials
 * URL: https://github.com/p4lang/tutorials/tree/master/exercises/firewall
 * The P4 program implements basic firewall.
 *
 *          ┌──────────┐              ┌──────────┐
 *          │ Switch 2 \\            /│ Switch 3 │
 *          └─────┬────┘  \        // └──────┬───┘
 *                │         \    /           │
 *                │           /              │
 *          ┌─────┴────┐   /   \      ┌──────┴───┐
 *          │ Switch 0 //         \ \ │ Switch 1 │
 *      ┌───┼ firewall │             \\          ┼────┐
 *      │   └────────┬─┘              └┬─────────┘    │
 *  ┌───┼────┐     ┌─┴──────┐    ┌─────┼──┐     ┌─────┼──┐
 *  │ host 4 │     │ host 5 │    │ host 6 │     │ host 7 │
 *  └────────┘     └────────┘    └────────┘     └────────┘
 *  |----Interal network----|
 *
 */

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-topology-reader-helper.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4BasicExample");

unsigned long start = getTickCount();
double global_start_time = 1.0;
double sink_start_time = global_start_time + 1.0;
double client_start_time = sink_start_time + 1.0;
double client_stop_time = client_start_time + 3;
double sink_stop_time = client_stop_time + 5;
double global_stop_time = sink_stop_time + 5;

bool first_tx = true;
bool first_rx = true;
int counter_sender_10 = 10;
int counter_receiver_10 = 10;
double first_packet_send_time_tx = 0.0;
double last_packet_send_time_tx = 0.0;
double first_packet_received_time_rx = 0.0;
double last_packet_received_time_rx = 0.0;
uint64_t totalTxBytes = 0;
uint64_t totalRxBytes = 0;

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

// ============================ data struct ============================
struct SwitchNodeC_t
{
    NetDeviceContainer switchDevices;
    std::vector<std::string> switchPortInfos;
};

struct HostNodeC_t
{
    NetDeviceContainer hostDevice;
    Ipv4InterfaceContainer hostIpv4;
    unsigned int linkSwitchIndex;
    unsigned int linkSwitchPort;
    std::string hostIpv4Str;
};

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4BasicExample", LOG_LEVEL_INFO);

    // ============================ parameters ============================
    uint16_t pktSize = 1000;           // in Bytes. 1458 to prevent fragments, default 512
    std::string appDataRate = "1Mbps"; // Default application data rate
    std::string ns3_link_rate = "1000Mbps";
    bool enableTracePcap = true;

    // Use P4SIM_DIR environment variable for portable paths
    std::string p4SrcDir = GetP4ExamplePath() + "/p4_basic";
    std::string p4JsonPath = p4SrcDir + "/p4_basic.json";
    std::string flowTableDirPath = p4SrcDir + "/";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat("CsmaTopo");

    // ============================  command line ============================
    CommandLine cmd;
    cmd.AddValue("pktSize", "Packet size in bytes (default 1000)", pktSize);
    cmd.AddValue("appDataRate", "Application data rate in bps (default 1Mbps)", appDataRate);
    cmd.AddValue("pcap", "Trace packet pacp [true] or not[false]", enableTracePcap);
    cmd.Parse(argc, argv);

    // ============================ topo -> network ============================
    P4TopologyReaderHelper p4TopoHelper;
    p4TopoHelper.SetFileName(topoInput);
    p4TopoHelper.SetFileType(topoFormat);
    NS_LOG_INFO("*** Reading topology from file: " << topoInput << " with format: " << topoFormat);

    // Get the topology reader, and read the file, load in the m_linksList.
    Ptr<P4TopologyReader> topoReader = p4TopoHelper.GetTopologyReader();

    topoReader->PrintTopology();

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
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(ns3_link_rate));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(0.01)));

    P4TopologyReader::ConstLinksIterator_t iter;
    SwitchNodeC_t switchNodes[switchNum];
    HostNodeC_t hostNodes[hostNum];
    unsigned int fromIndex, toIndex;
    std::string dataRate, delay;
    for (iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); iter++)
    {
        if (iter->GetAttributeFailSafe("DataRate", dataRate))
            csma.SetChannelAttribute("DataRate", StringValue(dataRate));
        if (iter->GetAttributeFailSafe("Delay", delay))
            csma.SetChannelAttribute("Delay", StringValue(delay));

        fromIndex = iter->GetFromIndex();
        toIndex = iter->GetToIndex();
        NetDeviceContainer link =
            csma.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

        if (iter->GetFromType() == 's' && iter->GetToType() == 's')
        {
            NS_LOG_INFO("*** Link from  switch " << fromIndex << " to  switch " << toIndex
                                                 << " with data rate " << dataRate << " and delay "
                                                 << delay);

            unsigned int fromSwitchPortNumber = switchNodes[fromIndex].switchDevices.GetN();
            unsigned int toSwitchPortNumber = switchNodes[toIndex].switchDevices.GetN();
            switchNodes[fromIndex].switchDevices.Add(link.Get(0));
            switchNodes[fromIndex].switchPortInfos.push_back("s" + UintToString(toIndex) + "_" +
                                                             UintToString(toSwitchPortNumber));

            switchNodes[toIndex].switchDevices.Add(link.Get(1));
            switchNodes[toIndex].switchPortInfos.push_back("s" + UintToString(fromIndex) + "_" +
                                                           UintToString(fromSwitchPortNumber));
        }
        else
        {
            if (iter->GetFromType() == 's' && iter->GetToType() == 'h')
            {
                NS_LOG_INFO("*** Link from switch " << fromIndex << " to  host" << toIndex
                                                    << " with data rate " << dataRate
                                                    << " and delay " << delay);

                unsigned int fromSwitchPortNumber = switchNodes[fromIndex].switchDevices.GetN();
                switchNodes[fromIndex].switchDevices.Add(link.Get(0));
                switchNodes[fromIndex].switchPortInfos.push_back("h" +
                                                                 UintToString(toIndex - switchNum));

                hostNodes[toIndex - switchNum].hostDevice.Add(link.Get(1));
                hostNodes[toIndex - switchNum].linkSwitchIndex = fromIndex;
                hostNodes[toIndex - switchNum].linkSwitchPort = fromSwitchPortNumber;
            }
            else
            {
                if (iter->GetFromType() == 'h' && iter->GetToType() == 's')
                {
                    NS_LOG_INFO("*** Link from host " << fromIndex << " to  switch" << toIndex
                                                      << " with data rate " << dataRate
                                                      << " and delay " << delay);
                    unsigned int toSwitchPortNumber = switchNodes[toIndex].switchDevices.GetN();
                    switchNodes[toIndex].switchDevices.Add(link.Get(1));
                    switchNodes[toIndex].switchPortInfos.push_back(
                        "h" + UintToString(fromIndex - switchNum));

                    hostNodes[fromIndex - switchNum].hostDevice.Add(link.Get(0));
                    hostNodes[fromIndex - switchNum].linkSwitchIndex = toIndex;
                    hostNodes[fromIndex - switchNum].linkSwitchPort = toSwitchPortNumber;
                }
                else
                {
                    NS_LOG_ERROR("link error!");
                    abort();
                }
            }
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

    // Bridge or P4 switch configuration
    P4Helper p4SwitchHelper;
    p4SwitchHelper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(0));
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));

    for (unsigned int i = 0; i < switchNum; i++)
    {
        std::string flowTablePath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", \n " << flowTablePath);

        p4SwitchHelper.Install(switchNode.Get(i), switchNodes[i].switchDevices);
    }

    // === Configuration for Link: h0 -----> h3
    unsigned int serverI = 3;
    unsigned int clientI = 0;
    uint16_t servPort = 9093; // UDP port for the server

    // === Retrieve Server Address ===
    Ptr<Node> node = terminals.Get(serverI);
    Ptr<Ipv4> ipv4_adder = node->GetObject<Ipv4>();
    Ipv4Address serverAddr1 = ipv4_adder->GetAddress(1, 0).GetLocal();
    InetSocketAddress dst1 = InetSocketAddress(serverAddr1, servPort);
    PacketSinkHelper sink1("ns3::TcpSocketFactory", dst1);
    ApplicationContainer sinkApp1 = sink1.Install(terminals.Get(serverI));
    sinkApp1.Start(Seconds(sink_start_time));
    sinkApp1.Stop(Seconds(sink_stop_time));
    OnOffHelper onOff1("ns3::TcpSocketFactory", dst1);
    onOff1.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff1.SetAttribute("DataRate", StringValue(appDataRate));
    onOff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer app1 = onOff1.Install(terminals.Get(clientI));
    app1.Start(Seconds(client_start_time));
    app1.Stop(Seconds(client_stop_time));

    // Normal Stream == Second == send link h3 -----> h0
    serverI = 0;
    clientI = 3;
    servPort = 9200; // change the application port
    InetSocketAddress dst2 = InetSocketAddress(serverAddr1, servPort);
    PacketSinkHelper sink2 = PacketSinkHelper("ns3::UdpSocketFactory", dst2);
    ApplicationContainer sinkApp2 = sink2.Install(terminals.Get(serverI));
    sinkApp2.Start(Seconds(sink_start_time));
    sinkApp2.Stop(Seconds(sink_stop_time));
    OnOffHelper onOff2("ns3::UdpSocketFactory", dst2);
    onOff2.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff2.SetAttribute("DataRate", StringValue(appDataRate));
    onOff2.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff2.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer app2 = onOff2.Install(terminals.Get(clientI));
    app2.Start(Seconds(client_start_time));
    app2.Stop(Seconds(client_stop_time));

    // Normal Stream == Second == send link h3 -----> h0
    serverI = 0;
    clientI = 1;
    servPort = 9003; // change the application port
    InetSocketAddress dst3 = InetSocketAddress(serverAddr1, servPort);
    PacketSinkHelper sink3 = PacketSinkHelper("ns3::UdpSocketFactory", dst3);
    ApplicationContainer sinkApp3 = sink3.Install(terminals.Get(serverI));
    sinkApp3.Start(Seconds(sink_start_time));
    sinkApp3.Stop(Seconds(sink_stop_time));
    OnOffHelper onOff3("ns3::UdpSocketFactory", dst3);
    onOff3.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff3.SetAttribute("DataRate", StringValue(appDataRate));
    onOff3.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff3.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer app3 = onOff3.Install(terminals.Get(clientI));
    app3.Start(Seconds(client_start_time));
    app3.Stop(Seconds(client_stop_time));

    if (enableTracePcap)
    {
        csma.EnablePcapAll("p4-firewall");
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

    return 0;
}
