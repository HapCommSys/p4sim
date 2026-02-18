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

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/custom-header.h"
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

NS_LOG_COMPONENT_DEFINE("P4BasicTunnel");

unsigned long start = getTickCount();
double global_start_time = 1.0;
double sink_start_time = global_start_time + 1.0;
double client_start_time = sink_start_time + 1.0;
double client_stop_time = client_start_time + 3; // sending time
double sink_stop_time = client_stop_time + 5;
double global_stop_time = sink_stop_time + 5;

// bool first_tx = true;
// bool first_rx = true;
int counter_sender_10 = 10;
int counter_receiver_10 = 10;
double first_packet_send_time_tx = 0.0;
double last_packet_send_time_tx = 0.0;
double first_packet_received_time_rx = 0.0;
double last_packet_received_time_rx = 0.0;
uint64_t totalTxBytes_1 = 0;
uint64_t totalRxBytes_1 = 0;
uint64_t totalTxBytes_2 = 0;
uint64_t totalRxBytes_2 = 0;

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

void
TxCallback(Ptr<const Packet> packet)
{
    totalTxBytes_1 += packet->GetSize();
    last_packet_send_time_tx = Simulator::Now().GetSeconds();
}

void
RxCallback(Ptr<const Packet> packet, const Address& addr)
{
    totalRxBytes_1 += packet->GetSize();
    last_packet_received_time_rx = Simulator::Now().GetSeconds();
}

void
TxCallback_2(Ptr<const Packet> packet)
{
    totalTxBytes_2 += packet->GetSize();
    last_packet_send_time_tx = Simulator::Now().GetSeconds();
}

void
RxCallback_2(Ptr<const Packet> packet, const Address& addr)
{
    totalRxBytes_2 += packet->GetSize();
    last_packet_received_time_rx = Simulator::Now().GetSeconds();
}

void
PrintFinalThroughput()
{
    // 计算传输和接收的时间间隔
    double send_time = last_packet_send_time_tx - first_packet_send_time_tx;
    double elapsed_time = last_packet_received_time_rx - first_packet_received_time_rx;

    // 计算每个传输流的总字节数
    uint64_t totalTxBytes = totalTxBytes_1 + totalTxBytes_2;
    uint64_t totalRxBytes = totalRxBytes_1 + totalRxBytes_2;

    // 避免除零错误
    double finalTxThroughput = (send_time > 0) ? (totalTxBytes * 8.0) / (send_time * 1e6) : 0.0;
    double finalRxThroughput =
        (elapsed_time > 0) ? (totalRxBytes * 8.0) / (elapsed_time * 1e6) : 0.0;

    std::cout << "======================================" << std::endl;
    std::cout << "Final Simulation Results:" << std::endl;
    std::cout << "Client Start Time: " << first_packet_send_time_tx << " s" << std::endl;
    std::cout << "Client Stop Time: " << last_packet_send_time_tx << " s" << std::endl;
    std::cout << "Sink Start Time: " << first_packet_received_time_rx << " s" << std::endl;
    std::cout << "Sink Stop Time: " << last_packet_received_time_rx << " s" << std::endl;

    std::cout << "--------------------------------------" << std::endl;
    std::cout << "Detailed Bytes Transmitted & Received" << std::endl;
    std::cout << "Tx Stream 1: " << totalTxBytes_1 << " bytes" << std::endl;
    std::cout << "Tx Stream 2: " << totalTxBytes_2 << " bytes" << std::endl;
    std::cout << "Total Transmitted Bytes: " << totalTxBytes << " bytes over " << send_time << " s"
              << std::endl;

    std::cout << "Rx Stream 1: " << totalRxBytes_1 << " bytes" << std::endl;
    std::cout << "Rx Stream 2: " << totalRxBytes_2 << " bytes" << std::endl;
    std::cout << "Total Received Bytes: " << totalRxBytes << " bytes over " << elapsed_time << " s"
              << std::endl;

    std::cout << "--------------------------------------" << std::endl;
    std::cout << "Final Throughput Metrics" << std::endl;
    std::cout << "Final Transmitted Throughput: " << finalTxThroughput << " Mbps" << std::endl;
    std::cout << "Final Received Throughput: " << finalRxThroughput << " Mbps" << std::endl;
    std::cout << "======================================" << std::endl;
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
    LogComponentEnable("P4BasicTunnel", LOG_LEVEL_INFO);

    Packet::EnablePrinting();

    // ============================ parameters ============================

    int running_number = 0;
    uint16_t pktSize = 1000; // in Bytes. 1458 to prevent fragments, default 512
    std::string appDataRate[] = {"1Mbps", "4Mbps"}; // Default application data rate
    std::string ns3_link_rate = "100Mbps";
    bool enableTracePcap = true;

    // Use P4SIM_DIR environment variable for portable paths
    std::string p4SrcDir = GetP4ExamplePath() + "/basic_tunnel";
    std::string p4JsonPath = p4SrcDir + "/basic_tunnel.json";
    std::string flowTableDirPath = p4SrcDir + "/";
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
    P4PointToPointHelper p4p2phelper;
    p4p2phelper.SetDeviceAttribute("DataRate", DataRateValue(DataRate(ns3_link_rate)));
    p4p2phelper.SetChannelAttribute("Delay", TimeValue(MilliSeconds(1)));

    P4TopologyReader::ConstLinksIterator_t iter;
    SwitchNodeC_t switchNodes[switchNum];
    HostNodeC_t hostNodes[hostNum];
    unsigned int fromIndex, toIndex;
    std::string dataRate, delay;
    for (iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); iter++)
    {
        fromIndex = iter->GetFromIndex();
        toIndex = iter->GetToIndex();
        NetDeviceContainer link =
            p4p2phelper.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

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
    // ======================== Print the Channel Type and NetDevice Type ========================

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
    // p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(0));
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(1));
    p4SwitchHelper.SetDeviceAttribute("SwitchRate", UintegerValue(1000));

    for (unsigned int i = 0; i < switchNum; i++)
    {
        std::string flowTablePath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", \n " << flowTablePath);

        p4SwitchHelper.Install(switchNode.Get(i), switchNodes[i].switchDevices);
    }

    // ============================ add custom header for the p4 switch ============================

    CustomHeader myTunnelHeader;
    myTunnelHeader.SetLayer(HeaderLayer::LAYER_3); // Network Layer
    myTunnelHeader.SetOperator(ADD_BEFORE);        // add before the ipv4 header

    myTunnelHeader.AddField("proto_id", 16);
    myTunnelHeader.AddField("dst_id", 16);

    myTunnelHeader.SetField("proto_id", 0x0800); // Example: IPv4 protocol
    myTunnelHeader.SetField("dst_id", 0x22);     // Example: Destination ID

    // Set for the NetDevice
    for (unsigned int i = 0; i < hostNum; i++)
    {
        Ptr<NetDevice> device = hostNodes[i].hostDevice.Get(0);
        if (device->GetObject<CustomP2PNetDevice>())
        {
            NS_LOG_DEBUG(
                "Host " << i << " NetDevice is CustomP2PNetDevice, Setting for the Tunnel Header!");
            Ptr<CustomP2PNetDevice> customDevice = DynamicCast<CustomP2PNetDevice>(device);
            customDevice->SetWithCustomHeader(true);
            customDevice->SetCustomHeader(myTunnelHeader);
        }
    }

    // ============================ add application to the hosts ============================

    // TUNNEL stream == First == send link h0 -----> h1
    unsigned int serverI = 1;
    unsigned int clientI = 0;
    uint16_t servPort = 12000; // setting for port

    Ptr<Node> node = terminals.Get(serverI);
    Ptr<Ipv4> ipv4_adder = node->GetObject<Ipv4>();
    Ipv4Address serverAddr1 =
        ipv4_adder->GetAddress(1, 0)
            .GetLocal(); // Interface index 1 corresponds to the first assigned IP
    InetSocketAddress dst1 = InetSocketAddress(serverAddr1, servPort);
    PacketSinkHelper sink1 = PacketSinkHelper("ns3::UdpSocketFactory", dst1);
    ApplicationContainer sinkApp1 = sink1.Install(terminals.Get(serverI));

    sinkApp1.Start(Seconds(sink_start_time));
    sinkApp1.Stop(Seconds(sink_stop_time));

    OnOffHelper onOff1("ns3::UdpSocketFactory", dst1);
    onOff1.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff1.SetAttribute("DataRate", StringValue(appDataRate[0]));
    onOff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    // onOff1.SetAttribute("MaxBytes", UintegerValue(5000));

    ApplicationContainer app1 = onOff1.Install(terminals.Get(clientI));
    app1.Start(Seconds(client_start_time));
    app1.Stop(Seconds(client_stop_time));

    // Normal Stream == Second == send link h0 -----> h1
    servPort = 1301; // change the application port

    node = terminals.Get(serverI);
    ipv4_adder = node->GetObject<Ipv4>();
    serverAddr1 = ipv4_adder->GetAddress(1, 0)
                      .GetLocal(); // Interface index 1 corresponds to the first assigned IP
    InetSocketAddress dst2 = InetSocketAddress(serverAddr1, servPort);
    PacketSinkHelper sink2 = PacketSinkHelper("ns3::UdpSocketFactory", dst2);
    ApplicationContainer sinkApp2 = sink2.Install(terminals.Get(serverI));

    sinkApp2.Start(Seconds(sink_start_time));
    sinkApp2.Stop(Seconds(sink_stop_time));

    OnOffHelper onOff2("ns3::UdpSocketFactory", dst2);
    onOff2.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff2.SetAttribute("DataRate", StringValue(appDataRate[1]));
    onOff2.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff2.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    // onOff2.SetAttribute("MaxBytes", UintegerValue(10000));

    ApplicationContainer app2 = onOff2.Install(terminals.Get(clientI));
    app2.Start(Seconds(client_start_time));
    app2.Stop(Seconds(client_stop_time));

    // Enable pcap tracing
    p4p2phelper.EnablePcapAll("p4-basic-tunnel");

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

    PrintFinalThroughput();
    return 0;
}
