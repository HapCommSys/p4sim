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
 * This example is same with "basic exerciese" in p4lang/tutorials
 * URL: https://github.com/p4lang/tutorials/tree/master/exercises/basic
 * The P4 program implements basic ipv4 forwarding, also with ARP.
 *                        Controller
 *          ┌──────────┐              ┌──────────┐
 *          │ Switch 2 \\            /│ Switch 3 │
 *          └─────┬────┘  \        // └──────┬───┘
 *                │         \    /           │
 *                │           /              │
 *          ┌─────┴────┐   /   \      ┌──────┴───┐
 *          │ Switch 0 //         \ \ │ Switch 1 │
 *      ┌───┼          │             \\          ┼────┐
 *      │   └────────┬─┘              └┬─────────┘    │
 *  ┌───┼────┐     ┌─┴──────┐    ┌─────┼──┐     ┌─────┼──┐
 *  │ host 4 │     │ host 5 │    │ host 6 │     │ host 7 │
 *  └────────┘     └────────┘    └────────┘     └────────┘
 */

#include "example-check.h"

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-controller.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-net-builder.h"
#include "ns3/p4-topology-reader-helper.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4BasicController");

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

void
TxCallback(Ptr<const Packet> packet)
{
    if (first_tx)
    {
        // here we just simple jump the first 10 pkts (include some of ARP packets)
        first_packet_send_time_tx = Simulator::Now().GetSeconds();
        counter_sender_10--;
        if (counter_sender_10 == 0)
        {
            first_tx = false;
        }
    }
    else
    {
        totalTxBytes += packet->GetSize();
        last_packet_send_time_tx = Simulator::Now().GetSeconds();
    }
}

void
RxCallback(Ptr<const Packet> packet, const Address& addr)
{
    if (first_rx)
    {
        // here we just simple jump the first 10 pkts (include some of ARP packets)
        first_packet_received_time_rx = Simulator::Now().GetSeconds();
        counter_receiver_10--;
        if (counter_receiver_10 == 0)
        {
            first_rx = false;
        }
    }
    else
    {
        totalRxBytes += packet->GetSize();
        last_packet_received_time_rx = Simulator::Now().GetSeconds();
    }
}

const double REROUTE_TIME = 4.5; ///< when the controller changes the route (s)
/// data frames that switch 0 sent before and after REROUTE_TIME, by port
std::map<uint32_t, std::pair<uint32_t, uint32_t>> g_frames;

void
CountFrame(uint32_t port, Ptr<const Packet> packet)
{
    if (packet->GetSize() > 500)
    {
        auto& [before, after] = g_frames[port];
        (Simulator::Now() < Seconds(REROUTE_TIME) ? before : after)++;
    }
}

void
PrintFinalThroughput()
{
    double send_time = last_packet_send_time_tx - first_packet_send_time_tx;
    double elapsed_time = last_packet_received_time_rx - first_packet_received_time_rx;

    double finalTxThroughput = (totalTxBytes * 8.0) / (send_time * 1e6);
    double finalRxThroughput = (totalRxBytes * 8.0) / (elapsed_time * 1e6);
    std::cout << "client_start_time: " << first_packet_send_time_tx
              << "client_stop_time: " << last_packet_send_time_tx
              << "sink_start_time: " << first_packet_received_time_rx
              << "sink_stop_time: " << last_packet_received_time_rx << std::endl;

    std::cout << "======================================" << std::endl;
    std::cout << "Final Simulation Results:" << std::endl;
    std::cout << "Total Transmitted Bytes: " << totalTxBytes << " bytes in time " << send_time
              << std::endl;
    std::cout << "Total Received Bytes: " << totalRxBytes << " bytes in time " << elapsed_time
              << std::endl;
    std::cout << "Final Transmitted Throughput: " << finalTxThroughput << " Mbps" << std::endl;
    std::cout << "Final Received Throughput: " << finalRxThroughput << " Mbps" << std::endl;
    std::cout << "======================================" << std::endl;
}


int
main(int argc, char* argv[])
{
    LogComponentEnable("P4BasicController", LOG_LEVEL_INFO);
    LogComponentEnable("P4CoreV1model", LOG_LEVEL_WARN);

    // ============================ parameters ============================
    uint16_t pktSize = 1000;           // in Bytes. 1458 to prevent fragments, default 512
    std::string appDataRate = "3Mbps"; // Default application data rate
    std::string ns3_link_rate = "1000Mbps";
    bool enableTracePcap = true;

    // P4 files: examples/p4src in the p4sim folder of this build
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

    std::vector<SwitchNodeC_t> switchNodes(switchNum);
    std::vector<HostNodeC_t> hostNodes(hostNum);
    BuildNetworkFromTopology(topoReader, csma, switchNodes, hostNodes);

    // ========================Print the Channel Type and NetDevice
    // Type========================

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

    //===============================  Print IP and MAC
    // addresses===============================
    NS_LOG_INFO("Node IP and MAC addresses:");
    for (uint32_t i = 0; i < terminals.GetN(); ++i)
    {
        Ptr<Node> node = terminals.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        Ptr<NetDevice> netDevice = node->GetDevice(0);

        // Get the IP address
        Ipv4Address ipAddr = ipv4->GetAddress(1, 0).GetLocal(); // Interface index 1 corresponds to
                                                                // the first assigned IP

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
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));

    P4Controller controller;

    for (unsigned int i = 0; i < switchNum; i++)
    {
        std::string flowTablePath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", \n " << flowTablePath);

        NetDeviceContainer p4SwitchNetDeviceContainer =
            p4SwitchHelper.Install(switchNode.Get(i), switchNodes[i].switchDevices);

        for (uint32_t j = 0; j < p4SwitchNetDeviceContainer.GetN(); j++)
        {
            Ptr<P4SwitchNetDevice> p4sw =
                DynamicCast<P4SwitchNetDevice>(p4SwitchNetDeviceContainer.Get(j));
            if (p4sw)
            {
                controller.RegisterSwitch(p4sw);
            }
            else
            {
                NS_LOG_WARN("Failed to cast device at index " << j << " to P4SwitchNetDevice");
            }
        }
    }

    controller.ConnectToSwitchEvents(0);
    Simulator::Schedule(Seconds(2.0), [&controller]() {
        controller.PrintTableEntryCount(0, "MyIngress.ipv4_nhop");
        controller.PrintFlowEntries(0, "MyIngress.ipv4_nhop");
    });

    // At 4.5 s the controller moves the flow to host 3 from the path through switch 3 (port
    // 3 of switch 0) to the path through switch 2 (port 2): it changes the entry of 10.1.1.4,
    // the fourth of the table (handle 3)
    Simulator::Schedule(Seconds(REROUTE_TIME), [&controller]() {
        bm::ActionData action;
        action.push_back_action_data(bm::Data(7)); // MAC address of host 3
        action.push_back_action_data(bm::Data(2)); // port
        controller.ModifyFlowEntry(0, "MyIngress.ipv4_nhop", 3, "MyIngress.ipv4_forward", action);
    });
    for (uint32_t port : {2, 3})
    {
        switchNodes[0].switchDevices.Get(port)->TraceConnectWithoutContext(
            "MacTx",
            MakeBoundCallback(&CountFrame, port));
    }

    // === Configuration for Link: h0 -----> h1 ===
    unsigned int serverI = 3;
    unsigned int clientI = 0;
    uint16_t servPort = 9093; // UDP port for the server

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
    onOff1.SetAttribute("DataRate", StringValue(appDataRate));
    onOff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer app1 = onOff1.Install(terminals.Get(clientI));
    app1.Start(Seconds(client_start_time));
    app1.Stop(Seconds(client_stop_time));

    // === Setup Tracing ===
    Ptr<OnOffApplication> ptr_app1 =
        DynamicCast<OnOffApplication>(terminals.Get(clientI)->GetApplication(0));
    ptr_app1->TraceConnectWithoutContext("Tx", MakeCallback(&TxCallback));
    sinkApp1.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&RxCallback));

    if (enableTracePcap)
    {
        csma.EnablePcapAll("p4-basic-controller");
    }

    // Run simulation
    NS_LOG_INFO("Running simulation...");
    unsigned long simulate_start = getTickCount();
    Simulator::Stop(Seconds(global_stop_time));
    p4sim_example::CountTraffic();
    Simulator::Run();
    Simulator::Destroy();

    unsigned long end = getTickCount();
    NS_LOG_INFO("Simulate Running time: " << end - simulate_start << "ms" << std::endl
                                          << "Total Running time: " << end - start << "ms"
                                          << std::endl
                                          << "Run successfully!");

    PrintFinalThroughput();

    std::cout << "Frames of switch 0: port 3 " << g_frames[3].first << " before and "
              << g_frames[3].second << " after " << REROUTE_TIME << " s, port 2 "
              << g_frames[2].first << " before and " << g_frames[2].second << " after\n";
    int failed = p4sim_example::Check(g_frames[3].first > 0 && g_frames[3].second == 0 &&
                                          g_frames[2].first == 0 && g_frames[2].second > 0,
                                      "the controller moved the flow from port 3 to port 2");
    return failed | p4sim_example::CheckDelivery();
}
