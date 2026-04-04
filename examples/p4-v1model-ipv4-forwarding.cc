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
 *  │  Host 1   │        │  Host  2  │
 *  └───────────┘        └───────────┘
 */

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/csma-net-device.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-net-builder.h"
#include "ns3/p4-topology-reader-helper.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4V1modelIpv4Forwarding");

unsigned long start = getTickCount();
double global_start_time = 1.0;
double sink_start_time = global_start_time + 1.0;
double client_start_time = sink_start_time + 1.0;
double client_stop_time = client_start_time + 3; // sending time 30s
double sink_stop_time = client_stop_time + 5;
double global_stop_time = sink_stop_time + 5;

double first_packet_send_time_tx = 0.0;
double last_packet_send_time_tx = 0.0;
double first_packet_received_time_rx = 0.0;
double last_packet_received_time_rx = 0.0;
uint64_t totalTxBytes = 0;
uint64_t totalRxBytes = 0;

// MAC-layer stats (data packets only, ARP <= 64 bytes skipped)
uint64_t macTxBytes = 0;
uint64_t macRxBytes = 0;
double firstMacTxTime = 0.0;
double lastMacTxTime = 0.0;
double firstMacRxTime = 0.0;
double lastMacRxTime = 0.0;
bool firstMacTx = true;
bool firstMacRx = true;

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

static void
TxDropTrace(std::string label, Ptr<const Packet> p)
{
    NS_LOG_DEBUG(Simulator::Now().GetSeconds()
                 << "s [" << label << "][DROP] size=" << p->GetSize());
}

static void
MacTxTrace(std::string label, Ptr<const Packet> p)
{
    double now = Simulator::Now().GetSeconds();
    NS_LOG_DEBUG(now << "s [" << label << "][MacTx] size=" << p->GetSize());
    if (label == "TX-host" && p->GetSize() > 64)
    {
        if (firstMacTx)
        {
            firstMacTxTime = now;
            firstMacTx = false;
        }
        lastMacTxTime = now;
        macTxBytes += p->GetSize();
    }
}

static void
MacRxTrace(std::string label, Ptr<const Packet> p)
{
    double now = Simulator::Now().GetSeconds();
    NS_LOG_DEBUG(now << "s [" << label << "][MacRx] size=" << p->GetSize());
    if (label == "RX-host" && p->GetSize() > 64)
    {
        if (firstMacRx)
        {
            firstMacRxTime = now;
            firstMacRx = false;
        }
        lastMacRxTime = now;
        macRxBytes += p->GetSize();
    }
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

static void
LogNodeAddresses(const NodeContainer& terminals)
{
    NS_LOG_INFO("Node IP and MAC addresses:");
    for (uint32_t i = 0; i < terminals.GetN(); ++i)
    {
        Ptr<Node> node = terminals.Get(i);
        Ptr<Ipv4> ipv4Proto = node->GetObject<Ipv4>();
        Ipv4Address ipAddr = ipv4Proto->GetAddress(1, 0).GetLocal();
        Mac48Address mac = Mac48Address::ConvertFrom(node->GetDevice(0)->GetAddress());
        NS_LOG_INFO("Node " << i << ": IP = " << ipAddr << ", MAC = " << mac);
        NS_LOG_INFO("Node " << i << ": IP = " << ConvertIpToHex(ipAddr)
                            << ", MAC = " << ConvertMacToHex(mac));
    }
}

void
TxCallback(uint32_t dataSize, Ptr<const Packet> packet)
{
    // Here we filter out non-data packets (e.g., ARP) by checking the packet size against the
    // expected data size. The system will first send ARP packets to resolve the MAC address, which
    // are typically smaller than the application data packets. By only counting packets that match
    // the expected data size, we can focus our throughput calculations on the actual application
    // data being sent, providing a more accurate measure of the effective throughput of the system.
    if (packet->GetSize() != dataSize)
        return; // skip ARP and other non-data packets
    if (first_packet_send_time_tx == 0.0)
        first_packet_send_time_tx = Simulator::Now().GetSeconds();
    totalTxBytes += packet->GetSize();
    last_packet_send_time_tx = Simulator::Now().GetSeconds();
}

void
RxCallback(uint32_t dataSize, Ptr<const Packet> packet, const Address& addr)
{
    if (packet->GetSize() != dataSize)
        return; // skip ARP and other non-data packets
    if (first_packet_received_time_rx == 0.0)
        first_packet_received_time_rx = Simulator::Now().GetSeconds();
    totalRxBytes += packet->GetSize();
    last_packet_received_time_rx = Simulator::Now().GetSeconds();
}

void
PrintFinalThroughput()
{
    double send_time = last_packet_send_time_tx - first_packet_send_time_tx;
    double elapsed_time = last_packet_received_time_rx - first_packet_received_time_rx;

    double finalTxThroughput = (send_time > 0) ? (totalTxBytes * 8.0) / (send_time * 1e6) : 0.0;
    double finalRxThroughput =
        (elapsed_time > 0) ? (totalRxBytes * 8.0) / (elapsed_time * 1e6) : 0.0;
    double pktDeliveryRatio =
        (totalTxBytes > 0) ? (double)totalRxBytes / totalTxBytes * 100.0 : 0.0;

    double macTxTime = lastMacTxTime - firstMacTxTime;
    double macRxTime = lastMacRxTime - firstMacRxTime;
    double macTxThroughput = (macTxTime > 0) ? (macTxBytes * 8.0) / (macTxTime * 1e6) : 0.0;
    double macRxThroughput = (macRxTime > 0) ? (macRxBytes * 8.0) / (macRxTime * 1e6) : 0.0;

    std::cout << "======================================" << std::endl;
    std::cout << "Final Simulation Results:" << std::endl;
    std::cout << "  ** [App Layer]" << std::endl;
    std::cout << "  PDR: " << pktDeliveryRatio << "%" << std::endl;
    std::cout << "  TX: " << totalTxBytes << " bytes  (" << first_packet_send_time_tx << "s -> "
              << last_packet_send_time_tx << "s,  elapsed=" << send_time << "s)" << std::endl;
    std::cout << "  RX: " << totalRxBytes << " bytes  (" << first_packet_received_time_rx << "s -> "
              << last_packet_received_time_rx << "s,  elapsed=" << elapsed_time << "s)"
              << std::endl;
    std::cout << "  TX Throughput: " << finalTxThroughput << " Mbps" << std::endl;
    std::cout << "  RX Throughput: " << finalRxThroughput << " Mbps" << std::endl;
    std::cout << "  ** [MAC Layer]" << std::endl;
    std::cout << "  TX-host MacTx: " << macTxBytes << " bytes  (" << firstMacTxTime << "s -> "
              << lastMacTxTime << "s,  elapsed=" << macTxTime << "s)" << std::endl;
    std::cout << "  RX-host MacRx: " << macRxBytes << " bytes  (" << firstMacRxTime << "s -> "
              << lastMacRxTime << "s,  elapsed=" << macRxTime << "s)" << std::endl;
    std::cout << "  MAC TX Throughput: " << macTxThroughput << " Mbps" << std::endl;
    std::cout << "  MAC RX Throughput: " << macRxThroughput << " Mbps" << std::endl;
    std::cout << "======================================" << std::endl;
}

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4V1modelIpv4Forwarding", LOG_LEVEL_INFO);
    // LogComponentEnable("P4SwitchCore", LOG_LEVEL_DEBUG);

    // -----------------------------------------------------------------------
    // Simulation parameters – all adjustable via the command line
    // -----------------------------------------------------------------------
    uint16_t pktSize = 1000;           ///< Application payload size (bytes).
    std::string appDataRate = "3Mbps"; ///< OnOff application data rate.
    std::string linkRate = "1000Mbps"; ///< CSMA channel data rate.
    std::string linkDelay = "0.01ms";  ///< CSMA channel one-way propagation delay.
    uint32_t clientIndex = 0;          ///< Index of the sending host.
    uint32_t serverIndex = 1;          ///< Index of the receiving host.
    uint16_t serverPort = 9093;        ///< UDP destination port on the server.
    uint32_t switchRate = 10000;       ///< P4 switch processing rate in packets per second.
    double flowDuration = 3.0;         ///< Duration of the OnOff flow (s).
    double simDuration = 20.0;         ///< Total simulation time (s).
    int model = 0;          ///< 0 = P4 V1Model switch;  1 = standard NS-3 bridge (baseline).
    bool enablePcap = true; ///< Enable PCAP trace output.

    // Paths resolved via P4SIM_DIR environment variable (portable).
    std::string p4SrcDir = GetP4ExamplePath() + "/simple_v1model";
    std::string p4JsonPath = p4SrcDir + "/simple_v1model.json";
    std::string flowTablePath = p4SrcDir + "/flowtable_0.txt";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat("CsmaTopo");

    // ============================  command line ============================
    CommandLine cmd;
    cmd.AddValue("pktSize", "Application payload size in bytes (default 1000)", pktSize);
    cmd.AddValue("appDataRate", "OnOff application data rate, e.g. 3Mbps", appDataRate);
    cmd.AddValue("linkRate", "CSMA link data rate, e.g. 1000Mbps", linkRate);
    cmd.AddValue("linkDelay", "CSMA link one-way delay, e.g. 0.01ms", linkDelay);
    cmd.AddValue("clientIndex", "Sender host index (default 0)", clientIndex);
    cmd.AddValue("serverIndex", "Receiver host index (default 1)", serverIndex);
    cmd.AddValue("serverPort", "UDP destination port on the server (default 9093)", serverPort);
    cmd.AddValue("switchRate",
                 "P4 switch processing rate in packets per second (default 100000)",
                 switchRate);
    cmd.AddValue("flowDuration", "Duration of the traffic flow (s, default 3)", flowDuration);
    cmd.AddValue("simDuration", "Total simulation duration (s, default 20)", simDuration);
    cmd.AddValue("model", "Switch model: 0=P4 V1Model, 1=NS-3 bridge baseline", model);
    cmd.AddValue("pcap", "Enable PCAP packet capture (true/false)", enablePcap);
    cmd.Parse(argc, argv);

    // Apply runtime-configurable timing after parsing
    client_stop_time = client_start_time + flowDuration;
    sink_stop_time = client_stop_time + 5.0;

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
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(linkRate));
    csma.SetChannelAttribute("Delay", StringValue(linkDelay));

    std::vector<SwitchNodeC_t> switchNodes(switchNum);
    std::vector<HostNodeC_t> hostNodes(hostNum);
    BuildNetworkFromTopology(topoReader, csma, switchNodes, hostNodes);

    // Install the Internet stack
    InternetStackHelper internet;
    internet.Install(terminals);
    internet.Install(switchNode);

    // Assign IP addresses
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    std::vector<Ipv4InterfaceContainer> terminalInterfaces(hostNum);
    std::vector<std::string> hostIpv4(hostNum);

    for (unsigned int i = 0; i < hostNum; i++)
    {
        terminalInterfaces[i] = ipv4.Assign(terminals.Get(i)->GetDevice(0));
        hostIpv4[i] = Uint32IpToHex(terminalInterfaces[i].GetAddress(0).Get());
    }

    LogNodeAddresses(terminals);

    // Bridge or P4 switch configuration
    if (model == 0)
    {
        NS_LOG_INFO("*** Switch model: P4 V1Model  (" << p4JsonPath << ")");
        P4Helper p4Helper;
        p4Helper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
        p4Helper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        p4Helper.SetDeviceAttribute("ChannelType", UintegerValue(0));
        p4Helper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0)); // V1Model = 0
        p4Helper.SetDeviceAttribute(
            "SwitchRate",
            UintegerValue(switchRate)); // 1000Mbps with 1000B packets = 1e6 pps, so 10k pps is a
                                        // safe default for this simple test.

        for (uint32_t i = 0; i < switchNum; ++i)
            p4Helper.Install(switchNode.Get(i), switchNodes[i].switchDevices);
    }
    else
    {
        BridgeHelper bridge;
        for (unsigned int i = 0; i < switchNum; i++)
        {
            bridge.Install(switchNode.Get(i), switchNodes[i].switchDevices);
        }
    }

    // === Configuration for Link: h0 -----> h1 ===
    unsigned int serverI = serverIndex;
    unsigned int clientI = clientIndex;
    uint16_t servPort = serverPort;

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
    ptr_app1->TraceConnectWithoutContext("Tx", MakeBoundCallback(&TxCallback, (uint32_t)pktSize));
    sinkApp1.Get(0)->TraceConnectWithoutContext("Rx",
                                                MakeBoundCallback(&RxCallback, (uint32_t)pktSize));

    // Attach MAC-level traces to the sender NIC
    Ptr<CsmaNetDevice> txDev = DynamicCast<CsmaNetDevice>(terminals.Get(clientI)->GetDevice(0));
    if (txDev)
    {
        txDev->TraceConnectWithoutContext("MacTx",
                                          MakeBoundCallback(&MacTxTrace, std::string("TX-host")));
        txDev->TraceConnectWithoutContext("MacRx",
                                          MakeBoundCallback(&MacRxTrace, std::string("TX-host")));
        txDev->TraceConnectWithoutContext("MacTxDrop",
                                          MakeBoundCallback(&TxDropTrace, std::string("TX-host")));
    }

    // Attach MAC-level traces to the receiver NIC
    Ptr<CsmaNetDevice> rxDev = DynamicCast<CsmaNetDevice>(terminals.Get(serverI)->GetDevice(0));
    if (rxDev)
    {
        rxDev->TraceConnectWithoutContext("MacTx",
                                          MakeBoundCallback(&MacTxTrace, std::string("RX-host")));
        rxDev->TraceConnectWithoutContext("MacRx",
                                          MakeBoundCallback(&MacRxTrace, std::string("RX-host")));
        rxDev->TraceConnectWithoutContext("MacTxDrop",
                                          MakeBoundCallback(&TxDropTrace, std::string("RX-host")));
    }

    if (enablePcap)
    {
        csma.EnablePcapAll("p4-v1model-ipv4-forwarding");
    }

    // Run simulation
    NS_LOG_INFO("Running simulation...");
    unsigned long simulate_start = getTickCount();
    Simulator::Stop(Seconds(simDuration));
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
