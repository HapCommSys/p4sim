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
 * Topology (model == 0, P4 new architecture):
 *
 *   host0 ──[SwitchedEthernetChannel port 0]──┐
 *                                              ├── P4SwitchNetDevice (switch)
 *   host1 ──[SwitchedEthernetChannel port 1]──┘
 *
 * Each host has a P4SwitchNetDevice in NIC / passthrough mode.
 * The switch runs a V1model P4 program that does IPv4 LPM forwarding.
 *
 * Topology (model == 1, NS-3 bridge baseline):
 *
 *   host0 ──[CsmaChannel]──┐
 *                           ├── BridgeNetDevice (switch)
 *   host1 ──[CsmaChannel]──┘
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
#include "ns3/p4-switch-net-device.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4V1modelIpv4Forwarding");

unsigned long start = getTickCount();
double global_start_time = 1.0;
double sink_start_time = global_start_time + 1.0;
double client_start_time = sink_start_time + 1.0;
double client_stop_time = client_start_time + 3.0;
double sink_stop_time = client_stop_time + 5.0;
double global_stop_time = sink_stop_time + 5.0;

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

std::string
ConvertIpToHex(Ipv4Address ipAddr)
{
    std::ostringstream hexStream;
    uint32_t ip = ipAddr.Get();
    hexStream << "0x" << std::hex << std::setfill('0') << std::setw(2)
              << ((ip >> 24) & 0xFF) << std::setw(2) << ((ip >> 16) & 0xFF)
              << std::setw(2) << ((ip >> 8) & 0xFF) << std::setw(2) << (ip & 0xFF);
    return hexStream.str();
}

std::string
ConvertMacToHex(Address macAddr)
{
    Mac48Address mac = Mac48Address::ConvertFrom(macAddr);
    uint8_t buffer[6];
    mac.CopyTo(buffer);
    std::ostringstream hexStream;
    hexStream << "0x";
    for (int i = 0; i < 6; ++i)
        hexStream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buffer[i]);
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
        if (firstMacTx) { firstMacTxTime = now; firstMacTx = false; }
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
        if (firstMacRx) { firstMacRxTime = now; firstMacRx = false; }
        lastMacRxTime = now;
        macRxBytes += p->GetSize();
    }
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
        NS_LOG_INFO("Node " << i << ": IP=" << ipAddr << " (" << ConvertIpToHex(ipAddr)
                            << ")  MAC=" << mac << " (" << ConvertMacToHex(mac) << ")");
    }
}

void
TxCallback(uint32_t dataSize, Ptr<const Packet> packet)
{
    if (packet->GetSize() != dataSize) return;
    if (first_packet_send_time_tx == 0.0)
        first_packet_send_time_tx = Simulator::Now().GetSeconds();
    totalTxBytes += packet->GetSize();
    last_packet_send_time_tx = Simulator::Now().GetSeconds();
}

void
RxCallback(uint32_t dataSize, Ptr<const Packet> packet, const Address& addr)
{
    if (packet->GetSize() != dataSize) return;
    if (first_packet_received_time_rx == 0.0)
        first_packet_received_time_rx = Simulator::Now().GetSeconds();
    totalRxBytes += packet->GetSize();
    last_packet_received_time_rx = Simulator::Now().GetSeconds();
}

void
PrintFinalThroughput()
{
    double send_time    = last_packet_send_time_tx - first_packet_send_time_tx;
    double elapsed_time = last_packet_received_time_rx - first_packet_received_time_rx;
    double finalTxThroughput = (send_time > 0)    ? totalTxBytes * 8.0 / (send_time * 1e6)    : 0.0;
    double finalRxThroughput = (elapsed_time > 0) ? totalRxBytes * 8.0 / (elapsed_time * 1e6) : 0.0;
    double pdr = (totalTxBytes > 0) ? (double)totalRxBytes / totalTxBytes * 100.0 : 0.0;

    double macTxTime = lastMacTxTime - firstMacTxTime;
    double macRxTime = lastMacRxTime - firstMacRxTime;
    double macTxTp   = (macTxTime > 0) ? macTxBytes * 8.0 / (macTxTime * 1e6) : 0.0;
    double macRxTp   = (macRxTime > 0) ? macRxBytes * 8.0 / (macRxTime * 1e6) : 0.0;

    std::cout << "======================================\n";
    std::cout << "Final Simulation Results:\n";
    std::cout << "  ** [App Layer]\n";
    std::cout << "  PDR: " << pdr << "%\n";
    std::cout << "  TX: " << totalTxBytes << " bytes  (" << first_packet_send_time_tx
              << "s -> " << last_packet_send_time_tx << "s, elapsed=" << send_time << "s)\n";
    std::cout << "  RX: " << totalRxBytes << " bytes  (" << first_packet_received_time_rx
              << "s -> " << last_packet_received_time_rx << "s, elapsed=" << elapsed_time << "s)\n";
    std::cout << "  TX Throughput: " << finalTxThroughput << " Mbps\n";
    std::cout << "  RX Throughput: " << finalRxThroughput << " Mbps\n";
    std::cout << "  ** [MAC Layer]\n";
    std::cout << "  TX-host MacTx: " << macTxBytes << " bytes  (" << firstMacTxTime
              << "s -> " << lastMacTxTime << "s, elapsed=" << macTxTime << "s)\n";
    std::cout << "  RX-host MacRx: " << macRxBytes << " bytes  (" << firstMacRxTime
              << "s -> " << lastMacRxTime << "s, elapsed=" << macRxTime << "s)\n";
    std::cout << "  MAC TX Throughput: " << macTxTp << " Mbps\n";
    std::cout << "  MAC RX Throughput: " << macRxTp << " Mbps\n";
    std::cout << "======================================\n";
}

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4V1modelIpv4Forwarding", LOG_LEVEL_INFO);

    // -----------------------------------------------------------------------
    // Simulation parameters
    // -----------------------------------------------------------------------
    uint16_t    pktSize      = 1000;
    std::string appDataRate  = "3Mbps";
    std::string linkRate     = "1000Mbps";
    std::string linkDelay    = "0.01ms";
    uint32_t    clientIndex  = 0;
    uint32_t    serverIndex  = 1;
    uint16_t    serverPort   = 9093;
    uint32_t    switchRate   = 10000;
    double      flowDuration = 3.0;
    double      simDuration  = 20.0;
    int         model        = 0;      // 0 = P4 V1Model, 1 = NS-3 bridge baseline
    bool        enablePcap   = false;

    std::string p4SrcDir      = GetP4ExamplePath() + "/simple_v1model";
    std::string p4JsonPath    = p4SrcDir + "/simple_v1model.json";
    std::string flowTablePath = p4SrcDir + "/flowtable_0.txt";

    CommandLine cmd;
    cmd.AddValue("pktSize",      "Application payload size (bytes)",          pktSize);
    cmd.AddValue("appDataRate",  "OnOff application data rate",               appDataRate);
    cmd.AddValue("linkRate",     "Link data rate",                            linkRate);
    cmd.AddValue("linkDelay",    "Link propagation delay",                    linkDelay);
    cmd.AddValue("clientIndex",  "Sender host index",                         clientIndex);
    cmd.AddValue("serverIndex",  "Receiver host index",                       serverIndex);
    cmd.AddValue("serverPort",   "UDP destination port on the server",        serverPort);
    cmd.AddValue("switchRate",   "P4 switch processing rate (pps)",           switchRate);
    cmd.AddValue("flowDuration", "Duration of the traffic flow (s)",          flowDuration);
    cmd.AddValue("simDuration",  "Total simulation duration (s)",             simDuration);
    cmd.AddValue("model",        "Switch model: 0=P4 V1Model, 1=bridge",     model);
    cmd.AddValue("pcap",         "Enable PCAP capture",                       enablePcap);
    cmd.Parse(argc, argv);

    client_stop_time = client_start_time + flowDuration;
    sink_stop_time   = client_stop_time  + 5.0;

    // -----------------------------------------------------------------------
    // Create nodes: 2 hosts + 1 switch
    // -----------------------------------------------------------------------
    NodeContainer terminals;
    terminals.Create(2);

    Ptr<Node> switchNode = CreateObject<Node>();

    NS_LOG_INFO("Hosts: " << terminals.GetN() << "  Switch: 1");

    // -----------------------------------------------------------------------
    // Internet stack on hosts only (switch uses P4 for forwarding)
    // -----------------------------------------------------------------------
    InternetStackHelper internet;
    internet.Install(terminals);

    // -----------------------------------------------------------------------
    // IP address helper (shared between both models)
    // -----------------------------------------------------------------------
    Ipv4AddressHelper ipv4Addr;
    ipv4Addr.SetBase("10.1.1.0", "255.255.255.0");

    std::vector<Ipv4InterfaceContainer> terminalInterfaces(terminals.GetN());
    std::vector<std::string>            hostIpv4(terminals.GetN());

    // -----------------------------------------------------------------------
    // Model 0 – P4 V1Model switch with new NetDevice architecture
    // -----------------------------------------------------------------------
    if (model == 0)
    {
        NS_LOG_INFO("*** Switch model: P4 V1Model (" << p4JsonPath << ")");

        P4Helper p4;
        // Switch device attributes (pipeline mode)
        p4.SetDeviceAttribute("JsonPath",      StringValue(p4JsonPath));
        p4.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        p4.SetDeviceAttribute("P4SwitchArch",  UintegerValue(0)); // V1Model
        p4.SetDeviceAttribute("SwitchRate",    UintegerValue(switchRate));
        // Channel attributes applied to every switch-port link
        p4.SetChannelAttribute("DataRate", StringValue(linkRate));
        p4.SetChannelAttribute("Delay",    StringValue(linkDelay));

        // Install:
        //   devs[0]   = P4SwitchNetDevice on switchNode  (switch / pipeline mode)
        //   devs[1]   = P4SwitchNetDevice on terminals[0] (NIC / passthrough mode)
        //   devs[2]   = P4SwitchNetDevice on terminals[1] (NIC / passthrough mode)
        NetDeviceContainer devs = p4.Install(switchNode, terminals);

        // Assign IP addresses to host NIC devices (devs[1], devs[2], …)
        for (uint32_t i = 0; i < terminals.GetN(); ++i)
        {
            terminalInterfaces[i] = ipv4Addr.Assign(devs.Get(i + 1));
            hostIpv4[i] = Uint32IpToHex(terminalInterfaces[i].GetAddress(0).Get());
        }

        if (enablePcap)
        {
            p4.EnablePcapAll("p4-v1model-ipv4-forwarding");
        }
    }
    // -----------------------------------------------------------------------
    // Model 1 – standard NS-3 bridge (baseline, CSMA links)
    // -----------------------------------------------------------------------
    else
    {
        NS_LOG_INFO("*** Switch model: NS-3 bridge (baseline)");

        CsmaHelper csma;
        csma.SetChannelAttribute("DataRate", StringValue(linkRate));
        csma.SetChannelAttribute("Delay",    StringValue(linkDelay));

        // Create one CSMA link per host, collect the switch-side ports.
        NetDeviceContainer switchPorts;
        for (uint32_t i = 0; i < terminals.GetN(); ++i)
        {
            NodeContainer pair(switchNode, terminals.Get(i));
            NetDeviceContainer link = csma.Install(pair);
            switchPorts.Add(link.Get(0));                    // switch side
            terminalInterfaces[i] = ipv4Addr.Assign(link.Get(1)); // host side
            hostIpv4[i] = Uint32IpToHex(terminalInterfaces[i].GetAddress(0).Get());
        }

        BridgeHelper bridge;
        bridge.Install(switchNode, switchPorts);

        if (enablePcap)
        {
            csma.EnablePcapAll("p4-v1model-ipv4-forwarding-bridge");
        }
    }

    LogNodeAddresses(terminals);

    // -----------------------------------------------------------------------
    // Applications
    // -----------------------------------------------------------------------
    Ptr<Node>     serverNode = terminals.Get(serverIndex);
    Ptr<Ipv4>     serverIpv4 = serverNode->GetObject<Ipv4>();
    Ipv4Address   serverAddr = serverIpv4->GetAddress(1, 0).GetLocal();
    InetSocketAddress dst(serverAddr, serverPort);

    // Packet sink on server
    PacketSinkHelper sink("ns3::UdpSocketFactory", dst);
    ApplicationContainer sinkApp = sink.Install(serverNode);
    sinkApp.Start(Seconds(sink_start_time));
    sinkApp.Stop(Seconds(sink_stop_time));

    // OnOff source on client
    OnOffHelper onOff("ns3::UdpSocketFactory", dst);
    onOff.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff.SetAttribute("DataRate",   StringValue(appDataRate));
    onOff.SetAttribute("OnTime",  StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer clientApp = onOff.Install(terminals.Get(clientIndex));
    clientApp.Start(Seconds(client_start_time));
    clientApp.Stop(Seconds(client_stop_time));

    // -----------------------------------------------------------------------
    // Application-level Tx / Rx traces
    // -----------------------------------------------------------------------
    DynamicCast<OnOffApplication>(terminals.Get(clientIndex)->GetApplication(0))
        ->TraceConnectWithoutContext("Tx", MakeBoundCallback(&TxCallback, (uint32_t)pktSize));
    sinkApp.Get(0)
        ->TraceConnectWithoutContext("Rx", MakeBoundCallback(&RxCallback, (uint32_t)pktSize));

    // -----------------------------------------------------------------------
    // MAC-level traces (only available on CSMA devices in model == 1)
    // -----------------------------------------------------------------------
    if (model == 1)
    {
        Ptr<CsmaNetDevice> txDev =
            DynamicCast<CsmaNetDevice>(terminals.Get(clientIndex)->GetDevice(0));
        if (txDev)
        {
            txDev->TraceConnectWithoutContext(
                "MacTx",    MakeBoundCallback(&MacTxTrace,   std::string("TX-host")));
            txDev->TraceConnectWithoutContext(
                "MacRx",    MakeBoundCallback(&MacRxTrace,   std::string("TX-host")));
            txDev->TraceConnectWithoutContext(
                "MacTxDrop",MakeBoundCallback(&TxDropTrace,  std::string("TX-host")));
        }

        Ptr<CsmaNetDevice> rxDev =
            DynamicCast<CsmaNetDevice>(terminals.Get(serverIndex)->GetDevice(0));
        if (rxDev)
        {
            rxDev->TraceConnectWithoutContext(
                "MacTx",    MakeBoundCallback(&MacTxTrace,   std::string("RX-host")));
            rxDev->TraceConnectWithoutContext(
                "MacRx",    MakeBoundCallback(&MacRxTrace,   std::string("RX-host")));
            rxDev->TraceConnectWithoutContext(
                "MacTxDrop",MakeBoundCallback(&TxDropTrace,  std::string("RX-host")));
        }
    }

    // -----------------------------------------------------------------------
    // Run
    // -----------------------------------------------------------------------
    NS_LOG_INFO("Running simulation for " << simDuration << " s ...");
    unsigned long simulate_start = getTickCount();

    Simulator::Stop(Seconds(simDuration));
    Simulator::Run();
    Simulator::Destroy();

    unsigned long end = getTickCount();
    NS_LOG_INFO("Simulate time: " << end - simulate_start << " ms"
                << "  Total time: " << end - start << " ms"
                << "  Run successfully!");

    PrintFinalThroughput();
    return 0;
}
