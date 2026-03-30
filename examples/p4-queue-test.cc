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
 * @file p4-queue-test.cc
 * @brief QoS queuing test using a P4 V1model switch on a P2P topology.
 *
 * Topology
 * --------
 *
 *   Host 0 ──── Switch 0 ──── Host 1
 *   (sender)                (receiver)
 *
 * Three UDP OnOff flows are sent from Host 0 to Host 1 on different
 * destination ports (--port1, --port2, --port3).  The P4 program
 * classifies packets into QoS queues based on the destination port.
 *
 * Usage
 * -----
 * @code
 *   ./ns3 run "p4-queue-test         \
 *       --pktSize=1000               \
 *       --appDataRate1=3Mbps         \
 *       --appDataRate2=4Mbps         \
 *       --appDataRate3=5Mbps         \
 *       --linkRate=1000Mbps          \
 *       --linkDelay=10us             \
 *       --switchRate=1500            \
 *       --queueSize=1000             \
 *       --port1=2000                 \
 *       --port2=3000                 \
 *       --port3=4000                 \
 *       --flowDuration=10            \
 *       --simDuration=20             \
 *       --pcap=true                  \
 *       --runnum=0"
 * @endcode
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

static unsigned long g_wallClockStart = getTickCount();

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

static std::string
ConvertIpToHex(Ipv4Address ipAddr)
{
    std::ostringstream s;
    uint32_t ip = ipAddr.Get();
    s << "0x" << std::hex << std::setfill('0') << std::setw(2) << ((ip >> 24) & 0xFF)
      << std::setw(2) << ((ip >> 16) & 0xFF) << std::setw(2) << ((ip >> 8) & 0xFF) << std::setw(2)
      << (ip & 0xFF);
    return s.str();
}

static std::string
ConvertMacToHex(Address macAddr)
{
    uint8_t buf[6];
    Mac48Address::ConvertFrom(macAddr).CopyTo(buf);
    std::ostringstream s;
    s << "0x";
    for (int i = 0; i < 6; ++i)
        s << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buf[i]);
    return s.str();
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4QueueTest", LOG_LEVEL_INFO);

    // ---- tuneable parameters ----
    uint16_t pktSize = 1000;            // bytes per UDP payload
    std::string appDataRate1 = "3Mbps"; // flow 1 (port1)
    std::string appDataRate2 = "4Mbps"; // flow 2 (port2)
    std::string appDataRate3 = "5Mbps"; // flow 3 (port3)
    std::string linkRate = "1000Mbps";  // P2P link data rate
    std::string linkDelay = "10us";     // P2P link propagation delay
    uint32_t switchRate = 1500;         // switch processing rate (pps)
    uint32_t queueSize = 1000;          // total queue buffer (packets)
    uint16_t port1 = 2000;              // UDP dst port for flow 1
    uint16_t port2 = 3000;              // UDP dst port for flow 2
    uint16_t port3 = 4000;              // UDP dst port for flow 3
    uint32_t serverIndex = 1;           // host index acting as receiver
    uint32_t clientIndex = 0;           // host index acting as sender
    double flowDuration = 10.0;         // OnOff active duration (s)
    double simDuration = 20.0;          // total simulation time (s)
    bool enablePcap = true;

    // P4 program paths
    std::string p4SrcDir = GetP4ExamplePath() + "/qos";
    std::string p4JsonPath = p4SrcDir + "/qos.json";
    std::string flowTablePath = p4SrcDir + "/flowtable_0.txt";
    std::string topoInput = p4SrcDir + "/topo.txt";

    // ---- command line ----
    CommandLine cmd;
    cmd.AddValue("pktSize", "UDP payload size in bytes", pktSize);
    cmd.AddValue("appDataRate1", "OnOff data rate for flow 1 (port1)", appDataRate1);
    cmd.AddValue("appDataRate2", "OnOff data rate for flow 2 (port2)", appDataRate2);
    cmd.AddValue("appDataRate3", "OnOff data rate for flow 3 (port3)", appDataRate3);
    cmd.AddValue("linkRate", "P2P link data rate", linkRate);
    cmd.AddValue("linkDelay", "P2P link propagation delay", linkDelay);
    cmd.AddValue("switchRate", "Switch processing rate in packets per second", switchRate);
    cmd.AddValue("queueSize", "Total queue buffer size in packets", queueSize);
    cmd.AddValue("port1", "UDP destination port for flow 1", port1);
    cmd.AddValue("port2", "UDP destination port for flow 2", port2);
    cmd.AddValue("port3", "UDP destination port for flow 3", port3);
    cmd.AddValue("serverIndex", "Host index acting as UDP receiver", serverIndex);
    cmd.AddValue("clientIndex", "Host index acting as UDP sender", clientIndex);
    cmd.AddValue("flowDuration", "Duration of each OnOff flow (s)", flowDuration);
    cmd.AddValue("simDuration", "Total simulation duration (s)", simDuration);
    cmd.AddValue("pcap", "Enable PCAP tracing", enablePcap);
    cmd.Parse(argc, argv);

    // Derive timing
    const double sinkStart = 0.0;
    const double clientStart = 0.0;
    const double clientStop = clientStart + flowDuration;
    const double sinkStop = clientStop + 5.0;
    const double simStop = std::max(simDuration, sinkStop + 1.0);

    // ============================ topo -> network ============================

    P4TopologyReaderHelper p4TopoHelper;
    p4TopoHelper.SetFileName(topoInput);
    p4TopoHelper.SetFileType("P2PTopo");
    NS_LOG_INFO("Reading topology: " << topoInput);

    Ptr<P4TopologyReader> topoReader = p4TopoHelper.GetTopologyReader();
    if (topoReader->LinksSize() == 0)
    {
        NS_LOG_ERROR("Failed to read topology file: " << topoInput);
        return -1;
    }

    NodeContainer terminals = topoReader->GetHostNodeContainer();
    NodeContainer switchNode = topoReader->GetSwitchNodeContainer();
    const uint32_t hostNum = terminals.GetN();
    const uint32_t switchNum = switchNode.GetN();
    NS_LOG_INFO("Hosts: " << hostNum << "  Switches: " << switchNum);

    // ---- link installation ----
    P4PointToPointHelper p4p2p;
    p4p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate(linkRate)));
    p4p2p.SetChannelAttribute("Delay", TimeValue(Time(linkDelay)));

    NetDeviceContainer hostDevices;
    NetDeviceContainer switchDevices;
    for (auto iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); ++iter)
    {
        NetDeviceContainer link =
            p4p2p.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));
        char from = iter->GetFromType();
        char to = iter->GetToType();
        if (from == 's' && to == 's')
        {
            switchDevices.Add(link.Get(0));
            switchDevices.Add(link.Get(1));
        }
        else if (from == 's' && to == 'h')
        {
            switchDevices.Add(link.Get(0));
            hostDevices.Add(link.Get(1));
        }
        else if (from == 'h' && to == 's')
        {
            hostDevices.Add(link.Get(0));
            switchDevices.Add(link.Get(1));
        }
        else
        {
            NS_ABORT_MSG("Unexpected link type: " << from << "-" << to);
        }
    }

    // ---- IP stack ----
    InternetStackHelper internet;
    internet.Install(terminals);
    internet.Install(switchNode);

    Ipv4AddressHelper ipv4Helper;
    ipv4Helper.SetBase("10.1.1.0", "255.255.255.0");
    for (uint32_t i = 0; i < hostNum; ++i)
        ipv4Helper.Assign(terminals.Get(i)->GetDevice(0));

    // ---- log node addresses ----
    NS_LOG_INFO("Node IP / MAC addresses:");
    for (uint32_t i = 0; i < hostNum; ++i)
    {
        Ptr<Node> node = terminals.Get(i);
        Ipv4Address ipAddr = node->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();
        Mac48Address mac = Mac48Address::ConvertFrom(node->GetDevice(0)->GetAddress());
        NS_LOG_INFO("  Host[" << i << "]  IP=" << ipAddr << " (" << ConvertIpToHex(ipAddr) << ")"
                              << "  MAC=" << mac << " (" << ConvertMacToHex(mac) << ")");
    }

    // ---- P4 switch ----
    NS_LOG_INFO("Configuring P4 switch: " << p4JsonPath << "  switchRate=" << switchRate << " pps"
                                          << "  queueSize=" << queueSize);
    P4Helper p4SwitchHelper;
    p4SwitchHelper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
    p4SwitchHelper.SetDeviceAttribute("EnableTracing", BooleanValue(true));
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(1));  // P2P
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0)); // V1model
    p4SwitchHelper.SetDeviceAttribute("SwitchRate", UintegerValue(switchRate));
    p4SwitchHelper.SetDeviceAttribute("QueueBufferSize", UintegerValue(queueSize));
    for (uint32_t i = 0; i < switchNum; ++i)
        p4SwitchHelper.Install(switchNode.Get(i), switchDevices);

    // ---- retrieve server address ----
    Ipv4Address serverAddr =
        terminals.Get(serverIndex)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();
    NS_LOG_INFO("Server: Host[" << serverIndex << "]  " << serverAddr << "  Client: Host["
                                << clientIndex << "]");

    // ---- helper lambda: install one sink + one OnOff flow ----
    auto installFlow = [&](uint16_t port, const std::string& rate, const std::string& label) {
        InetSocketAddress dst(serverAddr, port);

        PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", dst);
        ApplicationContainer sinkApp = sinkHelper.Install(terminals.Get(serverIndex));
        sinkApp.Start(Seconds(sinkStart));
        sinkApp.Stop(Seconds(sinkStop));

        OnOffHelper onOff("ns3::UdpSocketFactory", dst);
        onOff.SetAttribute("PacketSize", UintegerValue(pktSize));
        onOff.SetAttribute("DataRate", StringValue(rate));
        onOff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onOff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

        ApplicationContainer clientApp = onOff.Install(terminals.Get(clientIndex));
        clientApp.Start(Seconds(clientStart));
        clientApp.Stop(Seconds(clientStop));

        NS_LOG_INFO("  Flow " << label << "  port=" << port << "  rate=" << rate);
    };

    NS_LOG_INFO("Installing flows:");
    installFlow(port1, appDataRate1, "1");
    installFlow(port2, appDataRate2, "2");
    installFlow(port3, appDataRate3, "3");

    // ---- PCAP ----
    if (enablePcap)
        p4p2p.EnablePcapAll("p4-queue-test");

    // ---- run ----
    NS_LOG_INFO("Starting simulation (stop at " << simStop << " s)");
    unsigned long simStart = getTickCount();
    Simulator::Stop(Seconds(simStop));
    Simulator::Run();
    Simulator::Destroy();

    unsigned long wallEnd = getTickCount();
    NS_LOG_INFO("Simulation wall time : " << (wallEnd - simStart) << " ms");
    NS_LOG_INFO("Total wall time      : " << (wallEnd - g_wallClockStart) << " ms");

    return 0;
}
