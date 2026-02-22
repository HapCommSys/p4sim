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
 * @file p4-v1model-ipv4-forwarding.cc
 * @brief NS-3 simulation of basic IPv4 forwarding using the P4 V1Model architecture.
 *
 * Overview
 * --------
 * This example demonstrates IPv4 packet forwarding using a P4 program compiled
 * for the *V1Model* architecture – the original and most widely used P4
 * architecture target for the BMv2 behavioural model.  V1Model defines a
 * simple, fixed pipeline with an ingress parser, ingress match-action pipeline,
 * egress match-action pipeline, and deparser.
 *
 * The simulation can optionally replace the P4 switch with a standard NS-3
 * BridgeHelper to serve as a baseline comparison (--model=1).
 *
 * Topology (loaded from topo.txt)
 * --------------------------------
 *          ┌────────────────┐
 *          │    Switch 0    │
 *          └─▲────────────┬─┘
 *            │            │
 *  ┌─────────┴─┐        ┌─▼─────────┐
 *  │  Host 0   │        │  Host 1   │
 *  └───────────┘        └───────────┘
 *
 * Traffic model
 * -------------
 * A single UDP OnOff flow is sent from host[clientIndex] to host[serverIndex].
 * Throughput (Tx and Rx goodput) is measured by discarding the first
 * kWarmupPackets packets (which include ARP exchanges) and recording
 * byte counts and timestamps for the remaining data packets.
 *
 * Usage
 * -----
 * @code
 *   ./ns3 run "p4-v1model-ipv4-forwarding  \
 *       --pktSize=1000                     \
 *       --appDataRate=3Mbps                \
 *       --linkRate=1000Mbps                \
 *       --linkDelay=0.01ms                 \
 *       --clientIndex=0                    \
 *       --serverIndex=1                    \
 *       --serverPort=9093                  \
 *       --flowDuration=3                   \
 *       --simDuration=20                   \
 *       --model=0                          \
 *       --pcap=true                        \
 *       --runnum=0"
 * @endcode
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

NS_LOG_COMPONENT_DEFINE("P4V1modelIpv4Forwarding");

// ---------------------------------------------------------------------------
// Simulation-wide timing (seconds).  Derived from g_simStartTime so that
// changing g_flowDuration or g_simDuration propagates correctly.
// ---------------------------------------------------------------------------
static unsigned long g_wallClockStart =
    getTickCount(); ///< Wall-clock start for overall runtime measurement.

static double g_simStartTime = 1.0;    ///< Simulation warm-up offset (s).
static double g_sinkStartTime = 0.0;   ///< Filled in main() after cmd parsing.
static double g_clientStartTime = 0.0; ///< Filled in main() after cmd parsing.
static double g_clientStopTime = 0.0;  ///< Filled in main() after cmd parsing.
static double g_sinkStopTime = 0.0;    ///< Filled in main() after cmd parsing.
static double g_simStopTime = 0.0;     ///< Filled in main() after cmd parsing.

// ---------------------------------------------------------------------------
// Per-flow throughput measurement state.
// The first kWarmupPackets packets on each direction are discarded to
// exclude ARP and initial handshake traffic from the goodput calculation.
// ---------------------------------------------------------------------------

/// Number of leading packets (per direction) excluded from throughput stats.
static constexpr int kWarmupPackets = 10;

static bool g_txWarmupDone = false;          ///< True once Tx warmup is complete.
static bool g_rxWarmupDone = false;          ///< True once Rx warmup is complete.
static int g_txWarmupCount = kWarmupPackets; ///< Remaining warmup packets (Tx).
static int g_rxWarmupCount = kWarmupPackets; ///< Remaining warmup packets (Rx).

static double g_firstTxTime = 0.0;  ///< Timestamp of first post-warmup Tx packet (s).
static double g_lastTxTime = 0.0;   ///< Timestamp of last  post-warmup Tx packet (s).
static double g_firstRxTime = 0.0;  ///< Timestamp of first post-warmup Rx packet (s).
static double g_lastRxTime = 0.0;   ///< Timestamp of last  post-warmup Rx packet (s).
static uint64_t g_totalTxBytes = 0; ///< Accumulated payload bytes sent (post-warmup).
static uint64_t g_totalRxBytes = 0; ///< Accumulated payload bytes received (post-warmup).

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

/**
 * @brief Converts an IPv4 address to a zero-padded hexadecimal string.
 *
 * Example: Ipv4Address("10.1.1.1") -> "0x0a010101"
 *
 * @param ipAddr The IPv4 address to convert.
 * @return Hex string prefixed with "0x", e.g. "0x0a010101".
 */
static std::string
IpToHexString(Ipv4Address ipAddr)
{
    std::ostringstream oss;
    uint32_t ip = ipAddr.Get();
    oss << "0x" << std::hex << std::setfill('0') << std::setw(2) << ((ip >> 24) & 0xFF)
        << std::setw(2) << ((ip >> 16) & 0xFF) << std::setw(2) << ((ip >> 8) & 0xFF) << std::setw(2)
        << (ip & 0xFF);
    return oss.str();
}

/**
 * @brief Converts a MAC address to a zero-padded hexadecimal string.
 *
 * Example: Mac48Address("00:11:22:33:44:55") -> "0x001122334455"
 *
 * @param macAddr The MAC address (as ns3::Address) to convert.
 * @return Hex string prefixed with "0x", e.g. "0x001122334455".
 */
static std::string
MacToHexString(Address macAddr)
{
    std::ostringstream oss;
    Mac48Address mac = Mac48Address::ConvertFrom(macAddr);
    uint8_t buf[6];
    mac.CopyTo(buf);
    oss << "0x";
    for (int i = 0; i < 6; ++i)
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buf[i]);
    return oss.str();
}

// ---------------------------------------------------------------------------
// Trace callbacks
// ---------------------------------------------------------------------------

/**
 * @brief Trace callback connected to the OnOff application's "Tx" trace source.
 *
 * The first kWarmupPackets are discarded (typically ARP / handshake traffic).
 * Subsequent packets contribute to the Tx byte counter and update the
 * last-seen Tx timestamp.
 *
 * @param packet The transmitted packet (read-only).
 */
static void
OnTxPacket(Ptr<const Packet> packet)
{
    if (!g_txWarmupDone)
    {
        g_firstTxTime = Simulator::Now().GetSeconds();
        if (--g_txWarmupCount == 0)
            g_txWarmupDone = true;
        return;
    }
    g_totalTxBytes += packet->GetSize();
    g_lastTxTime = Simulator::Now().GetSeconds();
}

/**
 * @brief Trace callback connected to the PacketSink application's "Rx" trace source.
 *
 * The first kWarmupPackets are discarded.  Subsequent packets contribute to
 * the Rx byte counter and update the last-seen Rx timestamp.
 *
 * @param packet  The received packet (read-only).
 * @param addr    Source socket address (unused here).
 */
static void
OnRxPacket(Ptr<const Packet> packet, const Address& addr)
{
    if (!g_rxWarmupDone)
    {
        g_firstRxTime = Simulator::Now().GetSeconds();
        if (--g_rxWarmupCount == 0)
            g_rxWarmupDone = true;
        return;
    }
    g_totalRxBytes += packet->GetSize();
    g_lastRxTime = Simulator::Now().GetSeconds();
}

/**
 * @brief Prints a throughput summary at the end of the simulation.
 *
 * Goodput (Mbps) is computed from the post-warmup byte counters and the
 * elapsed time between the first and last packet in each direction.
 */
static void
PrintThroughputSummary()
{
    double txDuration = g_lastTxTime - g_firstTxTime;
    double rxDuration = g_lastRxTime - g_firstRxTime;

    double txThroughput = (txDuration > 0) ? (g_totalTxBytes * 8.0) / (txDuration * 1e6) : 0.0;
    double rxThroughput = (rxDuration > 0) ? (g_totalRxBytes * 8.0) / (rxDuration * 1e6) : 0.0;

    std::cout << "\n======================================" << "\nFinal Simulation Results:"
              << "\n  Tx window : [" << g_firstTxTime << " s, " << g_lastTxTime << " s]"
              << "\n  Rx window : [" << g_firstRxTime << " s, " << g_lastRxTime << " s]"
              << "\n  Total Tx  : " << g_totalTxBytes << " bytes  -> " << txThroughput << " Mbps"
              << "\n  Total Rx  : " << g_totalRxBytes << " bytes  -> " << rxThroughput << " Mbps"
              << "\n======================================\n";
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4V1modelIpv4Forwarding", LOG_LEVEL_INFO);
    // Uncomment for verbose switch debug output:
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
    double flowDuration = 3.0;         ///< Duration of the OnOff flow (s).
    double simDuration = 20.0;         ///< Total simulation time (s).
    int model = 0;          ///< 0 = P4 V1Model switch;  1 = standard NS-3 bridge (baseline).
    bool enablePcap = true; ///< Enable PCAP trace output.
    int runnum = 0;         ///< Run index for batch experiments.

    // Paths resolved via P4SIM_DIR environment variable (portable).
    std::string p4SrcDir = GetP4ExamplePath() + "/simple_v1model";
    std::string p4JsonPath = p4SrcDir + "/simple_v1model.json";
    std::string flowTablePath = p4SrcDir + "/flowtable_0.txt";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat = "CsmaTopo";

    // -----------------------------------------------------------------------
    // Command-line interface
    // -----------------------------------------------------------------------
    CommandLine cmd;
    cmd.AddValue("pktSize", "Application payload size in bytes (default 1000)", pktSize);
    cmd.AddValue("appDataRate", "OnOff application data rate, e.g. 3Mbps", appDataRate);
    cmd.AddValue("linkRate", "CSMA link data rate, e.g. 1000Mbps", linkRate);
    cmd.AddValue("linkDelay", "CSMA link one-way delay, e.g. 0.01ms", linkDelay);
    cmd.AddValue("clientIndex", "Sender host index (default 0)", clientIndex);
    cmd.AddValue("serverIndex", "Receiver host index (default 1)", serverIndex);
    cmd.AddValue("serverPort", "UDP destination port on the server (default 9093)", serverPort);
    cmd.AddValue("flowDuration", "Duration of the traffic flow (s, default 3)", flowDuration);
    cmd.AddValue("simDuration", "Total simulation duration (s, default 20)", simDuration);
    cmd.AddValue("model", "Switch model: 0=P4 V1Model, 1=NS-3 bridge baseline", model);
    cmd.AddValue("pcap", "Enable PCAP packet capture (true/false)", enablePcap);
    cmd.AddValue("runnum", "Run index used for batch experiments", runnum);
    cmd.Parse(argc, argv);

    // Derived timing schedule.
    g_sinkStartTime = g_simStartTime + 1.0;
    g_clientStartTime = g_sinkStartTime + 1.0;
    g_clientStopTime = g_clientStartTime + flowDuration;
    g_sinkStopTime = g_clientStopTime + 5.0;
    g_simStopTime = g_sinkStopTime + std::max(5.0, simDuration - g_sinkStopTime);

    // -----------------------------------------------------------------------
    // Build topology from file
    // -----------------------------------------------------------------------
    P4TopologyReaderHelper p4TopoHelper;
    p4TopoHelper.SetFileName(topoInput);
    p4TopoHelper.SetFileType(topoFormat);
    NS_LOG_INFO("*** Reading topology: " << topoInput << " (format: " << topoFormat << ")");

    Ptr<P4TopologyReader> topoReader = p4TopoHelper.GetTopologyReader();

    if (topoReader->LinksSize() == 0)
    {
        NS_LOG_ERROR("Topology file contains no links. Aborting.");
        return -1;
    }

    NodeContainer hosts = topoReader->GetHostNodeContainer();
    NodeContainer switches = topoReader->GetSwitchNodeContainer();

    const uint32_t hostNum = hosts.GetN();
    const uint32_t switchNum = switches.GetN();
    NS_LOG_INFO("*** Hosts: " << hostNum << "  Switches: " << switchNum);

    // Validate indices.
    NS_ABORT_MSG_IF(clientIndex >= hostNum, "clientIndex out of range");
    NS_ABORT_MSG_IF(serverIndex >= hostNum, "serverIndex out of range");

    // -----------------------------------------------------------------------
    // Install CSMA links
    // -----------------------------------------------------------------------
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(linkRate));
    csma.SetChannelAttribute("Delay", StringValue(linkDelay));

    // For this simple two-host topology the switch device and host device
    // containers are accumulated in order and later used as a flat list.
    NetDeviceContainer switchDevices;
    NetDeviceContainer hostDevices;

    for (auto iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); ++iter)
    {
        NetDeviceContainer link =
            csma.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

        char fromType = iter->GetFromType();
        char toType = iter->GetToType();

        if (fromType == 's' && toType == 's')
        {
            switchDevices.Add(link.Get(0));
            switchDevices.Add(link.Get(1));
        }
        else if (fromType == 's' && toType == 'h')
        {
            switchDevices.Add(link.Get(0));
            hostDevices.Add(link.Get(1));
        }
        else if (fromType == 'h' && toType == 's')
        {
            hostDevices.Add(link.Get(0));
            switchDevices.Add(link.Get(1));
        }
        else
        {
            NS_LOG_ERROR("Unrecognised link type '" << fromType << "'-'" << toType << "'.");
            return -1;
        }
    }

    // -----------------------------------------------------------------------
    // Internet stack & IP address assignment
    // -----------------------------------------------------------------------
    InternetStackHelper internet;
    internet.Install(hosts);
    internet.Install(switches);

    Ipv4AddressHelper ipv4Helper;
    ipv4Helper.SetBase("10.1.1.0", "255.255.255.0");

    std::vector<Ipv4InterfaceContainer> hostIfaces(hostNum);
    std::vector<std::string> hostIpHex(hostNum);

    for (uint32_t i = 0; i < hostNum; ++i)
    {
        hostIfaces[i] = ipv4Helper.Assign(hosts.Get(i)->GetDevice(0));
        hostIpHex[i] = Uint32IpToHex(hostIfaces[i].GetAddress(0).Get());
    }

    // Print IP / MAC summary for each host.
    NS_LOG_INFO("--- Host IP / MAC summary ---");
    for (uint32_t i = 0; i < hosts.GetN(); ++i)
    {
        Ptr<Node> node = hosts.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        Ipv4Address ipAddr = ipv4->GetAddress(1, 0).GetLocal();
        Mac48Address mac = Mac48Address::ConvertFrom(node->GetDevice(0)->GetAddress());

        NS_LOG_INFO("  Host " << i << ": IP=" << ipAddr << " (" << IpToHexString(ipAddr)
                              << ")  MAC=" << mac << " (" << MacToHexString(mac) << ")");
    }

    // -----------------------------------------------------------------------
    // Install switch (P4 V1Model or NS-3 bridge)
    // -----------------------------------------------------------------------
    if (model == 0)
    {
        NS_LOG_INFO("*** Switch model: P4 V1Model  (" << p4JsonPath << ")");
        P4Helper p4Helper;
        p4Helper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
        p4Helper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        p4Helper.SetDeviceAttribute("ChannelType", UintegerValue(0));
        p4Helper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0)); // V1Model = 0

        for (uint32_t i = 0; i < switchNum; ++i)
            p4Helper.Install(switches.Get(i), switchDevices);
    }
    else
    {
        NS_LOG_INFO("*** Switch model: NS-3 bridge (baseline)");
        BridgeHelper bridge;
        for (uint32_t i = 0; i < switchNum; ++i)
            bridge.Install(switches.Get(i), switchDevices);
    }

    // -----------------------------------------------------------------------
    // Application layer (single UDP OnOff flow)
    // -----------------------------------------------------------------------
    Ptr<Ipv4> srvIpv4 = hosts.Get(serverIndex)->GetObject<Ipv4>();
    Ipv4Address srvAddr = srvIpv4->GetAddress(1, 0).GetLocal();
    InetSocketAddress dst(srvAddr, serverPort);

    // Packet sink on server.
    PacketSinkHelper sink("ns3::UdpSocketFactory", dst);
    ApplicationContainer sinkApps = sink.Install(hosts.Get(serverIndex));
    sinkApps.Start(Seconds(g_sinkStartTime));
    sinkApps.Stop(Seconds(g_sinkStopTime));

    // OnOff source on client.
    OnOffHelper onoff("ns3::UdpSocketFactory", dst);
    onoff.SetAttribute("PacketSize", UintegerValue(pktSize));
    onoff.SetAttribute("DataRate", StringValue(appDataRate));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer srcApps = onoff.Install(hosts.Get(clientIndex));
    srcApps.Start(Seconds(g_clientStartTime));
    srcApps.Stop(Seconds(g_clientStopTime));

    // Connect throughput-measurement trace sources.
    DynamicCast<OnOffApplication>(hosts.Get(clientIndex)->GetApplication(0))
        ->TraceConnectWithoutContext("Tx", MakeCallback(&OnTxPacket));
    sinkApps.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&OnRxPacket));

    NS_LOG_INFO("Flow (UDP): host " << clientIndex << " -> host " << serverIndex << " port "
                                    << serverPort);

    // -----------------------------------------------------------------------
    // PCAP tracing
    // -----------------------------------------------------------------------
    if (enablePcap)
    {
        csma.EnablePcapAll("p4-v1model-ipv4-forwarding");
        NS_LOG_INFO("PCAP tracing enabled: p4-v1model-ipv4-forwarding-*.pcap");
    }

    // -----------------------------------------------------------------------
    // Run simulation
    // -----------------------------------------------------------------------
    NS_LOG_INFO("Starting simulation (stop at t=" << g_simStopTime << " s)...");
    unsigned long simWallStart = getTickCount();

    Simulator::Stop(Seconds(g_simStopTime));
    Simulator::Run();
    Simulator::Destroy();

    unsigned long wallEnd = getTickCount();
    NS_LOG_INFO("Simulation wall time : " << wallEnd - simWallStart << " ms");
    NS_LOG_INFO("Total wall time      : " << wallEnd - g_wallClockStart << " ms");

    PrintThroughputSummary();

    return 0;
}
