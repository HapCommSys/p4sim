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
 * @file p4-pna-ipv4-forwarding.cc
 * @brief NS-3 simulation of basic IPv4 forwarding using the P4 PNA architecture.
 *
 * Overview
 * --------
 * This example demonstrates IPv4 packet forwarding using a P4 program compiled
 * for the *Portable NIC Architecture* (PNA).  The PNA NIC in this simulator
 * does not support loading flow-table entries from an external file (the Thrift
 * CLI is not available for PNA), so the forwarding decisions are encoded
 * directly in the P4 program source using "const entries" (see
 * p4src/simple_pna/simple_pna_ipv4.p4).
 *
 * The simulation can optionally replace the P4 switch with a standard NS-3
 * BridgeHelper to serve as a baseline (--model=1).
 *
 * Topology (loaded from topo.txt)
 * --------------------------------
 *          ┌────────────────┐
 *          │    Switch 0    │
 *          └─▲────────────┬─┘
 *            │            │
 *  ┌─────────┴─┐        ┌─▼─────────┐
 *  │  Host 0   │        │  Host 1   │
 *  │ 10.1.1.1  │        │ 10.1.1.2  │
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
 *   ./ns3 run "p4-pna-ipv4-forwarding    \
 *       --pktSize=1000                   \
 *       --appDataRate=3Mbps              \
 *       --clientIndex=0                  \
 *       --serverIndex=1                  \
 *       --serverPort=9093                \
 *       --flowDuration=3                 \
 *       --simDuration=20                 \
 *       --model=0                        \
 *       --pcap=true                      \
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

NS_LOG_COMPONENT_DEFINE("P4PnaIpv4Forwarding");

// ---------------------------------------------------------------------------
// Simulation-wide timing (seconds).
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
static int  g_txWarmupCount = kWarmupPackets; ///< Remaining warmup packets (Tx).
static int  g_rxWarmupCount = kWarmupPackets; ///< Remaining warmup packets (Rx).

static double   g_firstTxTime  = 0.0; ///< Timestamp of first post-warmup Tx packet (s).
static double   g_lastTxTime   = 0.0; ///< Timestamp of last  post-warmup Tx packet (s).
static double   g_firstRxTime  = 0.0; ///< Timestamp of first post-warmup Rx packet (s).
static double   g_lastRxTime   = 0.0; ///< Timestamp of last  post-warmup Rx packet (s).
static uint64_t g_totalTxBytes = 0;   ///< Accumulated payload bytes sent (post-warmup).
static uint64_t g_totalRxBytes = 0;   ///< Accumulated payload bytes received (post-warmup).

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

/** Convert an ns3::Ipv4Address to a 0x-prefixed hex string. */
static std::string
ConvertIpToHex(Ipv4Address ipAddr)
{
    std::ostringstream s;
    uint32_t ip = ipAddr.Get();
    s << "0x" << std::hex << std::setfill('0')
      << std::setw(2) << ((ip >> 24) & 0xFF)
      << std::setw(2) << ((ip >> 16) & 0xFF)
      << std::setw(2) << ((ip >>  8) & 0xFF)
      << std::setw(2) << ( ip        & 0xFF);
    return s.str();
}

/** Convert an ns3::Address (MAC) to a 0x-prefixed hex string. */
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
// Trace callbacks
// ---------------------------------------------------------------------------

static void
TxCallback(Ptr<const Packet> packet)
{
    if (!g_txWarmupDone)
    {
        if (g_txWarmupCount == kWarmupPackets)
            g_firstTxTime = Simulator::Now().GetSeconds();
        if (--g_txWarmupCount == 0)
            g_txWarmupDone = true;
        return;
    }
    g_totalTxBytes += packet->GetSize();
    g_lastTxTime    = Simulator::Now().GetSeconds();
}

static void
RxCallback(Ptr<const Packet> packet, const Address& /*addr*/)
{
    if (!g_rxWarmupDone)
    {
        if (g_rxWarmupCount == kWarmupPackets)
            g_firstRxTime = Simulator::Now().GetSeconds();
        if (--g_rxWarmupCount == 0)
            g_rxWarmupDone = true;
        return;
    }
    g_totalRxBytes += packet->GetSize();
    g_lastRxTime    = Simulator::Now().GetSeconds();
}

// ---------------------------------------------------------------------------
// Results printer
// ---------------------------------------------------------------------------

static void
PrintFinalResults()
{
    double txWindow = g_lastTxTime  - g_firstTxTime;
    double rxWindow = g_lastRxTime  - g_firstRxTime;

    std::cout << "\n======================================\n"
              << "  Final Simulation Results\n"
              << "======================================\n";
    std::cout << "  Tx window : " << g_firstTxTime << " s  ->  " << g_lastTxTime
              << " s  (" << txWindow << " s)\n";
    std::cout << "  Rx window : " << g_firstRxTime << " s  ->  " << g_lastRxTime
              << " s  (" << rxWindow << " s)\n";
    std::cout << "  Total Tx  : " << g_totalTxBytes << " bytes\n";
    std::cout << "  Total Rx  : " << g_totalRxBytes << " bytes\n";

    if (txWindow > 0)
        std::cout << "  Tx goodput: "
                  << (g_totalTxBytes * 8.0) / (txWindow * 1e6) << " Mbps\n";
    else
        std::cout << "  Tx goodput: N/A (measurement window is zero)\n";

    if (rxWindow > 0)
        std::cout << "  Rx goodput: "
                  << (g_totalRxBytes * 8.0) / (rxWindow * 1e6) << " Mbps\n";
    else
        std::cout << "  Rx goodput: N/A (measurement window is zero)\n";

    std::cout << "======================================\n";
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4PnaIpv4Forwarding", LOG_LEVEL_INFO);

    // ---- tuneable parameters ----
    int         runNum        = 0;
    int         model         = 0;      // 0 = P4 PNA switch, 1 = ns-3 BridgeHelper
    uint16_t    pktSize       = 1000;   // bytes per UDP payload
    uint32_t    clientIndex   = 0;
    uint32_t    serverIndex   = 1;
    uint16_t    serverPort    = 9093;
    double      flowDuration  = 3.0;    // s
    double      simDuration   = 20.0;   // s
    std::string appDataRate   = "3Mbps";
    std::string linkRate      = "1000Mbps";
    std::string linkDelay     = "0.01ms";
    bool        enablePcap    = true;

    // P4 program paths — relative to the p4src directory discovered at runtime.
    // The PNA NIC does NOT support external flow-table loading (Thrift CLI is
    // unavailable), so flowTablePath is intentionally left empty.  All
    // forwarding rules are encoded as "const entries" in simple_pna_ipv4.p4.
    std::string p4SrcDir      = GetP4ExamplePath() + "/simple_pna";
    std::string p4JsonPath    = p4SrcDir + "/simple_pna.json";
    std::string flowTablePath = ""; // not used for PNA
    std::string topoInput     = p4SrcDir + "/topo.txt";
    std::string topoFormat    = "CsmaTopo";

    // ---- command line ----
    CommandLine cmd;
    cmd.AddValue("runnum",      "Run index used in loop experiments",          runNum);
    cmd.AddValue("model",       "0 = P4 PNA switch,  1 = ns-3 BridgeHelper",  model);
    cmd.AddValue("pktSize",     "UDP payload size in bytes",                   pktSize);
    cmd.AddValue("appDataRate", "OnOff application data rate",                 appDataRate);
    cmd.AddValue("linkRate",    "CSMA link data rate",                         linkRate);
    cmd.AddValue("linkDelay",   "CSMA link propagation delay",                 linkDelay);
    cmd.AddValue("clientIndex", "Host index acting as UDP sender",             clientIndex);
    cmd.AddValue("serverIndex", "Host index acting as UDP receiver",           serverIndex);
    cmd.AddValue("serverPort",  "UDP destination port",                        serverPort);
    cmd.AddValue("flowDuration","Duration of the OnOff flow (s)",              flowDuration);
    cmd.AddValue("simDuration", "Total simulation duration (s)",               simDuration);
    cmd.AddValue("pcap",        "Enable PCAP tracing",                         enablePcap);
    cmd.Parse(argc, argv);

    // Derive timing from parameters
    g_sinkStartTime   = g_simStartTime + 1.0;
    g_clientStartTime = g_sinkStartTime + 1.0;
    g_clientStopTime  = g_clientStartTime + flowDuration;
    g_sinkStopTime    = g_clientStopTime  + 5.0;
    g_simStopTime     = g_sinkStopTime    + 5.0;

    // ---- topology ----
    P4TopologyReaderHelper p4TopoHelper;
    p4TopoHelper.SetFileName(topoInput);
    p4TopoHelper.SetFileType(topoFormat);
    NS_LOG_INFO("Reading topology: " << topoInput);

    Ptr<P4TopologyReader> topoReader = p4TopoHelper.GetTopologyReader();
    if (topoReader->LinksSize() == 0)
    {
        NS_LOG_ERROR("Failed to read topology file: " << topoInput);
        return -1;
    }

    NodeContainer terminals  = topoReader->GetHostNodeContainer();
    NodeContainer switchNodes = topoReader->GetSwitchNodeContainer();
    const uint32_t hostNum   = terminals.GetN();
    const uint32_t switchNum = switchNodes.GetN();
    NS_LOG_INFO("Hosts: " << hostNum << "  Switches: " << switchNum);

    // ---- link installation ----
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(linkRate));
    csma.SetChannelAttribute("Delay",    TimeValue(Time(linkDelay)));

    NetDeviceContainer hostDevices;
    NetDeviceContainer switchDevices;
    for (auto iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); ++iter)
    {
        NetDeviceContainer link =
            csma.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));
        char from = iter->GetFromType();
        char to   = iter->GetToType();
        if      (from == 's' && to == 's') { switchDevices.Add(link.Get(0)); switchDevices.Add(link.Get(1)); }
        else if (from == 's' && to == 'h') { switchDevices.Add(link.Get(0)); hostDevices.Add(link.Get(1)); }
        else if (from == 'h' && to == 's') { hostDevices.Add(link.Get(0));   switchDevices.Add(link.Get(1)); }
        else { NS_ABORT_MSG("Unexpected link type: " << from << "-" << to); }
    }

    // ---- IP stack ----
    InternetStackHelper internet;
    internet.Install(terminals);
    internet.Install(switchNodes);

    Ipv4AddressHelper ipv4Helper;
    ipv4Helper.SetBase("10.1.1.0", "255.255.255.0");
    for (uint32_t i = 0; i < hostNum; ++i)
        ipv4Helper.Assign(terminals.Get(i)->GetDevice(0));

    // ---- log node addresses ----
    NS_LOG_INFO("Node IP / MAC addresses:");
    for (uint32_t i = 0; i < hostNum; ++i)
    {
        Ptr<Node>    node   = terminals.Get(i);
        Ipv4Address  ipAddr = node->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();
        Mac48Address mac    = Mac48Address::ConvertFrom(node->GetDevice(0)->GetAddress());
        NS_LOG_INFO("  Host[" << i << "]  IP=" << ipAddr
                    << " (" << ConvertIpToHex(ipAddr) << ")"
                    << "  MAC=" << mac
                    << " (" << ConvertMacToHex(mac) << ")");
    }

    // ---- P4 switch or ns-3 bridge ----
    if (model == 0)
    {
        NS_LOG_INFO("Configuring P4 PNA switch: " << p4JsonPath);
        P4Helper p4SwitchHelper;
        p4SwitchHelper.SetDeviceAttribute("JsonPath",      StringValue(p4JsonPath));
        p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        p4SwitchHelper.SetDeviceAttribute("ChannelType",   UintegerValue(0)); // CSMA
        p4SwitchHelper.SetDeviceAttribute("P4SwitchArch",  UintegerValue(2)); // PNA
        for (uint32_t i = 0; i < switchNum; ++i)
            p4SwitchHelper.Install(switchNodes.Get(i), switchDevices);
    }
    else
    {
        NS_LOG_INFO("Configuring ns-3 BridgeHelper (baseline)");
        BridgeHelper bridge;
        for (uint32_t i = 0; i < switchNum; ++i)
            bridge.Install(switchNodes.Get(i), switchDevices);
    }

    // ---- applications ----
    Ptr<Node>      serverNode = terminals.Get(serverIndex);
    Ipv4Address    serverAddr = serverNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();
    InetSocketAddress dst(serverAddr, serverPort);

    // Packet sink (server)
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", dst);
    ApplicationContainer sinkApp = sinkHelper.Install(serverNode);
    sinkApp.Start(Seconds(g_sinkStartTime));
    sinkApp.Stop(Seconds(g_sinkStopTime));

    // OnOff source (client)
    OnOffHelper onOff("ns3::UdpSocketFactory", dst);
    onOff.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff.SetAttribute("DataRate",   StringValue(appDataRate));
    onOff.SetAttribute("OnTime",     StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff.SetAttribute("OffTime",    StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer clientApp = onOff.Install(terminals.Get(clientIndex));
    clientApp.Start(Seconds(g_clientStartTime));
    clientApp.Stop(Seconds(g_clientStopTime));

    // ---- tracing ----
    DynamicCast<OnOffApplication>(clientApp.Get(0))
        ->TraceConnectWithoutContext("Tx", MakeCallback(&TxCallback));
    sinkApp.Get(0)
        ->TraceConnectWithoutContext("Rx", MakeCallback(&RxCallback));

    if (enablePcap)
        csma.EnablePcapAll("p4-pna-ipv4-forwarding");

    // ---- run ----
    NS_LOG_INFO("Starting simulation (stop at " << g_simStopTime << " s)");
    unsigned long simStart = getTickCount();
    Simulator::Stop(Seconds(g_simStopTime));
    Simulator::Run();
    Simulator::Destroy();

    unsigned long wallEnd = getTickCount();
    NS_LOG_INFO("Simulation wall time : " << (wallEnd - simStart) << " ms");
    NS_LOG_INFO("Total wall time      : " << (wallEnd - g_wallClockStart) << " ms");

    PrintFinalResults();
    return 0;
}
