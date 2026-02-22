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
 * @file p4-firewall.cc
 * @brief NS-3 simulation of a P4-based stateful firewall.
 *
 * Overview
 * --------
 * This example mirrors the "firewall" exercise from the p4lang/tutorials
 * repository (https://github.com/p4lang/tutorials/tree/master/exercises/firewall).
 * The P4 program implements a basic stateful firewall: traffic initiated from
 * the *internal* network (hosts 4 and 5, connected to Switch 0) is allowed in
 * both directions, while externally-initiated connections destined for the
 * internal network are blocked.
 *
 * Topology (loaded from topo.txt)
 * --------------------------------
 *         ┌──────────┐              ┌──────────┐
 *         │ Switch 2 \\            /│ Switch 3 │
 *         └─────┬────┘  \        // └──────┬───┘
 *               │         \    /           │
 *               │           \/             │
 *         ┌─────┴────┐   /    \     ┌──────┴───┐
 *         │ Switch 0 //         \\  │ Switch 1 │
 *     ┌───┼ firewall │             \\          ┼────┐
 *     │   └────────┬─┘              └┬─────────┘    │
 * ┌───┴────┐  ┌────┴───┐       ┌─────┴──┐     ┌─────┴──┐
 * │ host 4 │  │ host 5 │       │ host 6 │     │ host 7 │
 * └────────┘  └────────┘       └────────┘     └────────┘
 * |----Internal network----|   |------External network-------|
 *
 * Traffic model
 * -------------
 * Three flows are configured:
 *   Flow 1 (TCP):  internal host[0] -> external host[3] on port 9093
 *   Flow 2 (UDP):  external host[3] -> internal host[0] on port 9200
 *                  (should be blocked by firewall once connection is torn down)
 *   Flow 3 (UDP):  external host[1] -> internal host[0] on port 9003
 *
 * Throughput (Tx and Rx goodput) is measured by discarding the first
 * kWarmupPackets packets (which include ARP exchanges) and recording
 * byte counts and timestamps for the remaining data packets.
 *
 * Usage
 * -----
 * @code
 *   ./ns3 run "p4-firewall           \
 *       --pktSize=1000               \
 *       --appDataRate=1Mbps          \
 *       --linkRate=1000Mbps          \
 *       --linkDelay=0.01ms           \
 *       --flowDuration=3             \
 *       --simDuration=20             \
 *       --pcap=true                  \
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

NS_LOG_COMPONENT_DEFINE("P4Firewall");

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
// Per-flow throughput measurement state (flow 1 only – TCP internal->external).
// The first kWarmupPackets packets are discarded to exclude ARP / handshake
// traffic from the goodput calculation.
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
 * @param addr    Source socket address (unused).
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

    std::cout << "\n======================================"
              << "\nFinal Simulation Results (Flow 1 TCP):" << "\n  Tx window : [" << g_firstTxTime
              << " s, " << g_lastTxTime << " s]" << "\n  Rx window : [" << g_firstRxTime << " s, "
              << g_lastRxTime << " s]" << "\n  Total Tx  : " << g_totalTxBytes << " bytes  -> "
              << txThroughput << " Mbps" << "\n  Total Rx  : " << g_totalRxBytes << " bytes  -> "
              << rxThroughput << " Mbps" << "\n======================================\n";
}

// ---------------------------------------------------------------------------
// Per-switch port bookkeeping
// ---------------------------------------------------------------------------

/**
 * @brief Aggregates the net-devices and port-description strings for one P4 switch.
 */
struct SwitchInfo
{
    NetDeviceContainer ports;      ///< All NetDevices attached to this switch.
    std::vector<std::string> tags; ///< Human-readable tag for each port, e.g. "h0", "s1_2".
};

/**
 * @brief Holds the single network device and assigned IP for one host node.
 */
struct HostInfo
{
    NetDeviceContainer device;    ///< The single CSMA NetDevice of this host.
    Ipv4InterfaceContainer iface; ///< Assigned IPv4 interface.
    uint32_t switchIdx;           ///< Index of the switch this host connects to.
    uint32_t switchPort;          ///< Port number on that switch.
    std::string ipHex;            ///< IPv4 address as "0x…" hex string (filled after assignment).
};

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4Firewall", LOG_LEVEL_INFO);

    // -----------------------------------------------------------------------
    // Simulation parameters – all adjustable via the command line
    // -----------------------------------------------------------------------
    uint16_t pktSize = 1000;           ///< Application payload size (bytes).
    std::string appDataRate = "1Mbps"; ///< OnOff application data rate.
    std::string linkRate = "1000Mbps"; ///< CSMA channel data rate.
    std::string linkDelay = "0.01ms";  ///< CSMA channel one-way propagation delay.
    double flowDuration = 3.0;         ///< Duration of each OnOff flow (s).
    double simDuration = 20.0;         ///< Total simulation time (s).
    bool enablePcap = true;            ///< Enable PCAP trace output.
    int runnum = 0;                    ///< Run index for batch experiments.

    // Paths resolved via P4SIM_DIR environment variable (portable).
    std::string p4SrcDir = GetP4ExamplePath() + "/p4_basic";
    std::string p4JsonPath = p4SrcDir + "/p4_basic.json";
    std::string flowTableDirPath = p4SrcDir + "/";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat = "CsmaTopo";

    // -----------------------------------------------------------------------
    // Command-line interface
    // -----------------------------------------------------------------------
    CommandLine cmd;
    cmd.AddValue("pktSize", "Application payload size in bytes (default 1000)", pktSize);
    cmd.AddValue("appDataRate", "OnOff application data rate, e.g. 1Mbps", appDataRate);
    cmd.AddValue("linkRate", "CSMA link data rate, e.g. 1000Mbps", linkRate);
    cmd.AddValue("linkDelay", "CSMA link one-way delay, e.g. 0.01ms", linkDelay);
    cmd.AddValue("flowDuration", "Duration of each traffic flow (s, default 3)", flowDuration);
    cmd.AddValue("simDuration", "Total simulation duration (s, default 20)", simDuration);
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
    topoReader->PrintTopology();

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

    // -----------------------------------------------------------------------
    // Install CSMA links
    // -----------------------------------------------------------------------
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(linkRate));
    csma.SetChannelAttribute("Delay", StringValue(linkDelay));

    std::vector<SwitchInfo> switchInfo(switchNum);
    std::vector<HostInfo> hostInfo(hostNum);

    for (auto iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); ++iter)
    {
        // Per-link overrides from topology file (optional).
        std::string dr, dl;
        if (iter->GetAttributeFailSafe("DataRate", dr))
            csma.SetChannelAttribute("DataRate", StringValue(dr));
        if (iter->GetAttributeFailSafe("Delay", dl))
            csma.SetChannelAttribute("Delay", StringValue(dl));

        uint32_t fromIdx = iter->GetFromIndex();
        uint32_t toIdx = iter->GetToIndex();
        NetDeviceContainer link =
            csma.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

        char fromType = iter->GetFromType();
        char toType = iter->GetToType();

        if (fromType == 's' && toType == 's')
        {
            // Switch-to-switch link
            uint32_t fromPort = switchInfo[fromIdx].ports.GetN();
            uint32_t toPort = switchInfo[toIdx].ports.GetN();

            switchInfo[fromIdx].ports.Add(link.Get(0));
            switchInfo[fromIdx].tags.push_back("s" + UintToString(toIdx) + "_" +
                                               UintToString(toPort));

            switchInfo[toIdx].ports.Add(link.Get(1));
            switchInfo[toIdx].tags.push_back("s" + UintToString(fromIdx) + "_" +
                                             UintToString(fromPort));

            NS_LOG_INFO("  Link: switch " << fromIdx << " <-> switch " << toIdx);
        }
        else if (fromType == 's' && toType == 'h')
        {
            // Switch-to-host link
            uint32_t port = switchInfo[fromIdx].ports.GetN();
            uint32_t hIdx = toIdx - switchNum;

            switchInfo[fromIdx].ports.Add(link.Get(0));
            switchInfo[fromIdx].tags.push_back("h" + UintToString(hIdx));

            hostInfo[hIdx].device.Add(link.Get(1));
            hostInfo[hIdx].switchIdx = fromIdx;
            hostInfo[hIdx].switchPort = port;

            NS_LOG_INFO("  Link: switch " << fromIdx << " -> host " << hIdx);
        }
        else if (fromType == 'h' && toType == 's')
        {
            // Host-to-switch link
            uint32_t port = switchInfo[toIdx].ports.GetN();
            uint32_t hIdx = fromIdx - switchNum;

            switchInfo[toIdx].ports.Add(link.Get(1));
            switchInfo[toIdx].tags.push_back("h" + UintToString(hIdx));

            hostInfo[hIdx].device.Add(link.Get(0));
            hostInfo[hIdx].switchIdx = toIdx;
            hostInfo[hIdx].switchPort = port;

            NS_LOG_INFO("  Link: host " << hIdx << " -> switch " << toIdx);
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

    for (uint32_t i = 0; i < hostNum; ++i)
    {
        hostInfo[i].iface = ipv4Helper.Assign(hosts.Get(i)->GetDevice(0));
        hostInfo[i].ipHex = Uint32IpToHex(hostInfo[i].iface.GetAddress(0).Get());
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
    // Install P4 switches
    // -----------------------------------------------------------------------
    P4Helper p4Helper;
    p4Helper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4Helper.SetDeviceAttribute("ChannelType", UintegerValue(0));
    p4Helper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0)); // v1model

    for (uint32_t i = 0; i < switchNum; ++i)
    {
        std::string ftPath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        p4Helper.SetDeviceAttribute("FlowTablePath", StringValue(ftPath));
        NS_LOG_INFO("*** Installing P4 switch " << i << ": json=" << p4JsonPath
                                                << "  table=" << ftPath);
        p4Helper.Install(switches.Get(i), switchInfo[i].ports);
    }

    // -----------------------------------------------------------------------
    // Application layer
    // -----------------------------------------------------------------------
    // Flow 1 (TCP):  internal host[0] -> external host[3]  port 9093
    {
        uint32_t srvIdx = 3;
        uint32_t cliIdx = 0;
        uint16_t srvPort = 9093;

        Ptr<Ipv4> srvIpv4 = hosts.Get(srvIdx)->GetObject<Ipv4>();
        Ipv4Address srvAddr = srvIpv4->GetAddress(1, 0).GetLocal();
        InetSocketAddress dst(srvAddr, srvPort);

        PacketSinkHelper sink("ns3::TcpSocketFactory", dst);
        ApplicationContainer sinkApps = sink.Install(hosts.Get(srvIdx));
        sinkApps.Start(Seconds(g_sinkStartTime));
        sinkApps.Stop(Seconds(g_sinkStopTime));

        OnOffHelper onoff("ns3::TcpSocketFactory", dst);
        onoff.SetAttribute("PacketSize", UintegerValue(pktSize));
        onoff.SetAttribute("DataRate", StringValue(appDataRate));
        onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        ApplicationContainer srcApps = onoff.Install(hosts.Get(cliIdx));
        srcApps.Start(Seconds(g_clientStartTime));
        srcApps.Stop(Seconds(g_clientStopTime));

        // Connect throughput-measurement trace sources to Flow 1 only.
        DynamicCast<OnOffApplication>(hosts.Get(cliIdx)->GetApplication(0))
            ->TraceConnectWithoutContext("Tx", MakeCallback(&OnTxPacket));
        sinkApps.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&OnRxPacket));

        NS_LOG_INFO("Flow 1 (TCP): host " << cliIdx << " -> host " << srvIdx << " port "
                                          << srvPort);
    }

    // Flow 2 (UDP): external host[3] -> internal host[0]  port 9200
    {
        uint32_t srvIdx = 0;
        uint32_t cliIdx = 3;
        uint16_t srvPort = 9200;

        Ptr<Ipv4> srvIpv4 = hosts.Get(srvIdx)->GetObject<Ipv4>();
        Ipv4Address srvAddr = srvIpv4->GetAddress(1, 0).GetLocal();
        InetSocketAddress dst(srvAddr, srvPort);

        PacketSinkHelper sink("ns3::UdpSocketFactory", dst);
        ApplicationContainer sinkApps = sink.Install(hosts.Get(srvIdx));
        sinkApps.Start(Seconds(g_sinkStartTime));
        sinkApps.Stop(Seconds(g_sinkStopTime));

        OnOffHelper onoff("ns3::UdpSocketFactory", dst);
        onoff.SetAttribute("PacketSize", UintegerValue(pktSize));
        onoff.SetAttribute("DataRate", StringValue(appDataRate));
        onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        ApplicationContainer srcApps = onoff.Install(hosts.Get(cliIdx));
        srcApps.Start(Seconds(g_clientStartTime));
        srcApps.Stop(Seconds(g_clientStopTime));

        NS_LOG_INFO("Flow 2 (UDP): host " << cliIdx << " -> host " << srvIdx << " port " << srvPort
                                          << "  (expected: blocked by firewall)");
    }

    // Flow 3 (UDP): external host[1] -> internal host[0]  port 9003
    {
        uint32_t srvIdx = 0;
        uint32_t cliIdx = 1;
        uint16_t srvPort = 9003;

        Ptr<Ipv4> srvIpv4 = hosts.Get(srvIdx)->GetObject<Ipv4>();
        Ipv4Address srvAddr = srvIpv4->GetAddress(1, 0).GetLocal();
        InetSocketAddress dst(srvAddr, srvPort);

        PacketSinkHelper sink("ns3::UdpSocketFactory", dst);
        ApplicationContainer sinkApps = sink.Install(hosts.Get(srvIdx));
        sinkApps.Start(Seconds(g_sinkStartTime));
        sinkApps.Stop(Seconds(g_sinkStopTime));

        OnOffHelper onoff("ns3::UdpSocketFactory", dst);
        onoff.SetAttribute("PacketSize", UintegerValue(pktSize));
        onoff.SetAttribute("DataRate", StringValue(appDataRate));
        onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        ApplicationContainer srcApps = onoff.Install(hosts.Get(cliIdx));
        srcApps.Start(Seconds(g_clientStartTime));
        srcApps.Stop(Seconds(g_clientStopTime));

        NS_LOG_INFO("Flow 3 (UDP): host " << cliIdx << " -> host " << srvIdx << " port " << srvPort
                                          << "  (expected: blocked by firewall)");
    }

    // -----------------------------------------------------------------------
    // PCAP tracing
    // -----------------------------------------------------------------------
    if (enablePcap)
    {
        csma.EnablePcapAll("p4-firewall");
        NS_LOG_INFO("PCAP tracing enabled: p4-firewall-*.pcap");
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
