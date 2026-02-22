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
 * @file p4-controller-action-profile.cc
 * @brief NS-3 simulation of IPv4 forwarding with P4 action profiles and a runtime controller.
 *
 * Overview
 * --------
 * This example exercises the *action-profile* feature of the P4 behavioural
 * model (BMv2).  An action profile allows the control plane to pre-install a
 * set of reusable action instances (called "members") and then reference them
 * from match-action table entries, enabling fast group-based or ECMP-style
 * forwarding without duplicating action data.
 *
 * A P4Controller is created and all P4SwitchNetDevice instances are registered
 * with it.  At t=1 s the controller schedules a runtime call that:
 *   1. Queries the current member list of "action_profile_0".
 *   2. Adds a new member bound to action "cIngress.foo1" with a sample
 *      destination address (10.10.10.10).
 *   3. Queries the member list again to confirm the addition.
 *
 * Topology (loaded from topo.txt)
 * --------------------------------
 *                       Controller
 *         ┌──────────┐              ┌──────────┐
 *         │ Switch 2 \\            /│ Switch 3 │
 *         └─────┬────┘  \        // └──────┬───┘
 *               │         \    /           │
 *               │           \/             │
 *         ┌─────┴────┐   /    \     ┌──────┴───┐
 *         │ Switch 0 //         \\  │ Switch 1 │
 *     ┌───┼          │             \\          ┼────┐
 *     │   └────────┬─┘              └┬─────────┘    │
 * ┌───┴────┐  ┌────┴───┐       ┌─────┴──┐     ┌─────┴──┐
 * │ host 4 │  │ host 5 │       │ host 6 │     │ host 7 │
 * └────────┘  └────────┘       └────────┘     └────────┘
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
 *   ./ns3 run "p4-controller-action-profile  \
 *       --pktSize=1000                        \
 *       --appDataRate=3Mbps                   \
 *       --linkRate=1000Mbps                   \
 *       --linkDelay=0.01ms                    \
 *       --clientIndex=0                       \
 *       --serverIndex=3                       \
 *       --serverPort=9093                     \
 *       --flowDuration=3                      \
 *       --simDuration=20                      \
 *       --pcap=true                           \
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
#include "ns3/p4-controller.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-topology-reader-helper.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4ControllerActionProfile");

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
    LogComponentEnable("P4ControllerActionProfile", LOG_LEVEL_INFO);
    LogComponentEnable("P4Controller", LOG_LEVEL_INFO);

    // -----------------------------------------------------------------------
    // Simulation parameters – all adjustable via the command line
    // -----------------------------------------------------------------------
    uint16_t pktSize = 1000;           ///< Application payload size (bytes).
    std::string appDataRate = "3Mbps"; ///< OnOff application data rate.
    std::string linkRate = "1000Mbps"; ///< CSMA channel data rate.
    std::string linkDelay = "0.01ms";  ///< CSMA channel one-way propagation delay.
    uint32_t clientIndex = 0;          ///< Index of the sending host.
    uint32_t serverIndex = 3;          ///< Index of the receiving host.
    uint16_t serverPort = 9093;        ///< UDP destination port on the server.
    double flowDuration = 3.0;         ///< Duration of the OnOff flow (s).
    double simDuration = 20.0;         ///< Total simulation time (s).
    bool enablePcap = true;            ///< Enable PCAP trace output.
    int runnum = 0;                    ///< Run index for batch experiments.

    // Paths resolved via P4SIM_DIR environment variable (portable).
    std::string p4SrcDir = GetP4ExamplePath() + "/action_profile";
    std::string p4JsonPath = p4SrcDir + "/action-profile.json";
    std::string flowTableDirPath = p4SrcDir + "/";
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
    cmd.AddValue("serverIndex", "Receiver host index (default 3)", serverIndex);
    cmd.AddValue("serverPort", "UDP destination port on the server (default 9093)", serverPort);
    cmd.AddValue("flowDuration", "Duration of the traffic flow (s, default 3)", flowDuration);
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

    // Validate indices.
    NS_ABORT_MSG_IF(clientIndex >= hostNum, "clientIndex out of range");
    NS_ABORT_MSG_IF(serverIndex >= hostNum, "serverIndex out of range");

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
    // Install P4 switches and attach controller
    // -----------------------------------------------------------------------
    P4Helper p4Helper;
    p4Helper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4Helper.SetDeviceAttribute("ChannelType", UintegerValue(0));
    p4Helper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0)); // v1model

    P4Controller controller;

    for (uint32_t i = 0; i < switchNum; ++i)
    {
        std::string ftPath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        p4Helper.SetDeviceAttribute("FlowTablePath", StringValue(ftPath));
        NS_LOG_INFO("*** Installing P4 switch " << i << ": json=" << p4JsonPath
                                                << "  table=" << ftPath);

        NetDeviceContainer p4Devs = p4Helper.Install(switches.Get(i), switchInfo[i].ports);

        // Register every P4SwitchNetDevice with the controller.
        for (uint32_t j = 0; j < p4Devs.GetN(); ++j)
        {
            Ptr<P4SwitchNetDevice> p4sw = DynamicCast<P4SwitchNetDevice>(p4Devs.Get(j));
            if (!p4sw)
            {
                NS_LOG_WARN("Device " << j << " on switch " << i
                                      << " is not a P4SwitchNetDevice – skipping.");
                continue;
            }
            controller.RegisterSwitch(p4sw);

            // At t=1 s: demo action-profile member management via controller.
            Simulator::Schedule(Seconds(1.0), [j, &controller]() {
                const std::string profile = "action_profile_0";
                const std::string action = "cIngress.foo1";

                // Query current members before adding.
                controller.GetActionProfileMembers(j, profile);

                // Build action data: a single 4-byte destination address field.
                bm::ActionData actionData;
                bm::Data dstAddr(4);     // 4 bytes = 32 bits
                dstAddr.set(0x0a0a0a0a); // 10.10.10.10
                actionData.push_back_action_data(dstAddr);

                bm::ActionProfile::mbr_hdl_t member = 0;
                controller.AddActionProfileMember(j,
                                                  profile,
                                                  action,
                                                  std::move(actionData),
                                                  member);
                NS_LOG_INFO("  Controller: added action-profile member " << member << " on device "
                                                                         << j);

                // Query members after adding to confirm.
                controller.GetActionProfileMembers(j, profile);
            });
        }
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
        csma.EnablePcapAll("p4-controller-action-profile");
        NS_LOG_INFO("PCAP tracing enabled: p4-controller-action-profile-*.pcap");
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
