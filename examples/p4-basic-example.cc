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
 * @file p4-basic-example.cc
 * @brief NS-3 simulation of basic IPv4 forwarding with P4 switches (no controller).
 *
 * Overview
 * --------
 * This example mirrors the "basic" exercise from the p4lang/tutorials repository
 * (https://github.com/p4lang/tutorials/tree/master/exercises/basic).
 * Unlike p4-basic-controller.cc, the P4 switches here are configured statically
 * via pre-loaded flow tables — no runtime controller is attached.
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
 *   ./ns3 run "p4-basic-example    \
 *       --pktSize=1000             \
 *       --appDataRate=3Mbps        \
 *       --linkRate=1000Mbps        \
 *       --linkDelay=0.01ms         \
 *       --clientIndex=0            \
 *       --serverIndex=3            \
 *       --serverPort=9093          \
 *       --flowDuration=3           \
 *       --simDuration=20           \
 *       --pcap=true                \
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

NS_LOG_COMPONENT_DEFINE("P4BasicExample");

// ---------------------------------------------------------------------------
// Simulation-wide wall-clock reference
// ---------------------------------------------------------------------------
static unsigned long g_wallClockStart =
    getTickCount(); ///< Wall-clock start for runtime measurement.

// ---------------------------------------------------------------------------
// Simulation timeline (seconds) — filled in main() after command-line parsing.
// ---------------------------------------------------------------------------
static double g_simStartTime = 1.0;    ///< Simulation warm-up offset (s).
static double g_sinkStartTime = 0.0;   ///< Time at which the PacketSink starts (s).
static double g_clientStartTime = 0.0; ///< Time at which the OnOff client starts (s).
static double g_clientStopTime = 0.0;  ///< Time at which the OnOff client stops (s).
static double g_sinkStopTime = 0.0;    ///< Time at which the PacketSink stops (s).
static double g_simStopTime = 0.0;     ///< Total simulation stop time (s).

// ---------------------------------------------------------------------------
// Per-flow throughput measurement state.
// The first kWarmupPackets packets on each direction are discarded to
// exclude ARP and other control-plane traffic from the goodput calculation.
// ---------------------------------------------------------------------------

/// Number of leading packets (per direction) excluded from throughput stats.
static constexpr int kWarmupPackets = 10;

static bool g_txWarmupDone = false;          ///< True once Tx warmup is complete.
static bool g_rxWarmupDone = false;          ///< True once Rx warmup is complete.
static int g_txWarmupCount = kWarmupPackets; ///< Remaining Tx warmup packets.
static int g_rxWarmupCount = kWarmupPackets; ///< Remaining Rx warmup packets.

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
 * The first kWarmupPackets packets are discarded (they typically include ARP
 * and other non-data traffic).  Subsequent packets contribute to the Tx byte
 * counter and update the last-seen Tx timestamp.
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
 * @brief Trace callback connected to the PacketSink's "Rx" trace source.
 *
 * Mirrors OnTxPacket(): the first kWarmupPackets received packets are
 * discarded; subsequent packets update the Rx byte counter and timestamp.
 *
 * @param packet The received packet (read-only).
 * @param addr   Sender's address (unused here).
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
 * @brief Prints a formatted throughput summary to stdout after the simulation.
 *
 * Computes Tx and Rx goodput in Mbps from the byte counters and timestamps
 * recorded by OnTxPacket() and OnRxPacket().  A warning is printed if either
 * measurement window is zero (e.g. no post-warmup traffic observed).
 */
static void
PrintThroughputSummary()
{
    double txDuration = g_lastTxTime - g_firstTxTime;
    double rxDuration = g_lastRxTime - g_firstRxTime;

    std::cout << "\n======================================\n";
    std::cout << "  Final Simulation Results\n";
    std::cout << "======================================\n";
    std::cout << "  Tx window : " << g_firstTxTime << " s  ->  " << g_lastTxTime << " s  ("
              << txDuration << " s)\n";
    std::cout << "  Rx window : " << g_firstRxTime << " s  ->  " << g_lastRxTime << " s  ("
              << rxDuration << " s)\n";
    std::cout << "  Total Tx  : " << g_totalTxBytes << " bytes\n";
    std::cout << "  Total Rx  : " << g_totalRxBytes << " bytes\n";

    if (txDuration > 0.0)
        std::cout << "  Tx goodput: " << (g_totalTxBytes * 8.0) / (txDuration * 1e6) << " Mbps\n";
    else
        std::cout << "  Tx goodput: N/A (measurement window is zero)\n";

    if (rxDuration > 0.0)
        std::cout << "  Rx goodput: " << (g_totalRxBytes * 8.0) / (rxDuration * 1e6) << " Mbps\n";
    else
        std::cout << "  Rx goodput: N/A (measurement window is zero)\n";

    std::cout << "======================================\n";
}

// ---------------------------------------------------------------------------
// Topology data structures
// ---------------------------------------------------------------------------

/**
 * @brief Per-switch topology descriptor.
 *
 * Holds the set of NetDevices installed on a switch and a human-readable
 * label for each port (e.g. "h0" or "s1_2"), used when configuring the
 * P4 flow tables.
 */
struct SwitchInfo
{
    NetDeviceContainer devices;          ///< All NetDevices on this switch (one per port).
    std::vector<std::string> portLabels; ///< Port label: "h<hostIdx>" or "s<swIdx>_<portNb>".
};

/**
 * @brief Per-host topology descriptor.
 *
 * Holds the host's NetDevice, its assigned IPv4 interface, and the index /
 * port number of the edge switch it is connected to.
 */
struct HostInfo
{
    NetDeviceContainer device;        ///< The host's single NetDevice.
    Ipv4InterfaceContainer ipv4Iface; ///< The host's IPv4 interface.
    unsigned int uplinkSwitchIdx;     ///< Index of the connected edge switch.
    unsigned int uplinkSwitchPort;    ///< Port number on that switch.
    std::string ipv4Hex;              ///< IPv4 address as hex string (for P4 table use).
};

// ---------------------------------------------------------------------------
// main()
// ---------------------------------------------------------------------------

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4BasicExample", LOG_LEVEL_INFO);

    // -----------------------------------------------------------------------
    // Simulation parameters — all overridable from the command line.
    // -----------------------------------------------------------------------
    int runNumber = 0;                 ///< Loop index when running in batch mode.
    uint16_t pktSize = 1000;           ///< UDP payload size in bytes.
    std::string appDataRate = "3Mbps"; ///< OnOff application data rate.
    std::string linkRate = "1000Mbps"; ///< CSMA link capacity.
    std::string linkDelay = "0.01ms";  ///< CSMA link propagation delay.
    bool enablePcap = true;            ///< Whether to write PCAP trace files.
    uint32_t clientIndex = 0;          ///< Index of the sending host.
    uint32_t serverIndex = 3;          ///< Index of the receiving host.
    uint16_t serverPort = 9093;        ///< UDP destination port.
    double flowDuration = 3.0;         ///< Duration of the OnOff flow in seconds.
    double simDuration = 20.0;         ///< Total simulation duration (s).

    // P4 program / topology paths (use P4SIM_DIR env var for portability).
    std::string p4SrcDir = GetP4ExamplePath() + "/p4_basic";
    std::string p4JsonPath = p4SrcDir + "/p4_basic.json";
    std::string flowTableDir = p4SrcDir + "/";
    std::string topoFile = p4SrcDir + "/topo.txt";
    std::string topoFormat = "CsmaTopo";

    // -----------------------------------------------------------------------
    // Command-line interface
    // -----------------------------------------------------------------------
    CommandLine cmd;
    cmd.AddValue("runnum", "Batch run index (used when sweeping parameters)", runNumber);
    cmd.AddValue("pktSize", "UDP payload size in bytes [default: 1000]", pktSize);
    cmd.AddValue("appDataRate", "OnOff application data rate [default: 3Mbps]", appDataRate);
    cmd.AddValue("linkRate", "CSMA link capacity [default: 1000Mbps]", linkRate);
    cmd.AddValue("linkDelay", "CSMA link propagation delay [default: 0.01ms]", linkDelay);
    cmd.AddValue("clientIndex", "Index of the UDP sender host [default: 0]", clientIndex);
    cmd.AddValue("serverIndex", "Index of the UDP receiver host [default: 3]", serverIndex);
    cmd.AddValue("serverPort", "UDP destination port [default: 9093]", serverPort);
    cmd.AddValue("flowDuration",
                 "Duration of the OnOff flow in seconds [default: 3]",
                 flowDuration);
    cmd.AddValue("simDuration", "Total simulation duration in seconds [default: 20]", simDuration);
    cmd.AddValue("p4Json", "Path to the compiled P4 JSON program", p4JsonPath);
    cmd.AddValue("flowTableDir", "Directory containing flowtable_<i>.txt files", flowTableDir);
    cmd.AddValue("topoFile", "Path to the topology description file", topoFile);
    cmd.AddValue("pcap", "Enable PCAP tracing [default: true]", enablePcap);
    cmd.Parse(argc, argv);

    // -----------------------------------------------------------------------
    // Derive simulation timeline from parsed parameters.
    // Layout: [0 -- simStart -- sinkStart -- clientStart
    //          -- clientStop -- sinkStop -- simStop]
    // -----------------------------------------------------------------------
    g_sinkStartTime = g_simStartTime + 1.0;
    g_clientStartTime = g_sinkStartTime + 1.0;
    g_clientStopTime = g_clientStartTime + flowDuration;
    g_sinkStopTime = g_clientStopTime + 5.0;
    g_simStopTime = std::max(simDuration, g_sinkStopTime + 5.0);

    NS_LOG_INFO("Simulation timeline:" << "  sink [" << g_sinkStartTime << "," << g_sinkStopTime
                                       << "] s" << "  client [" << g_clientStartTime << ","
                                       << g_clientStopTime << "] s" << "  stop at " << g_simStopTime
                                       << " s");

    // -----------------------------------------------------------------------
    // Load topology
    // -----------------------------------------------------------------------
    P4TopologyReaderHelper topoHelper;
    topoHelper.SetFileName(topoFile);
    topoHelper.SetFileType(topoFormat);
    NS_LOG_INFO("Reading topology from: " << topoFile << " (format: " << topoFormat << ")");

    Ptr<P4TopologyReader> topoReader = topoHelper.GetTopologyReader();
    topoReader->PrintTopology();

    if (topoReader->LinksSize() == 0)
    {
        NS_LOG_ERROR("Topology file contains no links. Aborting.");
        return -1;
    }

    NodeContainer hosts = topoReader->GetHostNodeContainer();
    NodeContainer switches = topoReader->GetSwitchNodeContainer();

    const unsigned int hostNum = hosts.GetN();
    const unsigned int switchNum = switches.GetN();
    NS_LOG_INFO("Topology: " << hostNum << " host(s), " << switchNum << " switch(es)");

    // Validate user-supplied indices.
    NS_ABORT_MSG_IF(clientIndex >= hostNum,
                    "clientIndex (" << clientIndex << ") >= hostNum (" << hostNum << ")");
    NS_ABORT_MSG_IF(serverIndex >= hostNum,
                    "serverIndex (" << serverIndex << ") >= hostNum (" << hostNum << ")");

    // -----------------------------------------------------------------------
    // Build CSMA links from the topology file
    // -----------------------------------------------------------------------
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(linkRate));
    csma.SetChannelAttribute("Delay", TimeValue(Time(linkDelay)));

    std::vector<SwitchInfo> switchInfos(switchNum);
    std::vector<HostInfo> hostInfos(hostNum);

    std::string dataRate, delay;
    for (auto iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); ++iter)
    {
        // Per-link overrides from the topology file (optional).
        if (iter->GetAttributeFailSafe("DataRate", dataRate))
            csma.SetChannelAttribute("DataRate", StringValue(dataRate));
        if (iter->GetAttributeFailSafe("Delay", delay))
            csma.SetChannelAttribute("Delay", StringValue(delay));

        unsigned int fromIdx = iter->GetFromIndex();
        unsigned int toIdx = iter->GetToIndex();
        NetDeviceContainer link =
            csma.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

        char fromType = iter->GetFromType();
        char toType = iter->GetToType();

        if (fromType == 's' && toType == 's')
        {
            // Switch-to-switch link: record port on both ends.
            NS_LOG_INFO("Link: switch[" << fromIdx << "] <-> switch[" << toIdx << "]"
                                        << "  rate=" << dataRate << "  delay=" << delay);

            unsigned int fromPort = switchInfos[fromIdx].devices.GetN();
            unsigned int toPort = switchInfos[toIdx].devices.GetN();

            switchInfos[fromIdx].devices.Add(link.Get(0));
            switchInfos[fromIdx].portLabels.push_back("s" + UintToString(toIdx) + "_" +
                                                      UintToString(toPort));

            switchInfos[toIdx].devices.Add(link.Get(1));
            switchInfos[toIdx].portLabels.push_back("s" + UintToString(fromIdx) + "_" +
                                                    UintToString(fromPort));
        }
        else if (fromType == 's' && toType == 'h')
        {
            // Switch-to-host link.
            unsigned int hostLocalIdx = toIdx - switchNum;
            NS_LOG_INFO("Link: switch[" << fromIdx << "] -> host[" << hostLocalIdx << "]"
                                        << "  rate=" << dataRate << "  delay=" << delay);

            unsigned int fromPort = switchInfos[fromIdx].devices.GetN();
            switchInfos[fromIdx].devices.Add(link.Get(0));
            switchInfos[fromIdx].portLabels.push_back("h" + UintToString(hostLocalIdx));

            hostInfos[hostLocalIdx].device.Add(link.Get(1));
            hostInfos[hostLocalIdx].uplinkSwitchIdx = fromIdx;
            hostInfos[hostLocalIdx].uplinkSwitchPort = fromPort;
        }
        else if (fromType == 'h' && toType == 's')
        {
            // Host-to-switch link.
            unsigned int hostLocalIdx = fromIdx - switchNum;
            NS_LOG_INFO("Link: host[" << hostLocalIdx << "] -> switch[" << toIdx << "]"
                                      << "  rate=" << dataRate << "  delay=" << delay);

            unsigned int toPort = switchInfos[toIdx].devices.GetN();
            switchInfos[toIdx].devices.Add(link.Get(1));
            switchInfos[toIdx].portLabels.push_back("h" + UintToString(hostLocalIdx));

            hostInfos[hostLocalIdx].device.Add(link.Get(0));
            hostInfos[hostLocalIdx].uplinkSwitchIdx = toIdx;
            hostInfos[hostLocalIdx].uplinkSwitchPort = toPort;
        }
        else
        {
            NS_FATAL_ERROR("Unsupported link type: '" << fromType << "' <-> '" << toType << "'");
        }
    }

    // -----------------------------------------------------------------------
    // Install Internet stacks and assign IPv4 addresses to hosts
    // -----------------------------------------------------------------------
    InternetStackHelper internet;
    internet.Install(hosts);
    internet.Install(switches);

    // All hosts share a single /24 subnet (10.1.1.0/24).
    Ipv4AddressHelper ipv4Helper;
    ipv4Helper.SetBase("10.1.1.0", "255.255.255.0");

    for (unsigned int i = 0; i < hostNum; i++)
    {
        hostInfos[i].ipv4Iface = ipv4Helper.Assign(hosts.Get(i)->GetDevice(0));
        hostInfos[i].ipv4Hex = Uint32IpToHex(hostInfos[i].ipv4Iface.GetAddress(0).Get());
    }

    // Print IP / MAC summary for debugging.
    NS_LOG_INFO("Host IP and MAC addresses:");
    for (unsigned int i = 0; i < hostNum; ++i)
    {
        Ptr<Ipv4> ipv4obj = hosts.Get(i)->GetObject<Ipv4>();
        Ipv4Address ipAddr = ipv4obj->GetAddress(1, 0).GetLocal();
        Mac48Address mac = Mac48Address::ConvertFrom(hosts.Get(i)->GetDevice(0)->GetAddress());

        NS_LOG_INFO("  host[" << i << "]" << "  IP=" << ipAddr << " (" << IpToHexString(ipAddr)
                              << ")" << "  MAC=" << mac << " (" << MacToHexString(mac) << ")"
                              << "  uplink=switch[" << hostInfos[i].uplinkSwitchIdx << "] port "
                              << hostInfos[i].uplinkSwitchPort << ")");
    }

    // -----------------------------------------------------------------------
    // Install P4 switches (static flow tables — no runtime controller)
    // -----------------------------------------------------------------------
    P4Helper p4Helper;
    p4Helper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4Helper.SetDeviceAttribute("ChannelType", UintegerValue(0));
    p4Helper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));

    for (unsigned int i = 0; i < switchNum; i++)
    {
        std::string flowTablePath = flowTableDir + "flowtable_" + std::to_string(i) + ".txt";
        p4Helper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));

        NS_LOG_INFO("Installing P4 switch[" << i << "]:" << "\n  JSON      : " << p4JsonPath
                                            << "\n  FlowTable : " << flowTablePath);

        p4Helper.Install(switches.Get(i), switchInfos[i].devices);
    }

    // -----------------------------------------------------------------------
    // Install UDP OnOff / PacketSink applications
    // -----------------------------------------------------------------------

    // Retrieve server IPv4 address from the pre-assigned interface.
    Ipv4Address serverAddr = hosts.Get(serverIndex)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();
    InetSocketAddress serverEndpoint(serverAddr, serverPort);

    NS_LOG_INFO("Flow: host[" << clientIndex << "] -> host[" << serverIndex << "]"
                              << "  dst=" << serverAddr << ":" << serverPort
                              << "  rate=" << appDataRate << "  pktSize=" << pktSize << " B");

    // PacketSink (server side)
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", serverEndpoint);
    ApplicationContainer sinkApp = sinkHelper.Install(hosts.Get(serverIndex));
    sinkApp.Start(Seconds(g_sinkStartTime));
    sinkApp.Stop(Seconds(g_sinkStopTime));

    // OnOff application (client side)
    OnOffHelper onOffHelper("ns3::UdpSocketFactory", serverEndpoint);
    onOffHelper.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOffHelper.SetAttribute("DataRate", StringValue(appDataRate));
    onOffHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOffHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer clientApp = onOffHelper.Install(hosts.Get(clientIndex));
    clientApp.Start(Seconds(g_clientStartTime));
    clientApp.Stop(Seconds(g_clientStopTime));

    // Connect throughput measurement trace callbacks.
    DynamicCast<OnOffApplication>(hosts.Get(clientIndex)->GetApplication(0))
        ->TraceConnectWithoutContext("Tx", MakeCallback(&OnTxPacket));
    sinkApp.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&OnRxPacket));

    // -----------------------------------------------------------------------
    // Optional PCAP tracing
    // -----------------------------------------------------------------------
    if (enablePcap)
    {
        csma.EnablePcapAll("p4-basic-example");
        NS_LOG_INFO("PCAP tracing enabled -> p4-basic-example-*.pcap");
    }

    // -----------------------------------------------------------------------
    // Run the simulation
    // -----------------------------------------------------------------------
    NS_LOG_INFO("Starting simulation (stop at t=" << g_simStopTime << " s) ...");
    unsigned long simWallStart = getTickCount();

    Simulator::Stop(Seconds(g_simStopTime));
    Simulator::Run();
    Simulator::Destroy();

    unsigned long wallEnd = getTickCount();
    NS_LOG_INFO("Simulate time : " << (wallEnd - simWallStart) << " ms");
    NS_LOG_INFO("Total runtime : " << (wallEnd - g_wallClockStart) << " ms");

    PrintThroughputSummary();

    return 0;
}
