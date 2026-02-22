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
 * @file p4-basic-tunnel.cc
 * @brief NS-3 simulation of P4-based tunneling with two concurrent UDP flows.
 *
 * Overview
 * --------
 * This example mirrors the "basic_tunnel" exercise from the p4lang/tutorials
 * repository (https://github.com/p4lang/tutorials/tree/master/exercises/basic_tunnel).
 * It demonstrates how a custom P4 tunnel header (proto_id + dst_id) can be
 * prepended to IPv4 packets at the source host and stripped at the destination,
 * enabling tunnel-based forwarding independent of the inner IP address.
 *
 * Two independent UDP flows share the same host pair (h0 -> h1):
 *   - Flow 1 (tunnel stream) : port tunnelPort1, rate appDataRate[0].
 *   - Flow 2 (normal stream) : port tunnelPort2, rate appDataRate[1].
 *
 * The tunnel header is injected by a CustomP2PNetDevice installed on every
 * host.  P4 switches use ChannelType=1 (P2P) and are loaded with static
 * flow tables from the basic_tunnel directory.
 *
 * Topology (loaded from topo.txt, P2PTopo format)
 * ------------------------------------------------
 *
 *   h0 --- s0 --- s1 --- h1
 *
 * (Actual topology is defined in topo.txt; the above is the typical case.)
 *
 * Custom tunnel header
 * --------------------
 * The header is inserted at Layer 3 (BEFORE the IPv4 header):
 * @code
 *   Field    | Width | Example value
 *   ---------+-------+--------------
 *   proto_id |  16 b | 0x0800 (IPv4)
 *   dst_id   |  16 b | 0x0022
 * @endcode
 *
 * Throughput measurement
 * ----------------------
 * Unlike the basic examples, this file does NOT skip warmup packets — all
 * transmitted/received bytes for each flow are counted from the start.
 * Per-flow byte counters (g_txBytes1/2, g_rxBytes1/2) are reported
 * separately and as a combined total in PrintThroughputSummary().
 *
 * Usage
 * -----
 * @code
 *   ./ns3 run "p4-basic-tunnel       \
 *       --pktSize=1000               \
 *       --flowRate1=1Mbps            \
 *       --flowRate2=4Mbps            \
 *       --linkRate=100Mbps           \
 *       --linkDelay=1ms              \
 *       --clientIndex=0              \
 *       --serverIndex=1              \
 *       --tunnelPort1=12000          \
 *       --tunnelPort2=1301           \
 *       --flowDuration=3             \
 *       --simDuration=20             \
 *       --pcap=true                  \
 *       --runnum=0"
 * @endcode
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

// ---------------------------------------------------------------------------
// Simulation-wide wall-clock reference
// ---------------------------------------------------------------------------
static unsigned long g_wallClockStart =
    getTickCount(); ///< Wall-clock start for runtime measurement.

// ---------------------------------------------------------------------------
// Simulation timeline (seconds) — filled in main() after command-line parsing.
// ---------------------------------------------------------------------------
static double g_simStartTime = 1.0;    ///< Simulation warm-up offset (s).
static double g_sinkStartTime = 0.0;   ///< Time at which PacketSink applications start (s).
static double g_clientStartTime = 0.0; ///< Time at which OnOff clients start (s).
static double g_clientStopTime = 0.0;  ///< Time at which OnOff clients stop (s).
static double g_sinkStopTime = 0.0;    ///< Time at which PacketSink applications stop (s).
static double g_simStopTime = 0.0;     ///< Total simulation stop time (s).

// ---------------------------------------------------------------------------
// Per-flow throughput measurement state (two independent flows).
// Timestamps shared across both flows (last seen wins).
// ---------------------------------------------------------------------------
static double g_firstTxTime = 0.0; ///< Timestamp of first Tx packet across both flows (s).
static double g_lastTxTime = 0.0;  ///< Timestamp of last  Tx packet across both flows (s).
static double g_firstRxTime = 0.0; ///< Timestamp of first Rx packet across both flows (s).
static double g_lastRxTime = 0.0;  ///< Timestamp of last  Rx packet across both flows (s).

static uint64_t g_txBytes1 = 0; ///< Bytes transmitted by flow 1 (tunnel stream).
static uint64_t g_rxBytes1 = 0; ///< Bytes received   by flow 1 (tunnel stream).
static uint64_t g_txBytes2 = 0; ///< Bytes transmitted by flow 2 (normal stream).
static uint64_t g_rxBytes2 = 0; ///< Bytes received   by flow 2 (normal stream).

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
// Trace callbacks — one pair per flow
// ---------------------------------------------------------------------------

/**
 * @brief Tx trace callback for flow 1 (tunnel stream).
 *
 * Accumulates payload bytes into g_txBytes1 and records the last Tx timestamp.
 * Also sets g_firstTxTime on the very first call.
 *
 * @param packet The transmitted packet (read-only).
 */
static void
OnTxFlow1(Ptr<const Packet> packet)
{
    if (g_firstTxTime == 0.0)
        g_firstTxTime = Simulator::Now().GetSeconds();
    g_txBytes1 += packet->GetSize();
    g_lastTxTime = Simulator::Now().GetSeconds();
}

/**
 * @brief Rx trace callback for flow 1 (tunnel stream).
 *
 * Accumulates payload bytes into g_rxBytes1 and records the last Rx timestamp.
 * Also sets g_firstRxTime on the very first call.
 *
 * @param packet The received packet (read-only).
 * @param addr   Sender's address (unused here).
 */
static void
OnRxFlow1(Ptr<const Packet> packet, const Address& addr)
{
    if (g_firstRxTime == 0.0)
        g_firstRxTime = Simulator::Now().GetSeconds();
    g_rxBytes1 += packet->GetSize();
    g_lastRxTime = Simulator::Now().GetSeconds();
}

/**
 * @brief Tx trace callback for flow 2 (normal stream).
 *
 * Accumulates payload bytes into g_txBytes2 and updates shared timestamps.
 *
 * @param packet The transmitted packet (read-only).
 */
static void
OnTxFlow2(Ptr<const Packet> packet)
{
    if (g_firstTxTime == 0.0)
        g_firstTxTime = Simulator::Now().GetSeconds();
    g_txBytes2 += packet->GetSize();
    g_lastTxTime = Simulator::Now().GetSeconds();
}

/**
 * @brief Rx trace callback for flow 2 (normal stream).
 *
 * Accumulates payload bytes into g_rxBytes2 and updates shared timestamps.
 *
 * @param packet The received packet (read-only).
 * @param addr   Sender's address (unused here).
 */
static void
OnRxFlow2(Ptr<const Packet> packet, const Address& addr)
{
    if (g_firstRxTime == 0.0)
        g_firstRxTime = Simulator::Now().GetSeconds();
    g_rxBytes2 += packet->GetSize();
    g_lastRxTime = Simulator::Now().GetSeconds();
}

/**
 * @brief Prints a formatted per-flow and aggregate throughput summary.
 *
 * Reports per-flow byte counts (flow 1 / flow 2) and computes combined
 * Tx and Rx goodput in Mbps.  Guards against division by zero if the
 * measurement window is empty.
 */
static void
PrintThroughputSummary()
{
    uint64_t totalTx = g_txBytes1 + g_txBytes2;
    uint64_t totalRx = g_rxBytes1 + g_rxBytes2;

    double txDuration = g_lastTxTime - g_firstTxTime;
    double rxDuration = g_lastRxTime - g_firstRxTime;

    std::cout << "\n======================================\n";
    std::cout << "  Final Simulation Results\n";
    std::cout << "======================================\n";
    std::cout << "  Tx window : " << g_firstTxTime << " s  ->  " << g_lastTxTime << " s  ("
              << txDuration << " s)\n";
    std::cout << "  Rx window : " << g_firstRxTime << " s  ->  " << g_lastRxTime << " s  ("
              << rxDuration << " s)\n";
    std::cout << "--------------------------------------\n";
    std::cout << "  Flow 1 (tunnel) Tx : " << g_txBytes1 << " bytes\n";
    std::cout << "  Flow 1 (tunnel) Rx : " << g_rxBytes1 << " bytes\n";
    std::cout << "  Flow 2 (normal) Tx : " << g_txBytes2 << " bytes\n";
    std::cout << "  Flow 2 (normal) Rx : " << g_rxBytes2 << " bytes\n";
    std::cout << "--------------------------------------\n";
    std::cout << "  Total Tx : " << totalTx << " bytes\n";
    std::cout << "  Total Rx : " << totalRx << " bytes\n";

    if (txDuration > 0.0)
        std::cout << "  Tx goodput: " << (totalTx * 8.0) / (txDuration * 1e6) << " Mbps\n";
    else
        std::cout << "  Tx goodput: N/A (measurement window is zero)\n";

    if (rxDuration > 0.0)
        std::cout << "  Rx goodput: " << (totalRx * 8.0) / (rxDuration * 1e6) << " Mbps\n";
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
    LogComponentEnable("P4BasicTunnel", LOG_LEVEL_INFO);
    Packet::EnablePrinting();

    // -----------------------------------------------------------------------
    // Simulation parameters — all overridable from the command line.
    // -----------------------------------------------------------------------
    int runNumber = 0;                ///< Loop index when running in batch mode.
    uint16_t pktSize = 1000;          ///< UDP payload size in bytes.
    std::string flowRate1 = "1Mbps";  ///< Data rate for flow 1 (tunnel stream).
    std::string flowRate2 = "4Mbps";  ///< Data rate for flow 2 (normal stream).
    std::string linkRate = "100Mbps"; ///< P2P link capacity.
    std::string linkDelay = "1ms";    ///< P2P link propagation delay.
    bool enablePcap = true;           ///< Whether to write PCAP trace files.
    uint32_t clientIndex = 0;         ///< Index of the sending host.
    uint32_t serverIndex = 1;         ///< Index of the receiving host.
    uint16_t tunnelPort1 = 12000;     ///< UDP port for flow 1 (tunnel stream).
    uint16_t tunnelPort2 = 1301;      ///< UDP port for flow 2 (normal stream).
    double flowDuration = 3.0;        ///< Duration of both OnOff flows in seconds.
    double simDuration = 20.0;        ///< Total simulation duration (s).

    // P4 program / topology paths (use P4SIM_DIR env var for portability).
    std::string p4SrcDir = GetP4ExamplePath() + "/basic_tunnel";
    std::string p4JsonPath = p4SrcDir + "/basic_tunnel.json";
    std::string flowTableDir = p4SrcDir + "/";
    std::string topoFile = p4SrcDir + "/topo.txt";
    std::string topoFormat = "P2PTopo";

    // -----------------------------------------------------------------------
    // Command-line interface
    // -----------------------------------------------------------------------
    CommandLine cmd;
    cmd.AddValue("runnum", "Batch run index (used when sweeping parameters)", runNumber);
    cmd.AddValue("pktSize", "UDP payload size in bytes [default: 1000]", pktSize);
    cmd.AddValue("flowRate1", "Data rate for flow 1 (tunnel stream) [default: 1Mbps]", flowRate1);
    cmd.AddValue("flowRate2", "Data rate for flow 2 (normal stream) [default: 4Mbps]", flowRate2);
    cmd.AddValue("linkRate", "P2P link capacity [default: 100Mbps]", linkRate);
    cmd.AddValue("linkDelay", "P2P link propagation delay [default: 1ms]", linkDelay);
    cmd.AddValue("clientIndex", "Index of the UDP sender host [default: 0]", clientIndex);
    cmd.AddValue("serverIndex", "Index of the UDP receiver host [default: 1]", serverIndex);
    cmd.AddValue("tunnelPort1",
                 "UDP port for flow 1 (tunnel stream) [default: 12000]",
                 tunnelPort1);
    cmd.AddValue("tunnelPort2", "UDP port for flow 2 (normal stream) [default: 1301]", tunnelPort2);
    cmd.AddValue("flowDuration", "Duration of both flows in seconds [default: 3]", flowDuration);
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
    // Build P2P links from the topology file
    // -----------------------------------------------------------------------
    // P4PointToPointHelper is used instead of CsmaHelper because the P4 tunnel
    // program requires custom P2P net devices (CustomP2PNetDevice) on hosts.
    P4PointToPointHelper p2pHelper;
    p2pHelper.SetDeviceAttribute("DataRate", DataRateValue(DataRate(linkRate)));
    p2pHelper.SetChannelAttribute("Delay", TimeValue(Time(linkDelay)));

    std::vector<SwitchInfo> switchInfos(switchNum);
    std::vector<HostInfo> hostInfos(hostNum);

    std::string dataRate, delay;
    for (auto iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); ++iter)
    {
        unsigned int fromIdx = iter->GetFromIndex();
        unsigned int toIdx = iter->GetToIndex();
        NetDeviceContainer link =
            p2pHelper.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

        char fromType = iter->GetFromType();
        char toType = iter->GetToType();

        if (fromType == 's' && toType == 's')
        {
            NS_LOG_INFO("Link: switch[" << fromIdx << "] <-> switch[" << toIdx << "]");

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
            unsigned int hostLocalIdx = toIdx - switchNum;
            NS_LOG_INFO("Link: switch[" << fromIdx << "] -> host[" << hostLocalIdx << "]");

            unsigned int fromPort = switchInfos[fromIdx].devices.GetN();
            switchInfos[fromIdx].devices.Add(link.Get(0));
            switchInfos[fromIdx].portLabels.push_back("h" + UintToString(hostLocalIdx));

            hostInfos[hostLocalIdx].device.Add(link.Get(1));
            hostInfos[hostLocalIdx].uplinkSwitchIdx = fromIdx;
            hostInfos[hostLocalIdx].uplinkSwitchPort = fromPort;
        }
        else if (fromType == 'h' && toType == 's')
        {
            unsigned int hostLocalIdx = fromIdx - switchNum;
            NS_LOG_INFO("Link: host[" << hostLocalIdx << "] -> switch[" << toIdx << "]");

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
    // Install P4 switches (ChannelType=1 for P2P, static flow tables)
    // -----------------------------------------------------------------------
    P4Helper p4Helper;
    p4Helper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4Helper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));
    p4Helper.SetDeviceAttribute("ChannelType", UintegerValue(1)); // P2P channel
    p4Helper.SetDeviceAttribute("SwitchRate", UintegerValue(1000));

    for (unsigned int i = 0; i < switchNum; i++)
    {
        std::string flowTablePath = flowTableDir + "flowtable_" + std::to_string(i) + ".txt";
        p4Helper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));

        NS_LOG_INFO("Installing P4 switch[" << i << "]:" << "\n  JSON      : " << p4JsonPath
                                            << "\n  FlowTable : " << flowTablePath);

        p4Helper.Install(switches.Get(i), switchInfos[i].devices);
    }

    // -----------------------------------------------------------------------
    // Configure custom tunnel header on all host NetDevices
    //
    // The tunnel header is prepended at Layer 3 (before IPv4) by each
    // CustomP2PNetDevice.  Fields:
    //   proto_id (16 b) : 0x0800  -> inner packet is IPv4
    //   dst_id   (16 b) : 0x0022  -> tunnel destination identifier
    // -----------------------------------------------------------------------
    CustomHeader tunnelHeader;
    tunnelHeader.SetLayer(HeaderLayer::LAYER_3); ///< Insert at network layer.
    tunnelHeader.SetOperator(ADD_BEFORE);        ///< Prepend before the IPv4 header.
    tunnelHeader.AddField("proto_id", 16);
    tunnelHeader.AddField("dst_id", 16);
    tunnelHeader.SetField("proto_id", 0x0800); ///< IPv4 EtherType.
    tunnelHeader.SetField("dst_id", 0x0022);   ///< Example tunnel destination ID.

    for (unsigned int i = 0; i < hostNum; i++)
    {
        Ptr<NetDevice> dev = hostInfos[i].device.Get(0);
        Ptr<CustomP2PNetDevice> custDev = DynamicCast<CustomP2PNetDevice>(dev);
        if (custDev)
        {
            NS_LOG_INFO("  host[" << i << "]: setting tunnel header on CustomP2PNetDevice");
            custDev->SetWithCustomHeader(true);
            custDev->SetCustomHeader(tunnelHeader);
        }
        else
        {
            NS_LOG_WARN("  host[" << i << "]: NetDevice is not a CustomP2PNetDevice — skipping.");
        }
    }

    // -----------------------------------------------------------------------
    // Install UDP OnOff / PacketSink applications (two flows, same host pair)
    // -----------------------------------------------------------------------
    Ipv4Address serverAddr = hosts.Get(serverIndex)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();

    // --- Flow 1: tunnel stream ---
    InetSocketAddress endpoint1(serverAddr, tunnelPort1);

    PacketSinkHelper sinkHelper1("ns3::UdpSocketFactory", endpoint1);
    ApplicationContainer sinkApp1 = sinkHelper1.Install(hosts.Get(serverIndex));
    sinkApp1.Start(Seconds(g_sinkStartTime));
    sinkApp1.Stop(Seconds(g_sinkStopTime));

    OnOffHelper onOffHelper1("ns3::UdpSocketFactory", endpoint1);
    onOffHelper1.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOffHelper1.SetAttribute("DataRate", StringValue(flowRate1));
    onOffHelper1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOffHelper1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer clientApp1 = onOffHelper1.Install(hosts.Get(clientIndex));
    clientApp1.Start(Seconds(g_clientStartTime));
    clientApp1.Stop(Seconds(g_clientStopTime));

    NS_LOG_INFO("Flow 1 (tunnel): host["
                << clientIndex << "] -> host[" << serverIndex << "]" << "  dst=" << serverAddr
                << ":" << tunnelPort1 << "  rate=" << flowRate1 << "  pktSize=" << pktSize << " B");

    // --- Flow 2: normal stream ---
    InetSocketAddress endpoint2(serverAddr, tunnelPort2);

    PacketSinkHelper sinkHelper2("ns3::UdpSocketFactory", endpoint2);
    ApplicationContainer sinkApp2 = sinkHelper2.Install(hosts.Get(serverIndex));
    sinkApp2.Start(Seconds(g_sinkStartTime));
    sinkApp2.Stop(Seconds(g_sinkStopTime));

    OnOffHelper onOffHelper2("ns3::UdpSocketFactory", endpoint2);
    onOffHelper2.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOffHelper2.SetAttribute("DataRate", StringValue(flowRate2));
    onOffHelper2.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOffHelper2.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer clientApp2 = onOffHelper2.Install(hosts.Get(clientIndex));
    clientApp2.Start(Seconds(g_clientStartTime));
    clientApp2.Stop(Seconds(g_clientStopTime));

    NS_LOG_INFO("Flow 2 (normal): host["
                << clientIndex << "] -> host[" << serverIndex << "]" << "  dst=" << serverAddr
                << ":" << tunnelPort2 << "  rate=" << flowRate2 << "  pktSize=" << pktSize << " B");

    // Connect throughput measurement trace callbacks.
    DynamicCast<OnOffApplication>(hosts.Get(clientIndex)->GetApplication(0))
        ->TraceConnectWithoutContext("Tx", MakeCallback(&OnTxFlow1));
    sinkApp1.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&OnRxFlow1));

    DynamicCast<OnOffApplication>(hosts.Get(clientIndex)->GetApplication(1))
        ->TraceConnectWithoutContext("Tx", MakeCallback(&OnTxFlow2));
    sinkApp2.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&OnRxFlow2));

    // -----------------------------------------------------------------------
    // PCAP tracing (always enabled for P2P links in this example)
    // -----------------------------------------------------------------------
    if (enablePcap)
    {
        p2pHelper.EnablePcapAll("p4-basic-tunnel");
        NS_LOG_INFO("PCAP tracing enabled -> p4-basic-tunnel-*.pcap");
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
