/*
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
 * Authors: <https://github.com/kphf1995cm/>
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * @file topo-fattree.cc
 * @brief NS-3 simulation of a k-ary Fat-Tree data-center network topology.
 *
 * Overview
 * --------
 * This example constructs a standard k-ary Fat-Tree topology (Al-Fares et al.,
 * SIGCOMM 2008) using NS-3 CSMA links and NS-3 BridgeHelper for L2 switching.
 * The topology is parameterised by the pod count `k` (default k=4) and consists
 * of three switch layers:
 *
 *   - Core switches    : (k/2)^2  switches, fully connected to every pod.
 *   - Aggregate switches: k*(k/2) switches, one group of k/2 per pod.
 *   - Edge switches    : k*(k/2) switches, one group of k/2 per pod.
 *   - Hosts            : k^3/4   end-hosts, k/2 hosts per edge switch.
 *
 * Switch index layout (0-based, contiguous):
 *   [0 .. coreSwitchNum-1]             -> core switches
 *   [coreSwitchNum .. 3*coreSwitchNum-1] -> aggregate switches
 *   [3*coreSwitchNum .. 5*coreSwitchNum-1] -> edge switches
 *
 * IP addressing follows the standard Fat-Tree scheme: 10.<pod>.<edge>.x/24.
 *
 * Traffic model
 * -------------
 * The first half of hosts act as OnOff TCP clients; the second half (in
 * reverse order) act as PacketSink TCP servers.  Clients transmit from t=1s
 * to t=10s; servers listen from t=0s to t=11s.
 *
 * Routing
 * -------
 * A combination of Ipv4GlobalRouting (priority 0) and Nix-Vector routing
 * (priority 10) is installed on all hosts.  Routing tables are populated
 * automatically via Ipv4GlobalRoutingHelper::PopulateRoutingTables().
 *
 * Known limitations
 * -----------------
 * Using NS-3 BridgeHelper on a Fat-Tree creates L2 forwarding loops that
 * result in broadcast storms.  This example is intentionally kept simple for
 * topology verification purposes.  For a fully functional simulation, replace
 * BridgeHelper with P4Helper (already included) and a suitable P4 program.
 *
 * Usage
 * -----
 * @code
 *   ./ns3 run "topo-fattree --podnum=4"
 * @endcode
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/point-to-point-helper.h"

#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TOPOFATTREE");

/**
 * @brief Returns the current wall-clock time in milliseconds.
 *
 * Provides a cross-platform millisecond timestamp used to measure
 * total program runtime and pure simulation runtime separately.
 *
 * @return Current time in milliseconds since the Unix epoch (or
 *         equivalent platform origin).
 */
unsigned long
getTickCount(void)
{
    unsigned long currentTime = 0;
#ifdef WIN32
    currentTime = GetTickCount();
#endif
    struct timeval current;
    gettimeofday(&current, NULL);
    currentTime = current.tv_sec * 1000 + current.tv_usec / 1000;
#ifdef OS_VXWORKS
    ULONGA timeSecond = tickGet() / sysClkRateGet();
    ULONGA timeMilsec = tickGet() % sysClkRateGet() * 1000 / sysClkRateGet();
    currentTime = timeSecond * 1000 + timeMilsec;
#endif
    return currentTime;
}

/**
 * @brief Trace callback invoked whenever a PacketSink receives a packet.
 *
 * Connected to the ns3::PacketSink/Rx trace source via
 * Config::ConnectWithoutContext().
 *
 * @param p  The received packet (read-only).
 * @param ad The sender's address.
 */
static void
SinkRx(Ptr<const Packet> p, const Address& ad)
{
    std::cout << "Rx - Received from " << ad << std::endl;
}

/**
 * @brief Per-switch topology descriptor.
 *
 * Stores all network devices attached to a switch and the adjacency
 * information for each port (whether the neighbour is another switch or
 * a host, and which index/port number it uses on the remote side).
 *
 * @note Switch indices run from 0 to (switchNum - 1).
 */
struct SwitchUnit_t
{
    SwitchUnit_t()
    {
    }

    /** All NetDevices installed on this switch (one per physical port). */
    NetDeviceContainer switchDevices;

    /** True if the neighbour on port j is a switch; false if it is a host. */
    std::vector<bool> isSwitch;

    /** Global index of the neighbour node connected to port j. */
    std::vector<unsigned int> index;

    /**
     * Port number on the *remote* side of the link connected to port j.
     * Used to cross-reference topology adjacency information.
     */
    std::vector<unsigned int> portNb;
};

/**
 * @brief Per-host topology descriptor.
 *
 * Stores the single network device of a host, its assigned IPv4 address,
 * and which switch port it is connected to.
 *
 * @note A host is always connected to exactly one edge switch.
 *       Host-to-host direct links are not supported in this topology.
 * @note Host indices run from 0 to (hostNum - 1).
 */
struct HostUnit_t
{
    HostUnit_t()
        : index(0),
          portNb(0)
    {
    }

    /** The single NetDevice of this host. */
    NetDeviceContainer hostDevice;

    /** The IPv4 interface assigned to this host. */
    Ipv4InterfaceContainer hostIpv4;

    /** Global index of the edge switch this host is connected to. */
    unsigned int index;

    /**
     * Port number on the edge switch that faces this host.
     * Useful when building per-switch forwarding tables.
     */
    unsigned int portNb;
};

/**
 * @brief Prints a human-readable summary of all switch and host adjacencies.
 *
 * For each switch, lists all neighbours (type, index, remote port).
 * For each host, prints its IPv4 address and the edge-switch port it is
 * connected to.  Useful for debugging topology construction.
 *
 * @param switchInfos Vector of per-switch topology descriptors.
 * @param hostInfos   Vector of per-host topology descriptors.
 */
void
ShowSwitchHostInfo(const std::vector<SwitchUnit_t>& switchInfos,
                   const std::vector<HostUnit_t>& hostInfos)
{
    // --- Switch adjacency summary ---
    std::cout << "Switch info [0 .. " << switchInfos.size() - 1 << "]:" << std::endl;
    for (size_t i = 0; i < switchInfos.size(); i++)
    {
        std::cout << "  switch " << i << ":" << std::endl;
        for (size_t j = 0; j < switchInfos[i].index.size(); j++)
        {
            std::cout << "    port " << j << " -> ";
            if (switchInfos[i].isSwitch[j])
                std::cout << "switch ";
            else
                std::cout << "host   ";
            std::cout << "index=" << switchInfos[i].index[j]
                      << "  remote-port=" << switchInfos[i].portNb[j] << std::endl;
        }
    }

    // --- Host address and uplink summary ---
    std::cout << "Host info [0 .. " << hostInfos.size() - 1 << "]:" << std::endl;
    for (size_t i = 0; i < hostInfos.size(); i++)
    {
        std::cout << "  host " << i << "  ipv4=";
        hostInfos[i].hostIpv4.GetAddress(0).Print(std::cout);
        std::cout << "  uplink-switch=" << hostInfos[i].index
                  << "  switch-port=" << hostInfos[i].portNb << std::endl;
    }
}

/**
 * @brief Generates the IP network base address for a given pod and edge-switch.
 *
 * Follows the standard Fat-Tree addressing scheme:
 *   10.<pod>.<edge>.0/24
 *
 * The caller is responsible for freeing the returned C-string.
 *
 * @param pod  Zero-based pod index (0 .. k-1).
 * @param s    Zero-based edge-switch index within the pod (0 .. k/2-1).
 * @return Heap-allocated C-string representing the base address, e.g. "10.1.2.0".
 */
char*
GetHostIpAddrBase(unsigned int pod, unsigned int s)
{
    std::string ipBase("10.");

    // Append pod octet
    if (pod == 0)
    {
        ipBase.append("0.");
    }
    else
    {
        std::string podStr;
        while (pod)
        {
            podStr.insert(podStr.begin(), pod % 10 + '0');
            pod /= 10;
        }
        ipBase.append(podStr);
        ipBase.push_back('.');
    }

    // Append edge-switch octet and host octet placeholder
    if (s == 0)
    {
        ipBase.append("0.0");
    }
    else
    {
        std::string sStr;
        while (s)
        {
            sStr.insert(sStr.begin(), s % 10 + '0');
            s /= 10;
        }
        ipBase.append(sStr);
        ipBase.append(".0");
    }

    // Copy to heap-allocated C-string for NS-3 API compatibility
    char* res = new char[ipBase.size() + 1];
    for (size_t i = 0; i < ipBase.size(); i++)
        res[i] = ipBase[i];
    res[ipBase.size()] = '\0';
    return res;
}

/**
 * @brief Simulation entry point.
 *
 * Constructs a k-ary Fat-Tree topology using L3 IP forwarding (Ipv4GlobalRouting)
 * on all switches and hosts.  Every inter-node link is modelled as a
 * PointToPoint channel so that each link forms an isolated /30 subnet, which
 * avoids the ECMP assert that Ipv4GlobalRouting triggers on shared CSMA segments.
 * IPv4 addresses are assigned to every link, OnOff/PacketSink TCP traffic is set
 * up between paired hosts, and the NS-3 simulator is run.
 *
 * Command-line parameters
 * -----------------------
 *   --podnum  Number of pods k (must be even; default: 4).
 *             Derived counts: core=(k/2)^2, aggr=edge=k*(k/2), hosts=k^3/4.
 *
 * @param argc Argument count forwarded from the OS.
 * @param argv Argument vector forwarded from the OS.
 * @return 0 on successful completion.
 */
int
main(int argc, char* argv[])
{
    unsigned long mainStart = getTickCount();

    // --- Simulation parameters (overridable via command line) ---
    unsigned int podNum = 4;              ///< Number of pods (k); must be even.
    std::string linkDataRate("1000Mbps"); ///< CSMA link capacity.
    std::string linkDelay("0.01ms");      ///< CSMA link propagation delay.
    int packetSize = 1024;                ///< OnOff application packet size in bytes.
    std::string onOffDataRate("1Mbps");   ///< OnOff application data rate.
    std::string maxBytes("0");            ///< Max bytes per flow; 0 means unlimited.

    LogComponentEnable("TOPOFATTREE", LOG_LEVEL_DEBUG);
    // LogComponentEnable("BridgeNetDevice", LOG_LEVEL_LOGIC);

    CommandLine cmd;
    cmd.AddValue("podnum", "Number of pods k in the Fat-Tree (must be even)", podNum);
    cmd.Parse(argc, argv);

    // --- Derive topology counts from pod number k ---
    unsigned int coreSwitchNum = podNum * podNum / 4; ///< (k/2)^2 core switches.
    unsigned int hostNum = coreSwitchNum * podNum;    ///< k^3/4 hosts total.
    unsigned int switchNum = coreSwitchNum * 5;       ///< core + aggr + edge.

    // Starting indices for aggregate and edge switches in the flat switch array.
    unsigned int aggrSwitchIndex = coreSwitchNum;     ///< First aggregate switch index.
    unsigned int edgeSwitchIndex = 3 * coreSwitchNum; ///< First edge switch index.

    unsigned int halfPodNum = podNum / 2; ///< k/2, used throughout topology construction.

    // --- Create node containers ---
    NodeContainer hosts;
    hosts.Create(hostNum);
    NodeContainer switches;
    switches.Create(switchNum);

    // Per-node topology metadata vectors
    std::vector<HostUnit_t> hostInfos(hostNum);
    std::vector<SwitchUnit_t> switchInfos(switchNum);

    // --- Configure PointToPoint channel attributes ---
    // Every link is a dedicated point-to-point channel, giving each link its
    // own isolated subnet and avoiding ECMP issues with Ipv4GlobalRouting.
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue(linkDataRate));
    p2p.SetChannelAttribute("Delay", StringValue(linkDelay));

    // --- Install Internet stack and routing on hosts AND switches ---
    // Switches act as IP routers (L3 forwarding) rather than L2 bridges,
    // because Fat-Tree has redundant paths that cause L2 forwarding loops
    // and ECMP asserts with NS-3's Ipv4GlobalRouting on shared CSMA segments.
    InternetStackHelper internet;
    Ipv4GlobalRoutingHelper globalRouting;
    internet.SetRoutingHelper(globalRouting);
    internet.Install(hosts);
    internet.Install(switches);

    //=========== Connect aggregate <-> edge switches and edge switches <-> hosts ===========//

    unsigned int curAggrSwitchIndex;
    unsigned int curEdgeSwitchIndex;
    unsigned int aggrLinkEdgeSwitchIndex;
    unsigned int edgeLinkHostIndex;

    Ipv4AddressHelper ipv4;       ///< Used for host-facing /24 subnets (10.<pod>.<edge>.0/24).
    Ipv4AddressHelper ipv4Switch; ///< Used for switch-to-switch /30 point-to-point subnets.
    ipv4Switch.SetBase("172.16.0.0", "255.255.255.252"); ///< Each /30 has 2 usable addresses.

    // Iterate over every pod, then over every aggregate/edge switch pair within the pod.
    for (unsigned int i = 0; i < podNum; i++) // pod index i in [0, k)
    {
        for (unsigned int j = 0; j < halfPodNum; j++) // switch pair index j in [0, k/2)
        {
            // Each edge switch j in pod i serves a /24 subnet: 10.<i>.<j>.0/24
            ipv4.SetBase(GetHostIpAddrBase(i, j), "255.255.255.0");

            curAggrSwitchIndex = aggrSwitchIndex + i * halfPodNum + j;
            curEdgeSwitchIndex = edgeSwitchIndex + i * halfPodNum + j;

            // Connect aggregate switch j to all edge switches in the same pod,
            // and connect each edge switch to its k/2 hosts.
            for (unsigned int p = 0; p < halfPodNum; p++)
            {
                aggrLinkEdgeSwitchIndex = edgeSwitchIndex + i * halfPodNum + p;
                edgeLinkHostIndex = i * coreSwitchNum + j * halfPodNum + p;

                // --- Link: aggregate switch j <-> edge switch p (within pod i) ---
                // Use PointToPoint so each link is an isolated /30 subnet.
                NetDeviceContainer linkAggrEdge =
                    p2p.Install(NodeContainer(switches.Get(curAggrSwitchIndex),
                                              switches.Get(aggrLinkEdgeSwitchIndex)));

                // Assign a /30 IP subnet to this switch-to-switch link
                ipv4Switch.Assign(linkAggrEdge);
                ipv4Switch.NewNetwork();

                // Register devices on both ends
                switchInfos[curAggrSwitchIndex].switchDevices.Add(linkAggrEdge.Get(0));
                switchInfos[aggrLinkEdgeSwitchIndex].switchDevices.Add(linkAggrEdge.Get(1));

                // Record adjacency from the aggregate switch's perspective
                switchInfos[curAggrSwitchIndex].isSwitch.push_back(true);
                switchInfos[curAggrSwitchIndex].index.push_back(aggrLinkEdgeSwitchIndex);
                switchInfos[curAggrSwitchIndex].portNb.push_back(
                    switchInfos[aggrLinkEdgeSwitchIndex].switchDevices.GetN() - 1);

                // Record adjacency from the edge switch's perspective
                switchInfos[aggrLinkEdgeSwitchIndex].isSwitch.push_back(true);
                switchInfos[aggrLinkEdgeSwitchIndex].index.push_back(curAggrSwitchIndex);
                switchInfos[aggrLinkEdgeSwitchIndex].portNb.push_back(
                    switchInfos[curAggrSwitchIndex].switchDevices.GetN() - 1);

                // --- Link: edge switch j <-> host p (within pod i, subnet j) ---
                NetDeviceContainer linkEdgeHost = p2p.Install(
                    NodeContainer(switches.Get(curEdgeSwitchIndex), hosts.Get(edgeLinkHostIndex)));

                switchInfos[curEdgeSwitchIndex].switchDevices.Add(linkEdgeHost.Get(0));
                hostInfos[edgeLinkHostIndex].hostDevice.Add(linkEdgeHost.Get(1));

                // Assign IPv4 address to both the edge-switch port and the host interface
                Ipv4InterfaceContainer ifaceEdgeHost = ipv4.Assign(linkEdgeHost);
                // Store only the host's interface (index 1)
                hostInfos[edgeLinkHostIndex].hostIpv4.Add(ifaceEdgeHost.Get(1));

                // Record adjacency from the edge switch's perspective
                switchInfos[curEdgeSwitchIndex].isSwitch.push_back(false);
                switchInfos[curEdgeSwitchIndex].index.push_back(edgeLinkHostIndex);
                switchInfos[curEdgeSwitchIndex].portNb.push_back(0); // host has only one port

                // Record uplink info from the host's perspective
                hostInfos[edgeLinkHostIndex].index = curEdgeSwitchIndex;
                hostInfos[edgeLinkHostIndex].portNb =
                    switchInfos[curEdgeSwitchIndex].switchDevices.GetN() - 1;
            }
        }
    }

    //=========== Connect core switches to aggregate switches ===========//

    // Each core switch i connects to exactly one aggregate switch per pod.
    // The aggregate switch index within a pod rotates to achieve full bisection bandwidth.
    unsigned int startPodI = 0; ///< Starting intra-pod aggr index for the current core switch.
    unsigned int k;             ///< Current intra-pod aggr index (wraps around at k/2).
    unsigned int coreLinkAggrSwitchIndex;

    for (unsigned int i = 0; i < coreSwitchNum; i++) // traverse core switches
    {
        k = startPodI;
        for (unsigned int j = 0; j < podNum; j++) // traverse pods (one uplink per pod)
        {
            coreLinkAggrSwitchIndex = aggrSwitchIndex + j * halfPodNum + k;

            // --- Link: core switch i <-> aggregate switch k in pod j ---
            // Use PointToPoint so each link is an isolated /30 subnet.
            NetDeviceContainer linkCoreAggr =
                p2p.Install(NodeContainer(switches.Get(i), switches.Get(coreLinkAggrSwitchIndex)));

            // Assign a /30 IP subnet to this switch-to-switch link
            ipv4Switch.Assign(linkCoreAggr);
            ipv4Switch.NewNetwork();

            switchInfos[i].switchDevices.Add(linkCoreAggr.Get(0));
            switchInfos[coreLinkAggrSwitchIndex].switchDevices.Add(linkCoreAggr.Get(1));

            // Record adjacency from the core switch's perspective
            switchInfos[i].isSwitch.push_back(true);
            switchInfos[i].index.push_back(coreLinkAggrSwitchIndex);
            switchInfos[i].portNb.push_back(
                switchInfos[coreLinkAggrSwitchIndex].switchDevices.GetN() - 1);

            // Record adjacency from the aggregate switch's perspective
            switchInfos[coreLinkAggrSwitchIndex].isSwitch.push_back(true);
            switchInfos[coreLinkAggrSwitchIndex].index.push_back(i);
            switchInfos[coreLinkAggrSwitchIndex].portNb.push_back(
                switchInfos[i].switchDevices.GetN() - 1);

            // Advance intra-pod index cyclically in [0, k/2)
            k = (k != halfPodNum - 1) ? k + 1 : 0;
        }
        // Advance the starting intra-pod index cyclically for the next core switch
        startPodI = (startPodI != halfPodNum - 1) ? startPodI + 1 : 0;
    }

    //=========== Print topology summary ===========//
    ShowSwitchHostInfo(switchInfos, hostInfos);

    //=========== Install OnOff / PacketSink TCP applications ===========//

    // Pair hosts symmetrically: host i (client) <-> host (hostNum-1-i) (server).
    ApplicationContainer apps;
    unsigned int halfHostNum = hostNum / 2;

    for (unsigned int i = 0; i < halfHostNum; i++)
    {
        unsigned int serverI = hostNum - i - 1;
        Ipv4Address serverAddr = hostInfos[serverI].hostIpv4.GetAddress(0);
        InetSocketAddress dst(serverAddr);

        // Configure OnOff client on host i
        OnOffHelper onOff("ns3::TcpSocketFactory", dst);
        onOff.SetAttribute("PacketSize", UintegerValue(packetSize));
        onOff.SetAttribute("DataRate", StringValue(onOffDataRate));
        onOff.SetAttribute("MaxBytes", StringValue(maxBytes));

        apps = onOff.Install(hosts.Get(i));
        apps.Start(Seconds(1.0));
        apps.Stop(Seconds(10.0));

        // Configure PacketSink server on host serverI
        PacketSinkHelper sink("ns3::TcpSocketFactory", dst);
        apps = sink.Install(hosts.Get(serverI));
        apps.Start(Seconds(0.0));
        apps.Stop(Seconds(11.0));

        NS_LOG_DEBUG("Flow: client host " << i << " -> server host " << serverI << " ("
                                          << serverAddr << ")");
    }

    // Populate routing tables after all nodes and applications are configured.
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Enable PCAP tracing on all PointToPoint devices (promiscuous mode disabled).
    p2p.EnablePcapAll("topo-fattree", false);

    // Connect a trace callback to the PacketSink on node 8 for demonstration.
    Config::ConnectWithoutContext("/NodeList/8/ApplicationList/0/$ns3::PacketSink/Rx",
                                  MakeCallback(&SinkRx));

    Packet::EnablePrinting();

    //=========== Run simulation ===========//
    unsigned long simulateStart = getTickCount();
    Simulator::Run();
    Simulator::Destroy();
    unsigned long end = getTickCount();

    std::cout << "Host count   : " << hostNum << std::endl;
    std::cout << "Switch count : " << switchNum << std::endl;
    std::cout << "Total runtime    : " << end - mainStart << " ms" << std::endl;
    std::cout << "Simulate runtime : " << end - simulateStart << " ms" << std::endl;

    return 0;
}
