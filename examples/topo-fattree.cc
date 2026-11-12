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
 * k-ary fat-tree data-center topology built from plain ns-3 nodes (no P4 program).
 *
 * This is the non-P4 counterpart of p4-topo-fattree. A fat tree has many redundant
 * paths between any two hosts, so it cannot be built from ns-3 BridgeNetDevices:
 * ns-3 bridges implement no spanning tree protocol, and a bridged fat tree is a
 * layer-2 loop (Ipv4GlobalRoutingHelper aborts with "L2 forwarding loop detected!",
 * and ARP broadcasts would circulate forever). Instead, every switch is an IPv4
 * router and every link is its own /30 subnet.
 *
 * Routes come from Nix-vector routing (on-demand shortest path). ns-3 global routing
 * is not used: its SPF computation asserts on the equal-cost paths of a fat tree
 * ("Assumed there is at most one exit from the root to this vertex").
 *
 * Note: earlier versions of this example bridged all switches at layer 2, which cannot
 * work on a fat tree (see above). This version is therefore a layer-3 baseline: each
 * flow follows one shortest path chosen by Nix-vector routing (no ECMP), which should be
 * kept in mind when comparing it with p4-topo-fattree.
 *
 * Addressing (pod p, edge switch e inside the pod, host h below that edge switch):
 *   edge switch <-> host link   10.p.e.(4h)/30, edge switch .4h+1, host .4h+2
 *   switch <-> switch link      one /30 per link, allocated consecutively from 172.16.0.0
 *
 * A k-ary fat tree has k^3/2 switch-to-switch links, i.e. 2*k^3 addresses. They stay
 * inside 172.16.0.0/12 only for podnum <= 80; for larger podnum the allocation continues
 * past 172.31.255.255 (up to 172.79.255.255 for podnum = 128). This does not affect the
 * simulation, since these addresses do not overlap with the 10.0.0.0/8 host links.
 *
 * Traffic: for the first half of the hosts, host i sends TCP OnOff traffic to host
 * (hostNum - 1 - i). A per-flow summary (sent / received bytes, goodput) is printed
 * at the end.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/nix-vector-helper.h"

#include <iomanip>
#include <iostream>
#include <string>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TOPOFATTREE");

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

// Bytes handed to the socket by each OnOff client, indexed by flow.
static std::vector<uint64_t> g_flowTxBytes;

static void
FlowTx(uint32_t flow, Ptr<const Packet> p)
{
    g_flowTxBytes[flow] += p->GetSize();
}

// switch number:0~switchNum-1
// host number: 0~hostNum-1

struct SwitchUnit_t
{
    SwitchUnit_t()
    {
    }

    // switch link port network device
    NetDeviceContainer switchDevices;
    // switch link port node info
    std::vector<bool> isSwitch;
    std::vector<unsigned int> index;
    std::vector<unsigned int> portNb;
};

// Attention: host can not link with other host
struct HostUnit_t
{
    HostUnit_t()
        : index(0),
          portNb(0)
    {
    }

    // host network device and ipv4 info
    NetDeviceContainer hostDevice;
    Ipv4InterfaceContainer hostIpv4;
    // host link switch info
    unsigned int index;
    unsigned int portNb;
};

void
ShowSwitchHostInfo(const std::vector<SwitchUnit_t>& switchInfos,
                   const std::vector<HostUnit_t>& hostInfos)
{
    // Show switch info
    std::cout << "Show switch info from 0 to " << switchInfos.size() - 1 << std::endl;
    for (size_t i = 0; i < switchInfos.size(); i++)
    {
        std::cout << "switch " << i << ":" << std::endl;
        for (size_t j = 0; j < switchInfos[i].index.size(); j++)
        {
            if (switchInfos[i].isSwitch[j])
                std::cout << "link switch index portNb:";
            else
                std::cout << "link host index portNb:";
            std::cout << switchInfos[i].index[j] << " " << switchInfos[i].portNb[j] << std::endl;
        }
    }

    // Show host info
    std::cout << "Show host info from 0 to " << hostInfos.size() - 1 << std::endl;
    for (size_t i = 0; i < hostInfos.size(); i++)
    {
        std::cout << "ipv4 address:";
        hostInfos[i].hostIpv4.GetAddress(0).Print(std::cout);
        std::cout << " index portNb: " << hostInfos[i].index << " " << hostInfos[i].portNb
                  << std::endl;
    }
}

// Base address of the host links below edge switch s of pod `pod`: 10.pod.s.0
std::string
GetHostIpAddrBase(unsigned int pod, unsigned int s)
{
    return "10." + std::to_string(pod) + "." + std::to_string(s) + ".0";
}

int
main(int argc, char* argv[])
{
    unsigned long mainStart = getTickCount();

    unsigned int podNum = 4;
    std::string linkDataRate("1000Mbps");
    std::string linkDelay("0.01ms");
    int packetSize = 1024;
    uint16_t servPort = 9; // TCP port of the PacketSink on every server host
    std::string onOffDataRate("1Mbps");
    std::string maxBytes("0");
    double clientStartTime = 1.0;
    double clientStopTime = 10.0;
    double sinkStopTime = 11.0;
    double simStopTime = 12.0;

    LogComponentEnable("TOPOFATTREE", LOG_LEVEL_DEBUG);

    CommandLine cmd;
    cmd.AddValue("podnum", "Number of pods k of the k-ary fat tree (even, 2..128)", podNum);
    cmd.Parse(argc, argv);

    NS_ABORT_MSG_IF(podNum < 2 || podNum % 2 != 0 || podNum > 128,
                    "podnum must be an even number between 2 and 128, got " << podNum);

    // All flows start at the same time and share the first hops of their shortest paths.
    // With the ns-3 default of 3 packets waiting per unresolved ARP entry, the 4th SYN
    // towards the same next hop is dropped and its connection only starts after the 3s
    // SYN retransmission timeout. Use a queue close to the Linux default (unres_qlen 101).
    Config::SetDefault("ns3::ArpCache::PendingQueueSize", UintegerValue(100));

    unsigned int coreSwitchNum = podNum * podNum / 4;
    unsigned int hostNum = coreSwitchNum * podNum;
    unsigned int switchNum = coreSwitchNum * 5;

    unsigned int aggrSwitchIndex = coreSwitchNum;
    unsigned int edgeSwitchIndex = 3 * coreSwitchNum;

    unsigned int halfPodNum = podNum / 2;

    NodeContainer hosts;
    hosts.Create(hostNum);
    NodeContainer switches;
    switches.Create(switchNum);

    std::vector<HostUnit_t> hostInfos(hostNum);
    std::vector<SwitchUnit_t> switchInfos(switchNum);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(linkDataRate));
    csma.SetChannelAttribute("Delay", StringValue(linkDelay));

    // Initialize Internet Stack and Routing Protocols on hosts and switches. Every switch
    // is an IPv4 router, so the redundant fat-tree paths do not form layer-2 loops.
    //
    InternetStackHelper internet;
    Ipv4NixVectorHelper nixRouting;
    internet.SetRoutingHelper(nixRouting);
    internet.Install(hosts);
    internet.Install(switches);

    // Host links: 10.pod.edge.(4h)/30. Switch-to-switch links: one /30 each, counting up
    // from 172.16.0.0 (inside 172.16.0.0/12 only for podnum <= 80, see the header comment).
    Ipv4AddressHelper hostLinkIpv4;
    Ipv4AddressHelper switchLinkIpv4;
    switchLinkIpv4.SetBase("172.16.0.0", "255.255.255.252");

    //=========== Connect aggregate switches to edge switches, edge switches to hosts  ===========//
    unsigned int curAggrSwitchIndex;
    unsigned int curEdgeSwitchIndex;
    unsigned int aggrLinkEdgeSwitchIndex;
    unsigned int edgeLinkHostIndex;

    for (unsigned int i = 0; i < podNum; i++) // number pod
    {
        for (unsigned int j = 0; j < halfPodNum; j++) // number switch in pod
        {
            // set host link ip base
            hostLinkIpv4.SetBase(GetHostIpAddrBase(i, j).c_str(), "255.255.255.252");

            curAggrSwitchIndex = aggrSwitchIndex + i * halfPodNum + j;
            curEdgeSwitchIndex = edgeSwitchIndex + i * halfPodNum + j;
            for (unsigned int p = 0; p < halfPodNum; p++)
            {
                aggrLinkEdgeSwitchIndex = edgeSwitchIndex + i * halfPodNum + p;
                edgeLinkHostIndex = i * coreSwitchNum + j * halfPodNum + p;

                // for aggr switch and edge switch link
                NetDeviceContainer linkAggrEdge =
                    csma.Install(NodeContainer(switches.Get(curAggrSwitchIndex),
                                               switches.Get(aggrLinkEdgeSwitchIndex)));
                switchLinkIpv4.Assign(linkAggrEdge);
                switchLinkIpv4.NewNetwork();

                switchInfos[curAggrSwitchIndex].switchDevices.Add(linkAggrEdge.Get(0));
                switchInfos[aggrLinkEdgeSwitchIndex].switchDevices.Add(linkAggrEdge.Get(1));

                switchInfos[curAggrSwitchIndex].isSwitch.push_back(true);
                switchInfos[curAggrSwitchIndex].index.push_back(aggrLinkEdgeSwitchIndex);
                switchInfos[curAggrSwitchIndex].portNb.push_back(
                    switchInfos[aggrLinkEdgeSwitchIndex].switchDevices.GetN() - 1);

                switchInfos[aggrLinkEdgeSwitchIndex].isSwitch.push_back(true);
                switchInfos[aggrLinkEdgeSwitchIndex].index.push_back(curAggrSwitchIndex);
                switchInfos[aggrLinkEdgeSwitchIndex].portNb.push_back(
                    switchInfos[curAggrSwitchIndex].switchDevices.GetN() - 1);

                // for edge switch and host link
                NetDeviceContainer linkEdgeHost = csma.Install(
                    NodeContainer(switches.Get(curEdgeSwitchIndex), hosts.Get(edgeLinkHostIndex)));

                switchInfos[curEdgeSwitchIndex].switchDevices.Add(linkEdgeHost.Get(0));
                hostInfos[edgeLinkHostIndex].hostDevice.Add(linkEdgeHost.Get(1));
                // assign ip: edge switch port gets .4h+1 (the host's gateway), host gets .4h+2
                Ipv4InterfaceContainer edgeHostIf = hostLinkIpv4.Assign(linkEdgeHost);
                hostLinkIpv4.NewNetwork();
                hostInfos[edgeLinkHostIndex].hostIpv4.Add(edgeHostIf.Get(1));

                switchInfos[curEdgeSwitchIndex].isSwitch.push_back(false);
                switchInfos[curEdgeSwitchIndex].index.push_back(edgeLinkHostIndex);
                switchInfos[curEdgeSwitchIndex].portNb.push_back(0);

                hostInfos[edgeLinkHostIndex].index = curEdgeSwitchIndex;
                hostInfos[edgeLinkHostIndex].portNb =
                    switchInfos[curEdgeSwitchIndex].switchDevices.GetN() - 1;
            }
        }
    }

    //=========== Connect core switches to aggregate switches ===========//
    unsigned int startPodI = 0;
    unsigned int k;
    unsigned int coreLinkAggrSwitchIndex;
    for (unsigned int i = 0; i < coreSwitchNum; i++) // traverse core switch
    {
        k = startPodI;
        for (unsigned int j = 0; j < podNum; j++) // traverse pod
        {
            coreLinkAggrSwitchIndex = aggrSwitchIndex + j * halfPodNum + k;
            NetDeviceContainer linkCoreAggr =
                csma.Install(NodeContainer(switches.Get(i), switches.Get(coreLinkAggrSwitchIndex)));
            switchLinkIpv4.Assign(linkCoreAggr);
            switchLinkIpv4.NewNetwork();

            switchInfos[i].switchDevices.Add(linkCoreAggr.Get(0));
            switchInfos[coreLinkAggrSwitchIndex].switchDevices.Add(linkCoreAggr.Get(1));

            switchInfos[i].isSwitch.push_back(true);
            switchInfos[i].index.push_back(coreLinkAggrSwitchIndex);
            switchInfos[i].portNb.push_back(
                switchInfos[coreLinkAggrSwitchIndex].switchDevices.GetN() - 1);

            switchInfos[coreLinkAggrSwitchIndex].isSwitch.push_back(true);
            switchInfos[coreLinkAggrSwitchIndex].index.push_back(i);
            switchInfos[coreLinkAggrSwitchIndex].portNb.push_back(
                switchInfos[i].switchDevices.GetN() - 1);
            // update k
            if (k != halfPodNum - 1)
                k++;
            else
                k = 0;
        }
        // update startPodI
        if (startPodI != halfPodNum - 1)
            startPodI++;
        else
            startPodI = 0;
    }

    //=========== Show switch and host info  ===========//
    ShowSwitchHostInfo(switchInfos, hostInfos);

    //=========== Build OnOff applications  ===========//

    unsigned int halfHostNum = hostNum / 2;
    g_flowTxBytes.assign(halfHostNum, 0);
    std::vector<Ptr<PacketSink>> flowSinks(halfHostNum);
    for (unsigned int i = 0; i < halfHostNum; i++)
    {
        unsigned int serverI = hostNum - i - 1;
        Ipv4Address serverAddr = hostInfos[serverI].hostIpv4.GetAddress(0);
        InetSocketAddress dst = InetSocketAddress(serverAddr, servPort);

        OnOffHelper onOff = OnOffHelper("ns3::TcpSocketFactory", dst);
        onOff.SetAttribute("PacketSize", UintegerValue(packetSize));
        onOff.SetAttribute("DataRate", StringValue(onOffDataRate));
        onOff.SetAttribute("MaxBytes", StringValue(maxBytes));

        ApplicationContainer clientApps = onOff.Install(hosts.Get(i));
        clientApps.Start(Seconds(clientStartTime));
        clientApps.Stop(Seconds(clientStopTime));
        clientApps.Get(0)->TraceConnectWithoutContext("Tx", MakeBoundCallback(&FlowTx, i));

        PacketSinkHelper sink = PacketSinkHelper("ns3::TcpSocketFactory", dst);
        ApplicationContainer sinkApps = sink.Install(hosts.Get(serverI));
        sinkApps.Start(Seconds(0.0));
        sinkApps.Stop(Seconds(sinkStopTime));
        flowSinks[i] = DynamicCast<PacketSink>(sinkApps.Get(0));

        NS_LOG_DEBUG("Data send from client " << i << " to the server " << serverI);
    }

    csma.EnablePcapAll("topo-fattree", false);

    Packet::EnablePrinting();

    unsigned long simulateStart = getTickCount();
    Simulator::Stop(Seconds(simStopTime));
    Simulator::Run();

    //=========== Per-flow results ===========//
    double sendDuration = clientStopTime - clientStartTime;
    uint64_t totalTx = 0;
    uint64_t totalRx = 0;
    std::cout << "=========== Flow results (TCP OnOff " << onOffDataRate
              << ", default on 1s / off 1s, " << clientStartTime << "s-" << clientStopTime
              << "s) ===========" << std::endl;
    for (unsigned int i = 0; i < halfHostNum; i++)
    {
        unsigned int serverI = hostNum - i - 1;
        uint64_t rx = flowSinks[i]->GetTotalRx();
        totalTx += g_flowTxBytes[i];
        totalRx += rx;
        std::cout << "flow " << i << ": host " << i << " (" << hostInfos[i].hostIpv4.GetAddress(0)
                  << ") -> host " << serverI << " (" << hostInfos[serverI].hostIpv4.GetAddress(0)
                  << ") sent " << g_flowTxBytes[i] << " B, received " << rx << " B, goodput "
                  << std::fixed << std::setprecision(3) << rx * 8.0 / sendDuration / 1e6
                  << " Mbps" << std::defaultfloat << std::endl;
    }
    std::cout << "Total sent " << totalTx << " B, received " << totalRx << " B, delivered "
              << std::fixed << std::setprecision(2)
              << (totalTx > 0 ? 100.0 * totalRx / totalTx : 0.0) << " %, aggregate goodput "
              << std::setprecision(3) << totalRx * 8.0 / sendDuration / 1e6 << " Mbps"
              << std::defaultfloat << std::endl;

    Simulator::Destroy();
    unsigned long end = getTickCount();

    std::cout << "Host Num: " << hostNum << " Switch Num: " << switchNum << std::endl;
    std::cout << "Program Running time: " << end - mainStart << "ms" << std::endl;
    std::cout << "Simulate Running time: " << end - simulateStart << "ms" << std::endl;
}
