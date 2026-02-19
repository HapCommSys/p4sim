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

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/fattree-topo-helper.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/network-module.h"
#include "ns3/nix-vector-helper.h"
#include "ns3/p4-helper.h"

#include <iostream>
#include <netinet/in.h>
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

static void
SinkRx(Ptr<const Packet> p, const Address& ad)
{
    std::cout << "Rx" << "Received from  " << ad << std::endl;
}

// static void
// PingRtt(std::string context, Time rtt)
// {
//     std::cout << "Rtt" << context << " " << rtt << std::endl;
// }

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

char*
GetHostIpAddrBase(unsigned int pod, unsigned int s)
{
    std::string ipBase("10.");
    if (pod == 0)
        ipBase.append("0.");
    else
    {
        std::string podStr;
        while (pod)
        {
            podStr.insert(podStr.begin(), pod % 10 + '0');
            pod /= 10;
        }
        ipBase.append(podStr);
        ipBase.insert(ipBase.end(), '.');
    }
    if (s == 0)
        ipBase.append("0.0");
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
    char* res = new char[ipBase.size() + 1];
    for (size_t i = 0; i < ipBase.size(); i++)
        res[i] = ipBase[i];
    res[ipBase.size()] = '\0';
    return res;
}

int
main(int argc, char* argv[])
{
    unsigned long mainStart = getTickCount();

    unsigned int podNum = 4;
    std::string linkDataRate("1000Mbps");
    std::string linkDelay("0.01ms");
    int packetSize = 1024;
    std::string onOffDataRate("1Mbps");
    std::string maxBytes("0");

    LogComponentEnable("TOPOFATTREE", LOG_LEVEL_DEBUG);
    // LogComponentEnable("BridgeNetDevice",LOG_LEVEL_LOGIC);

    CommandLine cmd;
    cmd.AddValue("podnum", "Numbers of built tree topo levels", podNum);
    cmd.Parse(argc, argv);

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

    // Initialize Internet Stack and Routing Protocols
    //
    InternetStackHelper internet;
    Ipv4NixVectorHelper nixRouting;
    Ipv4GlobalRoutingHelper globalRouting;
    // Ipv4StaticRoutingHelper staticRouting;

    Ipv4ListRoutingHelper Routinglist;
    Routinglist.Add(globalRouting, 0);
    Routinglist.Add(nixRouting, 10);
    internet.SetRoutingHelper(Routinglist);
    internet.Install(hosts);

    //=========== Connect aggregate switches to edge switches, edge switches to hosts  ===========//
    unsigned int curAggrSwitchIndex;
    unsigned int curEdgeSwitchIndex;
    unsigned int aggrLinkEdgeSwitchIndex;
    unsigned int edgeLinkHostIndex;

    Ipv4AddressHelper ipv4;
    // ipv4.SetBase("10.0.0.0","255.255.255.0","0.0.0.2");
    for (unsigned int i = 0; i < podNum; i++) // number pod
    {
        for (unsigned int j = 0; j < halfPodNum; j++) // number switch in pod
        {
            // set host ip base
            ipv4.SetBase(GetHostIpAddrBase(i, j), "255.255.255.0");

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
                // assign host ip
                hostInfos[edgeLinkHostIndex].hostIpv4 =
                    ipv4.Assign(hostInfos[edgeLinkHostIndex].hostDevice);

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

    //=========== Bridge switch and switch devices  ===========//
    BridgeHelper bridge;
    for (unsigned int i = 0; i < switchNum; i++)
    {
        bridge.Install(switches.Get(i), switchInfos[i].switchDevices);
    }

    //=========== Show switch and host info  ===========//
    ShowSwitchHostInfo(switchInfos, hostInfos);

    std::cout << "Using Bridge with L2 fat tree will cause error!!!!!" << std::endl;

    //=========== Build OnOff applications  ===========//

    ApplicationContainer apps;
    unsigned int halfHostNum = hostNum / 2;
    for (unsigned int i = 0; i < halfHostNum; i++)
    {
        unsigned int serverI = hostNum - i - 1;
        Ipv4Address serverAddr = hostInfos[serverI].hostIpv4.GetAddress(0);
        InetSocketAddress dst = InetSocketAddress(serverAddr);

        OnOffHelper onOff = OnOffHelper("ns3::TcpSocketFactory", dst);
        onOff.SetAttribute("PacketSize", UintegerValue(packetSize));
        onOff.SetAttribute("DataRate", StringValue(onOffDataRate));
        onOff.SetAttribute("MaxBytes", StringValue(maxBytes));

        apps = onOff.Install(hosts.Get(i));
        apps.Start(Seconds(1.0));
        apps.Stop(Seconds(10.0));

        PacketSinkHelper sink = PacketSinkHelper("ns3::TcpSocketFactory", dst);
        apps = sink.Install(hosts.Get(serverI));
        apps.Start(Seconds(0.0));
        apps.Stop(Seconds(11.0));

        NS_LOG_DEBUG("Data send from client " << i << " to the server " << serverI);
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    csma.EnablePcapAll("topo-fattree", false);

    // Test to print all the applications and types.
    // std::cout << "=================" << std::endl;
    // for (uint32_t nodeId = 0; nodeId < ns3::NodeList::GetNNodes(); ++nodeId)
    // {
    //     Ptr<ns3::Node> node = ns3::NodeList::GetNode(nodeId);
    //     std::cout << "Node " << nodeId << " has " << node->GetNApplications()
    //               << " application(s):" << std::endl;

    //     for (uint32_t appId = 0; appId < node->GetNApplications(); ++appId)
    //     {
    //         Ptr<ns3::Application> app = node->GetApplication(appId);
    //         std::cout << "  App[" << appId << "]: " << app->GetInstanceTypeId().GetName()
    //                   << std::endl;
    //     }
    // }
    // std::cout << "=================" << std::endl;

    Config::ConnectWithoutContext("/NodeList/8/ApplicationList/0/$ns3::PacketSink/Rx",
                                  MakeCallback(&SinkRx));

    // Config::Connect("/NodeList/*/ApplicationList/*/$ns3::V4Ping/Rtt", MakeCallback(&PingRtt));
    Packet::EnablePrinting();

    unsigned long simulateStart = getTickCount();
    Simulator::Run();
    Simulator::Destroy();
    // NS_LOG_INFO("Done.");
    unsigned long end = getTickCount();

    std::cout << "Host Num: " << hostNum << " Switch Num: " << switchNum << std::endl;
    std::cout << "Program Running time: " << end - mainStart << "ms" << std::endl;
    std::cout << "Simulate Running time: " << end - simulateStart << "ms" << std::endl;
}
