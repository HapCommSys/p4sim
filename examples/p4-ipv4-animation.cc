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

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-topology-reader-helper.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4Ipv4Animation");

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4Ipv4Animation", LOG_LEVEL_INFO);

    std::string ns3_link_rate = "1000Mbps";

    // Use P4SIM_DIR environment variable for portable paths
    // NOTE: original path was test/test_simple which no longer exists.
    // Update the subdirectory below to match your actual P4 program location.
    std::string p4SrcDir = GetP4ExamplePath() + "/simple_v1model";
    std::string p4JsonPath = p4SrcDir + "/simple_v1model.json";
    std::string flowTablePath = p4SrcDir + "/flowtable_0.txt";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat("CsmaTopo");

    // ============================ topo -> network ============================

    P4TopologyReaderHelper p4TopoHelper;
    p4TopoHelper.SetFileName(topoInput);
    p4TopoHelper.SetFileType(topoFormat);
    NS_LOG_INFO("*** Reading topology from file: " << topoInput << " with format: " << topoFormat);

    Ptr<P4TopologyReader> topoReader = p4TopoHelper.GetTopologyReader();

    if (topoReader->LinksSize() == 0)
    {
        NS_LOG_ERROR("Problems reading the topology file. Failing.");
        return -1;
    }

    // get switch and host node
    NodeContainer terminals = topoReader->GetHostNodeContainer();
    NodeContainer switchNode = topoReader->GetSwitchNodeContainer();

    const unsigned int hostNum = terminals.GetN();
    const unsigned int switchNum = switchNode.GetN();
    NS_LOG_INFO("*** Host number: " << hostNum << ", Switch number: " << switchNum);

    // set default network link parameter
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(ns3_link_rate)); //@todo
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(0.01)));

    // 创建并安装网络设备
    NetDeviceContainer terminalDevices = csma.Install(terminals);
    NetDeviceContainer switchDevices = csma.Install(switchNode);
    uint32_t nTerminals = terminals.GetN();
    uint32_t nSwitches = switchNode.GetN();

    std::cout << "Number of Terminals: " << nTerminals << std::endl;
    std::cout << "Number of Switches: " << nSwitches << std::endl;

    // 安装网络协议栈
    InternetStackHelper internet;
    internet.Install(terminals);
    internet.Install(switchNode);

    // 分配 IP 地址
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    std::vector<Ipv4InterfaceContainer> terminalInterfaces(hostNum);
    std::vector<std::string> hostIpv4(hostNum);

    for (unsigned int i = 0; i < hostNum; i++)
    {
        terminalInterfaces[i] = ipv4.Assign(terminalDevices.Get(i));
        hostIpv4[i] = Uint32IpToHex(terminalInterfaces[i].GetAddress(0).Get());
    }

    // Bridge or P4 switch configuration
    P4Helper p4Bridge;
    p4Bridge.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4Bridge.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));

    NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", " << flowTablePath);

    for (unsigned int i = 0; i < switchNum; i++)
    {
        p4Bridge.Install(switchNode.Get(i), switchDevices.Get(i));
    }

    NS_LOG_INFO("*** P4 switch already configured with: " << p4JsonPath << ", " << flowTablePath);

    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    // Set constant position for terminals
    for (uint32_t i = 0; i < terminals.GetN(); ++i)
    {
        Ptr<Node> node = terminals.Get(i);
        mobility.Install(node);
        Ptr<ConstantPositionMobilityModel> pos = node->GetObject<ConstantPositionMobilityModel>();
        pos->SetPosition(Vector(10 * i, 10, 0)); // Adjust positions as needed
    }

    // Set constant position for switches
    for (uint32_t j = 0; j < switchNode.GetN(); ++j)
    {
        Ptr<Node> node = switchNode.Get(j);
        mobility.Install(node);
        Ptr<ConstantPositionMobilityModel> pos = node->GetObject<ConstantPositionMobilityModel>();
        pos->SetPosition(Vector(20 * j, 20, 0)); // Adjust positions as needed
    }
    // NetAnim Animation Setup
    AnimationInterface anim("topology.xml");

    // Set node positions for visualization
    for (uint32_t i = 0; i < nTerminals; ++i)
    {
        anim.SetConstantPosition(terminals.Get(i), 10 * i, 10);
    }
    for (uint32_t j = 0; j < nSwitches; ++j)
    {
        anim.SetConstantPosition(switchNode.Get(j), 20 * j, 20);
    }

    // Run simulation
    NS_LOG_INFO("Running simulation...");
    Simulator::Stop(Seconds(30));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
