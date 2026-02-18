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
 *
 */

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/custom-p2p-net-device.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/network-module.h"
#include "ns3/on-off-helper.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-p2p-channel.h"
#include "ns3/p4-p2p-helper.h"
#include "ns3/p4-topology-reader-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"

#include <filesystem>
#include <iomanip>
using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4LinkMonitoring");

// Convert IP address to hexadecimal format
std::string
ConvertIpToHex(Ipv4Address ipAddr)
{
    std::ostringstream hexStream;
    uint32_t ip = ipAddr.Get(); // Get the IP address as a 32-bit integer
    hexStream << "0x" << std::hex << std::setfill('0') << std::setw(2)
              << ((ip >> 24) & 0xFF)                 // First byte
              << std::setw(2) << ((ip >> 16) & 0xFF) // Second byte
              << std::setw(2) << ((ip >> 8) & 0xFF)  // Third byte
              << std::setw(2) << (ip & 0xFF);        // Fourth byte
    return hexStream.str();
}

// Convert MAC address to hexadecimal format
std::string
ConvertMacToHex(Address macAddr)
{
    std::ostringstream hexStream;
    Mac48Address mac = Mac48Address::ConvertFrom(macAddr); // Convert Address to Mac48Address
    uint8_t buffer[6];
    mac.CopyTo(buffer); // Copy MAC address bytes into buffer

    hexStream << "0x";
    for (int i = 0; i < 6; ++i)
    {
        hexStream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buffer[i]);
    }
    return hexStream.str();
}

// ============================ data struct ============================
struct SwitchNodeC_t
{
    NetDeviceContainer switchDevices;
    std::vector<std::string> switchPortInfos;
};

struct HostNodeC_t
{
    NetDeviceContainer hostDevice;
    Ipv4InterfaceContainer hostIpv4;
    unsigned int linkSwitchIndex;
    unsigned int linkSwitchPort;
    std::string hostIpv4Str;
};

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4LinkMonitoring", LOG_LEVEL_INFO);

    // ============================ parameters ============================

    int running_number = 0;
    uint16_t pktSize = 512;              // in Bytes. 1458 to prevent fragments, default 512
    std::string appDataRate = "4096bps"; // Default application data rate
    std::string ns3_link_rate = "1000Mbps";
    bool enableTracePcap = true;

    // Use P4SIM_DIR environment variable for portable paths
    std::string p4SrcDir = GetP4ExamplePath() + "/link_monitor";
    std::string p4JsonPath = p4SrcDir + "/link_monitor.json";
    std::string flowTableDirPath = p4SrcDir + "/";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat("CsmaTopo");

    // ============================  command line ============================
    CommandLine cmd;
    cmd.AddValue("runnum", "running number in loops", running_number);
    cmd.AddValue("pktSize", "Packet size in bytes (default 1000)", pktSize);
    cmd.AddValue("pcap", "Trace packet pacp [true] or not[false]", enableTracePcap);
    cmd.Parse(argc, argv);

    // ============================ topo -> network ============================

    P4TopologyReaderHelper p4TopoHelper;
    p4TopoHelper.SetFileName(topoInput);
    p4TopoHelper.SetFileType(topoFormat);
    NS_LOG_INFO("*** Reading topology from file: " << topoInput << " with format: " << topoFormat);

    // Get the topology reader, and read the file, load in the m_linksList.
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
    P4PointToPointHelper p4p2phelper;
    p4p2phelper.SetChannelAttribute("Delay", TimeValue(MilliSeconds(0.01)));

    P4TopologyReader::ConstLinksIterator_t iter;
    SwitchNodeC_t switchNodes[switchNum];
    HostNodeC_t hostNodes[hostNum];
    unsigned int fromIndex, toIndex;
    std::string dataRate, delay;
    for (iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); iter++)
    {
        fromIndex = iter->GetFromIndex();
        toIndex = iter->GetToIndex();
        NetDeviceContainer link =
            p4p2phelper.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

        if (iter->GetFromType() == 's' && iter->GetToType() == 's')
        {
            NS_LOG_INFO("*** Link from  switch " << fromIndex << " to  switch " << toIndex
                                                 << " with data rate " << dataRate << " and delay "
                                                 << delay);

            unsigned int fromSwitchPortNumber = switchNodes[fromIndex].switchDevices.GetN();
            unsigned int toSwitchPortNumber = switchNodes[toIndex].switchDevices.GetN();
            switchNodes[fromIndex].switchDevices.Add(link.Get(0));
            switchNodes[fromIndex].switchPortInfos.push_back("s" + UintToString(toIndex) + "_" +
                                                             UintToString(toSwitchPortNumber));

            switchNodes[toIndex].switchDevices.Add(link.Get(1));
            switchNodes[toIndex].switchPortInfos.push_back("s" + UintToString(fromIndex) + "_" +
                                                           UintToString(fromSwitchPortNumber));
        }
        else
        {
            if (iter->GetFromType() == 's' && iter->GetToType() == 'h')
            {
                NS_LOG_INFO("*** Link from switch " << fromIndex << " to  host" << toIndex
                                                    << " with data rate " << dataRate
                                                    << " and delay " << delay);

                unsigned int fromSwitchPortNumber = switchNodes[fromIndex].switchDevices.GetN();
                switchNodes[fromIndex].switchDevices.Add(link.Get(0));
                switchNodes[fromIndex].switchPortInfos.push_back("h" +
                                                                 UintToString(toIndex - switchNum));

                hostNodes[toIndex - switchNum].hostDevice.Add(link.Get(1));
                hostNodes[toIndex - switchNum].linkSwitchIndex = fromIndex;
                hostNodes[toIndex - switchNum].linkSwitchPort = fromSwitchPortNumber;
            }
            else
            {
                if (iter->GetFromType() == 'h' && iter->GetToType() == 's')
                {
                    NS_LOG_INFO("*** Link from host " << fromIndex << " to  switch" << toIndex
                                                      << " with data rate " << dataRate
                                                      << " and delay " << delay);
                    unsigned int toSwitchPortNumber = switchNodes[toIndex].switchDevices.GetN();
                    switchNodes[toIndex].switchDevices.Add(link.Get(1));
                    switchNodes[toIndex].switchPortInfos.push_back(
                        "h" + UintToString(fromIndex - switchNum));

                    hostNodes[fromIndex - switchNum].hostDevice.Add(link.Get(0));
                    hostNodes[fromIndex - switchNum].linkSwitchIndex = toIndex;
                    hostNodes[fromIndex - switchNum].linkSwitchPort = toSwitchPortNumber;
                }
                else
                {
                    NS_LOG_ERROR("link error!");
                    abort();
                }
            }
        }
    }
    // ======================== Print the Channel Type and NetDevice Type ========================

    InternetStackHelper internet;
    internet.Install(terminals);
    internet.Install(switchNode);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    std::vector<Ipv4InterfaceContainer> terminalInterfaces(hostNum);
    std::vector<std::string> hostIpv4(hostNum);

    for (unsigned int i = 0; i < hostNum; i++)
    {
        terminalInterfaces[i] = ipv4.Assign(terminals.Get(i)->GetDevice(0));
        hostIpv4[i] = Uint32IpToHex(terminalInterfaces[i].GetAddress(0).Get());
    }

    //===============================  Print IP and MAC addresses===============================
    NS_LOG_INFO("Node IP and MAC addresses:");
    for (uint32_t i = 0; i < terminals.GetN(); ++i)
    {
        Ptr<Node> node = terminals.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        Ptr<NetDevice> netDevice = node->GetDevice(0);

        // Get the IP address
        Ipv4Address ipAddr =
            ipv4->GetAddress(1, 0)
                .GetLocal(); // Interface index 1 corresponds to the first assigned IP

        // Get the MAC address
        Ptr<NetDevice> device = node->GetDevice(0); // Assuming the first device is the desired one
        Mac48Address mac = Mac48Address::ConvertFrom(device->GetAddress());

        NS_LOG_INFO("Node " << i << ": IP = " << ipAddr << ", MAC = " << mac);

        // Convert to hexadecimal
        std::string ipHex = ConvertIpToHex(ipAddr);
        std::string macHex = ConvertMacToHex(mac);
        NS_LOG_INFO("Node " << i << ": IP = " << ipHex << ", MAC = " << macHex);
    }

    // Bridge or P4 switch configuration
    P4Helper p4SwitchHelper;
    p4SwitchHelper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(0));
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(1));

    for (unsigned int i = 0; i < switchNum; i++)
    {
        std::string flowTablePath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", \n " << flowTablePath);

        p4SwitchHelper.Install(switchNode.Get(i), switchNodes[i].switchDevices);
    }

    // ============================ add custom header for the p4 switch ============================

    CustomHeader probeHeader;
    probeHeader.SetLayer(HeaderLayer::LAYER_3); // Network Layer
    probeHeader.SetOperator(ADD_AFTER);         // add before the ipv4 header

    probeHeader.AddField("proto_id", 16);
    probeHeader.AddField("hop_cnt", 8);
    probeHeader.AddField("bos", 1);
    probeHeader.AddField("swid", 7);
    probeHeader.AddField("port", 8);
    probeHeader.AddField("byte_cnt", 32);
    probeHeader.AddField("last_time", 48);
    probeHeader.AddField("cur_time", 48);

    for (unsigned int i = 0; i < 9; i++)
    {
        std::string field_name = "field" + std::to_string(i);
        probeHeader.AddField(field_name, 8);
    }

    probeHeader.SetField("proto_id", 0x0800);
    probeHeader.SetField("hop_cnt", 0);
    std::vector<int> forward_egress = {4, 1, 4, 1, 3, 2, 3, 2, 1};

    for (unsigned int i = 0; i < 9; i++)
    {
        probeHeader.SetField("field" + std::to_string(i), forward_egress[i]);
    }

    for (unsigned int i = 0; i < hostNum; i++)
    {
        Ptr<NetDevice> device = hostNodes[i].hostDevice.Get(0);
        if (device->GetObject<CustomP2PNetDevice>())
        {
            NS_LOG_DEBUG(
                "Host " << i << " NetDevice is CustomP2PNetDevice, Setting for the Tunnel Header!");
            Ptr<CustomP2PNetDevice> customDevice = DynamicCast<CustomP2PNetDevice>(device);
            customDevice->SetWithCustomHeader(true);
            customDevice->SetCustomHeader(probeHeader);
        }
    }

    // ============================ add application to the hosts ============================

    // TUNNEL stream == First == send link h0 -----> h0
    unsigned int clientI = 1;
    unsigned int serverI = 1;

    uint16_t servPort = 12000; // setting for port

    Ptr<Node> node = terminals.Get(serverI);
    Ptr<Ipv4> ipv4_adder = node->GetObject<Ipv4>();
    Ipv4Address serverAddr1 =
        ipv4_adder->GetAddress(1, 0)
            .GetLocal(); // Interface index 1 corresponds to the first assigned IP
    InetSocketAddress dst1 = InetSocketAddress(serverAddr1, servPort);
    PacketSinkHelper sink1 = PacketSinkHelper("ns3::UdpSocketFactory", dst1);
    ApplicationContainer sinkApp1 = sink1.Install(terminals.Get(serverI));

    sinkApp1.Start(Seconds(1));
    sinkApp1.Stop(Seconds(30));

    OnOffHelper onOff1("ns3::UdpSocketFactory", dst1);
    onOff1.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff1.SetAttribute("DataRate", StringValue(appDataRate));
    onOff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));

    ApplicationContainer app1 = onOff1.Install(terminals.Get(clientI));
    app1.Start(Seconds(3));
    app1.Stop(Seconds(30));

    // Enable pcap tracing
    p4p2phelper.EnablePcapAll("p4-link-monitoring");

    // Run simulation
    NS_LOG_INFO("Running simulation...");
    Simulator::Stop(Seconds(30));
    Simulator::Run();
    Simulator::Destroy();
    NS_LOG_INFO("Run successfully!");

    return 0;
}
