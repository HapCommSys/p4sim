#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/build-flowtable-helper.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/custom-p2p-net-device.h"
#include "ns3/fattree-topo-helper.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-topology-reader-helper.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4TopoFattree");

unsigned long start = getTickCount();
double global_start_time = 1.0;
double sink_start_time = global_start_time + 1.0;
double client_start_time = sink_start_time + 1.0;
double client_stop_time = client_start_time + 2; // Client will send packets for 2 seconds
double sink_stop_time = client_stop_time + 5;
double global_stop_time = sink_stop_time + 5;

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

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4TopoFattree", LOG_LEVEL_INFO);
    LogComponentEnable("P4TopologyReader", LOG_LEVEL_INFO);

    int running_number = 0;
    int podNum = 2;
    bool enableBuildTableEntry = true;
    uint16_t pktSize = 1000; // in Bytes. 1458 to prevent fragments, default 512
    int model = 0;
    std::string appDataRate = "1Mbps"; // Default application data rate
    bool enableTracePcap = false;

    // Use P4SIM_DIR environment variable for portable paths
    std::string p4SrcDir = GetP4ExamplePath() + "/fat-tree";
    std::string p4JsonPath = p4SrcDir + "/switch.json";
    std::string flowTableDirPath = p4SrcDir + "/";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat("CsmaTopo");

    // ============================  command line ============================
    CommandLine cmd;
    cmd.AddValue("runnum", "running number in loops", running_number);
    cmd.AddValue("podnum", "Numbers of built tree topo levels", podNum);
    cmd.AddValue("tableEntry", "Build the table entry [true] or not[false]", enableBuildTableEntry);
    cmd.AddValue("model", "running simulation with p4switch: 0, with ns-3 bridge: 1", model);
    cmd.AddValue("pktSize", "Packet size in bytes (default 1000)", pktSize);
    cmd.AddValue("appDataRate", "Application data rate in bps (default 1Mbps)", appDataRate);
    cmd.AddValue("pcap", "Trace packet pacp [true] or not[false]", enableTracePcap);
    cmd.Parse(argc, argv);

    // ============================ config -> topo ============================

    /*
    You can build network topo by program or handwork, we use handwork to build topo to test
    topology reader program.
    */
    FattreeTopoHelper treeTopo(podNum, topoInput);
    // BinaryTreeTopoHelper treeTopo(podNum,topoPath);
    treeTopo.SetLinkDataRate("1000Mbps");
    treeTopo.SetLinkDelay("0.01ms");
    NS_LOG_INFO("*** Building topology with pod number: "
                << podNum << ", link data rate: " << treeTopo.GetLinkDataRate()
                << ", link delay: " << treeTopo.GetLinkDelay());
    NS_LOG_INFO("*** Writing topology to file: " << topoInput);
    treeTopo.Write();

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
    NodeContainer hosts = topoReader->GetHostNodeContainer();
    NodeContainer switchNode = topoReader->GetSwitchNodeContainer();

    const unsigned int hostNum = hosts.GetN();
    const unsigned int switchNum = switchNode.GetN();
    NS_LOG_INFO("*** Host number: " << hostNum << ", Switch number: " << switchNum);

    // set default network link parameter
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("1000Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(10)));
    // P4PointToPointHelper p4p2p;
    // p4p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate("10Gbps")));
    // p4p2p.SetChannelAttribute("Delay", TimeValue(NanoSeconds(10)));

    P4TopologyReader::ConstLinksIterator_t iter;
    SwitchNodeC_t switchNodes[switchNum];
    HostNodeC_t hostNodes[hostNum];
    unsigned int fromIndex, toIndex;
    std::string dataRate, delay;
    for (iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); iter++)
    {
        if (iter->GetAttributeFailSafe("DataRate", dataRate))
        {
            csma.SetChannelAttribute("DataRate", DataRateValue(DataRate(dataRate)));
            NS_LOG_INFO("DataRate: " << dataRate);
        }
        if (iter->GetAttributeFailSafe("Delay", delay))
        {
            csma.SetChannelAttribute("Delay", StringValue(delay));
            NS_LOG_INFO("Delay: " << delay);
        }

        fromIndex = iter->GetFromIndex();
        toIndex = iter->GetToIndex();
        NetDeviceContainer link =
            csma.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

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

    // // view host link info
    // for (unsigned int i = 0; i < hostNum; i++)
    //     std::cout << "h" << i << ": " << hostNodes[i].linkSwitchIndex << " "
    //               << hostNodes[i].linkSwitchPort << std::endl;

    // // view switch port info
    // for (unsigned int i = 0; i < switchNum; i++)
    // {
    //     std::cout << "s" << i << ": ";
    //     for (size_t k = 0; k < switchNodes[i].switchPortInfos.size(); k++)
    //         std::cout << switchNodes[i].switchPortInfos[k] << " ";
    //     std::cout << std::endl;
    // }

    // ===================print topo info===================
    NS_LOG_INFO("\n=========== Switch Port Connection Details ===========");
    for (unsigned int i = 0; i < switchNum; i++)
    {
        NS_LOG_INFO("Switch " << i << " (Node ID: " << switchNode.Get(i)->GetId() << ") has "
                              << switchNodes[i].switchDevices.GetN() << " ports:");

        for (unsigned int j = 0; j < switchNodes[i].switchDevices.GetN(); j++)
        {
            uint32_t netDeviceId =
                switchNodes[i].switchDevices.Get(j)->GetIfIndex(); // 获取 NetDevice ID
            NS_LOG_INFO("  - Port " << j << " (Device ID: " << netDeviceId << ") connected to "
                                    << switchNodes[i].switchPortInfos[j]);
        }
    }

    NS_LOG_INFO("\n=========== Host Connection Details ===========");
    for (unsigned int i = 0; i < hostNum; i++)
    {
        uint32_t nodeId = hosts.Get(i)->GetId();

        NS_LOG_INFO("Host " << (i + switchNum) << " (Node ID: " << nodeId
                            << ") connected to Switch " << hostNodes[i].linkSwitchIndex
                            << " at Port " << hostNodes[i].linkSwitchPort);
    }

    // ========================Print the Channel Type and NetDevice Type========================

    InternetStackHelper internet;
    internet.Install(hosts);
    // internet.Install(switchNode);

    NS_LOG_INFO("*** Installed Internet Stack on all nodes.");
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.0.0", "255.255.255.0");

    for (unsigned int i = 0; i < hostNum; i++)
    {
        hostNodes[i].hostIpv4 = ipv4.Assign(hostNodes[i].hostDevice);
        hostNodes[i].hostIpv4Str = Uint32IpToHex(hostNodes[i].hostIpv4.GetAddress(0).Get());
        std::cout << i << " " << hostNodes[i].hostIpv4Str << std::endl;
    }

    //===============================  Print IP and MAC addresses===============================
    NS_LOG_INFO("Node IP and MAC addresses:");
    for (uint32_t i = 0; i < hosts.GetN(); ++i)
    {
        Ptr<Node> node = hosts.Get(i);
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

    // =============================== Build the Flow Table Entries ===============================
    std::vector<unsigned int> linkSwitchIndex(hostNum);
    std::vector<unsigned int> linkSwitchPort(hostNum);
    std::vector<std::string> hostIpv4(hostNum);
    std::vector<std::vector<std::string>> switchPortInfo(switchNum);
    for (unsigned int i = 0; i < hostNum; i++)
    {
        linkSwitchIndex[i] = hostNodes[i].linkSwitchIndex;
        linkSwitchPort[i] = hostNodes[i].linkSwitchPort;
        hostIpv4[i] = hostNodes[i].hostIpv4Str;
    }
    for (unsigned int i = 0; i < switchNum; i++)
    {
        switchPortInfo[i] = switchNodes[i].switchPortInfos;
    }

    // build flow table entries by program
    if (enableBuildTableEntry)
    {
        NS_LOG_LOGIC("Build Flow table with Helper.");
        BuildFlowtableHelper flowtableHelper("fattree", podNum);
        flowtableHelper.Build(linkSwitchIndex, linkSwitchPort, hostIpv4, switchPortInfo);
        flowtableHelper.Write(flowTableDirPath);
        flowtableHelper.Show();
        NS_LOG_INFO("Flow table entries built successfully.");
    }

    // Bridge or P4 switch configuration
    P4Helper p4SwitchHelper;
    p4SwitchHelper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(0)); // CSMA
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));

    for (unsigned int i = 0; i < switchNum; i++)
    {
        p4SwitchHelper.SetDeviceAttribute("SwitchRate", UintegerValue(2000));

        std::string flowTablePath = flowTableDirPath + "flowtable_" + std::to_string(i);
        p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", \n " << flowTablePath
                                                    << " for switch " << i);

        p4SwitchHelper.Install(switchNode.Get(i), switchNodes[i].switchDevices);
    }

    NS_LOG_LOGIC("OnoffSink");
    // Config::SetDefault("ns3::Ipv4RawSocketImpl::Protocol", StringValue("2"));
    ApplicationContainer apps;
    unsigned int halfHostNum = hostNum / 2;
    for (unsigned int i = 0; i < halfHostNum; i++)
    {
        NS_LOG_INFO("Install OnOff application on host " << i << " to send packets to host "
                                                         << (hostNum - i - 1));
        // Install OnOff application on host i to send packets to host (hostNum - i - 1)
        // The host (hostNum - i - 1) is the server, and host i is the client.
        // The server is the last half of the hosts, and the client is the first half.
        // The server is the host with index (hostNum - i - 1), and the client is the host with
        // index i.
        unsigned int serverI = hostNum - i - 1;
        Ipv4Address serverAddr = hostNodes[serverI].hostIpv4.GetAddress(0);
        InetSocketAddress dst = InetSocketAddress(serverAddr);

        OnOffHelper onOff = OnOffHelper("ns3::UdpSocketFactory", dst);
        onOff.SetAttribute("PacketSize", UintegerValue(pktSize));
        onOff.SetAttribute("DataRate", StringValue(appDataRate));
        onOff.SetAttribute("MaxBytes", UintegerValue(1000));

        apps = onOff.Install(hosts.Get(i));
        apps.Start(Seconds(client_start_time));
        apps.Stop(Seconds(client_stop_time));

        PacketSinkHelper sink = PacketSinkHelper("ns3::UdpSocketFactory", dst);
        apps = sink.Install(hosts.Get(serverI));
        apps.Start(Seconds(sink_start_time));
        apps.Stop(Seconds(sink_stop_time));
    }

    if (enableTracePcap)
    {
        NS_LOG_INFO("Enable Pcap tracing for all devices.");
        csma.EnablePcapAll("p4-topo-fattree");
    }

    // Run simulation
    NS_LOG_INFO("Running simulation...");
    unsigned long simulate_start = getTickCount();
    Simulator::Stop(Seconds(global_stop_time));
    Simulator::Run();
    Simulator::Destroy();

    unsigned long end = getTickCount();
    NS_LOG_INFO("Simulate Running time: " << end - simulate_start << "ms" << std::endl
                                          << "Total Running time: " << end - start << "ms"
                                          << std::endl
                                          << "Run successfully!");

    return 0;
}
