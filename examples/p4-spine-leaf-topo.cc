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

NS_LOG_COMPONENT_DEFINE("SpineLeafTopology");

unsigned long start = getTickCount();
double global_start_time = 1.0;
double sink_start_time = global_start_time + 1.0;
double client_start_time = sink_start_time + 1.0;
double client_stop_time = client_start_time + 3; // sending time 30s
double sink_stop_time = client_stop_time + 5;
double global_stop_time = sink_stop_time + 5;

bool first_tx = true;
bool first_rx = true;
int counter_sender_10 = 10;
int counter_receiver_10 = 10;
double first_packet_send_time_tx = 0.0;
double last_packet_send_time_tx = 0.0;
double first_packet_received_time_rx = 0.0;
double last_packet_received_time_rx = 0.0;
uint64_t totalTxBytes = 0;
uint64_t totalRxBytes = 0;

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
    LogComponentEnable("SpineLeafTopology", LOG_LEVEL_INFO);

    int running_number = 0;
    uint16_t pktSize = 1000; // in Bytes. 1458 to prevent fragments, default 512
    int model = 0;
    std::string appDataRate = "10Mbps"; // Default application data rate
    bool enableTracePcap = true;

    std::string p4JsonPath =
        "/home/p4/workdir/ns-3-dev-git/contrib/p4sim/examples/p4src/load_balance/load_balance.json";
    std::string flowTableDirPath =
        "/home/p4/workdir/ns-3-dev-git/contrib/p4sim/examples/p4src/load_balance/";
    std::string topoInput =
        "/home/p4/workdir/ns-3-dev-git/contrib/p4sim/examples/p4src/load_balance/topo.txt";
    std::string topoFormat("CsmaTopo");

    // ============================  command line ============================
    CommandLine cmd;
    cmd.AddValue("runnum", "running number in loops", running_number);
    cmd.AddValue("model", "running simulation with p4switch: 0, with ns-3 bridge: 1", model);
    cmd.AddValue("pktSize", "Packet size in bytes (default 1000)", pktSize);
    cmd.AddValue("appDataRate", "Application data rate in bps (default 1Mbps)", appDataRate);
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
    CsmaHelper csma;

    P4TopologyReader::ConstLinksIterator_t iter;
    SwitchNodeC_t switchNodes[switchNum];
    HostNodeC_t hostNodes[hostNum];
    unsigned int fromIndex, toIndex;
    std::string dataRate, delay;
    for (iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); iter++)
    {
        if (iter->GetAttributeFailSafe("DataRate", dataRate))
            csma.SetChannelAttribute("DataRate", StringValue(dataRate));
        if (iter->GetAttributeFailSafe("Delay", delay))
            csma.SetChannelAttribute("Delay", StringValue(delay));

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
    // ===================print topo info===================
    // 打印交换机端口连接情况
    NS_LOG_INFO("\n=========== Switch Port Connection Details ===========");
    for (unsigned int i = 0; i < switchNum; i++)
    {
        NS_LOG_INFO("Switch " << i << " has " << switchNodes[i].switchDevices.GetN() << " ports:");
        for (unsigned int j = 0; j < switchNodes[i].switchDevices.GetN(); j++)
        {
            NS_LOG_INFO("  - Port " << j << " connected to " << switchNodes[i].switchPortInfos[j]);
        }
    }

    // 打印主机连接情况
    NS_LOG_INFO("\n=========== Host Connection Details ===========");
    for (unsigned int i = 0; i < hostNum; i++)
    {
        NS_LOG_INFO("Host " << (i + switchNum) << " connected to Switch "
                            << hostNodes[i].linkSwitchIndex << " at Port "
                            << hostNodes[i].linkSwitchPort);
    }

    // ========================Print the Channel Type and NetDevice Type========================

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

    NS_LOG_INFO("\n=========== Switch Port IP and MAC Addresses ===========");
    for (unsigned int i = 0; i < switchNum; i++)
    {
        NS_LOG_INFO("Switch " << i << " Interface Details:");

        for (unsigned int j = 0; j < switchNodes[i].switchDevices.GetN(); j++)
        {
            Ptr<NetDevice> netDevice = switchNodes[i].switchDevices.Get(j);
            Ptr<Ipv4> ipv4 = switchNode.Get(i)->GetObject<Ipv4>();

            // 获取 MAC 地址
            Mac48Address mac = Mac48Address::ConvertFrom(netDevice->GetAddress());

            // 获取 IP 地址
            Ipv4Address ipAddr = Ipv4Address("0.0.0.0"); // 默认值
            int32_t interfaceIndex = ipv4->GetInterfaceForDevice(netDevice);
            if (interfaceIndex != -1)
            {
                ipAddr = ipv4->GetAddress(interfaceIndex, 0).GetLocal();
            }

            NS_LOG_INFO("  - Port " << j << " | MAC: " << mac << " | IP: " << ipAddr);
        }
    }

    // Bridge or P4 switch configuration
    P4Helper p4SwitchHelper;
    p4SwitchHelper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(0));
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));

    for (unsigned int i = 0; i < switchNum; i++)
    {
        std::string flowTablePath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", \n " << flowTablePath
                                                    << " for switch " << i);

        p4SwitchHelper.Install(switchNode.Get(i), switchNodes[i].switchDevices);
    }

    // // === Configuration for Link: h0 -----> h1 ===
    // unsigned int serverI = 3;
    // unsigned int clientI = 0;
    // uint16_t servPort = 4500; // UDP port for the server

    // // === Retrieve Server Address ===
    // Ptr<Node> node = terminals.Get(serverI);
    // Ptr<Ipv4> ipv4_adder = node->GetObject<Ipv4>();
    // Ipv4Address serverAddr1 = ipv4_adder->GetAddress(1, 0).GetLocal();
    // InetSocketAddress dst1 = InetSocketAddress(serverAddr1, servPort);

    // // === Setup Packet Sink on Server ===
    // PacketSinkHelper sink1("ns3::UdpSocketFactory", dst1);
    // ApplicationContainer sinkApp1 = sink1.Install(terminals.Get(serverI));
    // sinkApp1.Start(Seconds(sink_start_time));
    // sinkApp1.Stop(Seconds(sink_stop_time));

    // // === Setup OnOff Application on Client ===
    // OnOffHelper onOff1("ns3::UdpSocketFactory", dst1);
    // onOff1.SetAttribute("PacketSize", UintegerValue(pktSize));
    // onOff1.SetAttribute("DataRate", StringValue(appDataRate));
    // onOff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    // onOff1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    // ApplicationContainer app1 = onOff1.Install(terminals.Get(clientI));
    // app1.Start(Seconds(client_start_time));
    // app1.Stop(Seconds(client_stop_time));

    unsigned int serverI = 3;
    unsigned int clientI = 0;
    uint16_t servPortStart = 9900;
    uint16_t servPortEnd = 10000;
    // unsigned int numFlows = servPortEnd - servPortStart; // 5000 flows

    Ptr<Node> serverNode = terminals.Get(serverI);
    Ptr<Ipv4> ipv4_adder = serverNode->GetObject<Ipv4>();
    Ipv4Address serverAddr = ipv4_adder->GetAddress(1, 0).GetLocal();

    // **创建 PacketSink 并绑定所有端口**
    PacketSinkHelper sink("ns3::UdpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), servPortStart));
    ApplicationContainer sinkApp = sink.Install(serverNode);
    sinkApp.Start(Seconds(sink_start_time));
    sinkApp.Stop(Seconds(sink_stop_time));

    // **创建多个 UDP 数据流**
    for (uint16_t port = servPortStart; port < servPortEnd; port++)
    {
        InetSocketAddress dst(serverAddr, port);

        // 配置客户端（OnOffApplication）
        OnOffHelper onOff("ns3::UdpSocketFactory", dst);
        onOff.SetAttribute("PacketSize", UintegerValue(pktSize));
        onOff.SetAttribute("DataRate", StringValue(appDataRate));
        onOff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onOff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        // onOff.SetAttribute("MaxBytes", UintegerValue(10000));

        ApplicationContainer app = onOff.Install(terminals.Get(clientI));
        app.Start(Seconds(client_start_time));
        app.Stop(Seconds(client_stop_time));
    }

    if (enableTracePcap)
    {
        csma.EnablePcapAll("p4-spine-leaf-topo");
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
