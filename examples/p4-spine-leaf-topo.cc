#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
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

NS_LOG_COMPONENT_DEFINE("SpineLeafTopology");

unsigned long start = getTickCount();
double global_start_time = 1.0;
double sink_start_time = global_start_time + 1.0;
double client_start_time = sink_start_time + 1.0;
double client_stop_time = client_start_time + 60;
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

struct SwitchInfoTracing
{
    bool first_tx = true;
    bool first_rx = true;
    int counter_sender_10 = 2;
    int counter_receiver_10 = 2;
    uint64_t totalTxBytes = 0;
    uint64_t totalTxBytes_lasttime = 0;
    uint64_t totalRxBytes = 0;
    uint64_t totalRxBytes_lasttime = 0;
    uint64_t totalPackets = 0;
    uint64_t totalPackets_lasttime = 0;
    double first_packet_send_time_tx = 0.0;
    double last_packet_send_time_tx = 0.0;
    double first_packet_received_time_rx = 0.0;
    double last_packet_received_time_rx = 0.0;
};

SwitchInfoTracing switch2;
SwitchInfoTracing switch3;
SwitchInfoTracing switch0;
SwitchInfoTracing switch5;

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

void
RxCallback_switch_2(Ptr<const Packet> packet)
{
    switch2.totalPackets++;
    if (switch2.first_rx)
    {
        // here we just simple jump the first 10 pkts (include some of ARP packets)
        switch2.first_packet_received_time_rx = Simulator::Now().GetSeconds();
        switch2.counter_receiver_10--;
        if (switch2.counter_receiver_10 == 0)
        {
            switch2.first_rx = false;
        }
    }
    else
    {
        switch2.totalRxBytes += packet->GetSize();
        switch2.last_packet_received_time_rx = Simulator::Now().GetSeconds();
    }
    NS_LOG_DEBUG("Packet transmitted. Size: " << packet->GetSize()
                                              << " bytes, Total packets: " << switch2.totalPackets
                                              << ", Total bytes: " << switch2.totalRxBytes);
}

void
RxCallback_switch_3(Ptr<const Packet> packet)
{
    switch3.totalPackets++;
    if (switch3.first_rx)
    {
        // here we just simple jump the first 10 pkts (include some of ARP packets)
        switch3.first_packet_received_time_rx = Simulator::Now().GetSeconds();
        switch3.counter_receiver_10--;
        if (switch3.counter_receiver_10 == 0)
        {
            switch3.first_rx = false;
        }
    }
    else
    {
        switch3.totalRxBytes += packet->GetSize();
        switch3.last_packet_received_time_rx = Simulator::Now().GetSeconds();
    }
    NS_LOG_DEBUG("Packet transmitted. Size: " << packet->GetSize()
                                              << " bytes, Total packets: " << switch3.totalPackets
                                              << ", Total bytes: " << switch3.totalRxBytes);
}

void
RxCallback_switch_0(Ptr<const Packet> packet)
{
    switch0.totalPackets++;
    if (switch0.first_rx)
    {
        // here we just simple jump the first 10 pkts (include some of ARP packets)
        switch0.first_packet_received_time_rx = Simulator::Now().GetSeconds();
        switch0.counter_receiver_10--;
        if (switch0.counter_receiver_10 == 0)
        {
            switch0.first_rx = false;
        }
    }
    else
    {
        switch0.totalRxBytes += packet->GetSize();
        switch0.last_packet_received_time_rx = Simulator::Now().GetSeconds();
    }
    NS_LOG_DEBUG("Packet transmitted. Size: " << packet->GetSize()
                                              << " bytes, Total packets: " << switch0.totalPackets
                                              << ", Total bytes: " << switch0.totalRxBytes);
}

void
TxCallback_switch_5(Ptr<const Packet> packet)
{
    switch5.totalPackets++;
    if (switch5.first_tx)
    {
        // here we just simple jump the first 10 pkts (include some of ARP packets)
        switch5.first_packet_send_time_tx = Simulator::Now().GetSeconds();
        switch5.counter_receiver_10--;
        if (switch5.counter_receiver_10 == 0)
        {
            switch5.first_tx = false;
        }
    }
    else
    {
        switch5.totalTxBytes += packet->GetSize();
        switch5.last_packet_send_time_tx = Simulator::Now().GetSeconds();
    }
    NS_LOG_DEBUG("Packet transmitted. Size: " << packet->GetSize()
                                              << " bytes, Total packets: " << switch5.totalPackets
                                              << ", Total bytes: " << switch5.totalTxBytes);
}

// 统计吞吐量并打印
void
CalculateThroughput()
{
    double currentTime = Simulator::Now().GetSeconds();

    double throughput_switch0 =
        ((switch0.totalRxBytes - switch0.totalRxBytes_lasttime) * 8.0) / 1e6; // Mbps
    double throughput_switch2 =
        ((switch2.totalRxBytes - switch2.totalRxBytes_lasttime) * 8.0) / 1e6; // Mbps
    double throughput_switch3 =
        ((switch3.totalRxBytes - switch3.totalRxBytes_lasttime) * 8.0) / 1e6; // Mbps
    double throughput_switch5 =
        ((switch5.totalTxBytes - switch5.totalTxBytes_lasttime) * 8.0) / 1e6; // Mbps

    switch0.totalRxBytes_lasttime = switch0.totalRxBytes;
    switch2.totalRxBytes_lasttime = switch2.totalRxBytes;
    switch3.totalRxBytes_lasttime = switch3.totalRxBytes;
    switch5.totalTxBytes_lasttime = switch5.totalTxBytes;

    // 打印吞吐量信息
    NS_LOG_INFO("Time: " << currentTime << "s | Throughput (Mbps) - " << "Switch0(Rx): "
                         << throughput_switch0 << ", " << "Switch2(Rx): " << throughput_switch2
                         << ", " << "Switch3(Rx): " << throughput_switch3 << ", "
                         << "Switch5(Tx): " << throughput_switch5);

    // 追加写入文件
    std::ofstream outFile("throughput_log_1.txt", std::ios::app);
    if (outFile.is_open())
    {
        outFile << currentTime << " " << throughput_switch0 << " " << throughput_switch2 << " "
                << throughput_switch3 << " " << throughput_switch5 << "\n";
        outFile.close();
    }
    else
    {
        NS_LOG_ERROR("Unable to open file for writing.");
    }

    // 每秒再次调用自身
    Simulator::Schedule(Seconds(1.0), &CalculateThroughput);
}

int
main(int argc, char* argv[])
{
    LogComponentEnable("SpineLeafTopology", LOG_LEVEL_INFO);

    int running_number = 0;
    uint16_t pktSize = 1000; // in Bytes. 1458 to prevent fragments, default 512
    int model = 0;
    std::string appDataRate = "10Mbps"; // Default application data rate
    bool enableTracePcap = false;

    // Use P4SIM_DIR environment variable for portable paths
    std::string p4SrcDir = GetP4ExamplePath() + "/load_balance";
    std::string p4JsonPath = p4SrcDir + "/load_balance.json";
    std::string flowTableDirPath = p4SrcDir + "/";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat("P2PTopo");

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
    // CsmaHelper csma;
    // csma.SetChannelAttribute("DataRate", StringValue("10Gbps"));
    // csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(10)));
    P4PointToPointHelper p4p2p;
    p4p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate("10Gbps")));
    p4p2p.SetChannelAttribute("Delay", TimeValue(NanoSeconds(10)));

    P4TopologyReader::ConstLinksIterator_t iter;
    SwitchNodeC_t switchNodes[switchNum];
    HostNodeC_t hostNodes[hostNum];
    unsigned int fromIndex, toIndex;
    std::string dataRate, delay;
    for (iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); iter++)
    {
        if (iter->GetAttributeFailSafe("DataRate", dataRate))
        {
            p4p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate(dataRate)));
            NS_LOG_INFO("DataRate: " << dataRate);
        }
        if (iter->GetAttributeFailSafe("Delay", delay))
        {
            p4p2p.SetChannelAttribute("Delay", StringValue(delay));
            NS_LOG_INFO("Delay: " << delay);
        }

        fromIndex = iter->GetFromIndex();
        toIndex = iter->GetToIndex();
        NetDeviceContainer link =
            p4p2p.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

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
        uint32_t nodeId = terminals.Get(i)->GetId();

        NS_LOG_INFO("Host " << (i + switchNum) << " (Node ID: " << nodeId
                            << ") connected to Switch " << hostNodes[i].linkSwitchIndex
                            << " at Port " << hostNodes[i].linkSwitchPort);
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
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(1)); // p2p channel
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));
    // p4SwitchHelper.SetDeviceAttribute(
    //     "SwitchRate",
    //     UintegerValue(1300000)); // 1.25 * 10^6 pps for 10Gbps with each packet 1000Bytes
    // // p4SwitchHelper.SetDeviceAttribute("SwitchRate", UintegerValue(10000));

    for (unsigned int i = 0; i < switchNum; i++)
    {
        if (i >= 4)
        {
            // s4, s5 are leaf switches, not using for simulation.
            p4SwitchHelper.SetDeviceAttribute("SwitchRate", UintegerValue(1000));
        }
        else
        {
            p4SwitchHelper.SetDeviceAttribute("SwitchRate", UintegerValue(1300000));
        }
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
    uint16_t servPortStart = 9000;
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
        // 设置开启时间 (OnTime) 和 关闭时间 (OffTime) 为随机分布
        // 创建随机变量并设置不同种子
        Ptr<ExponentialRandomVariable> onTime = CreateObject<ExponentialRandomVariable>();
        Ptr<ExponentialRandomVariable> offTime = CreateObject<ExponentialRandomVariable>();

        onTime->SetAttribute("Mean", DoubleValue(2.0));
        offTime->SetAttribute("Mean", DoubleValue(1.0));

        // 为每个流分配一个唯一的种子
        onTime->SetAttribute(
            "Stream",
            IntegerValue(servPortStart)); // flowId should be different for each flow
        offTime->SetAttribute("Stream", IntegerValue(servPortStart + 1000)); // Avoid overlap

        // 将变量绑定到 OnOffApplication
        onOff.SetAttribute("OnTime", PointerValue(onTime));
        onOff.SetAttribute("OffTime", PointerValue(offTime));

        // onOff.SetAttribute("MaxBytes", UintegerValue(5000));

        ApplicationContainer app = onOff.Install(terminals.Get(clientI));
        app.Start(Seconds(client_start_time));
        app.Stop(Seconds(client_stop_time));
    }

    // Add call back for netdevice we want to trace
    Ptr<NetDevice> netDevice0 = switchNodes[0].switchDevices.Get(0); // switch 0 port 0
    Ptr<CustomP2PNetDevice> customNetDevice0 = DynamicCast<CustomP2PNetDevice>(netDevice0);
    if (customNetDevice0)
    {
        NS_LOG_INFO("TraceConnectWithoutContext for switch 0.");
        customNetDevice0->TraceConnectWithoutContext("MacRx", MakeCallback(&RxCallback_switch_0));
    }

    Ptr<NetDevice> netDevice = switchNodes[2].switchDevices.Get(0); // switch 2 port 0
    Ptr<CustomP2PNetDevice> customNetDevice = DynamicCast<CustomP2PNetDevice>(netDevice);
    if (customNetDevice)
    {
        NS_LOG_INFO("TraceConnectWithoutContext for switch 2.");
        customNetDevice->TraceConnectWithoutContext("MacRx", MakeCallback(&RxCallback_switch_2));
    }

    Ptr<NetDevice> netDevice2 = switchNodes[3].switchDevices.Get(0); // switch 3 port 0
    Ptr<CustomP2PNetDevice> customNetDevice2 = DynamicCast<CustomP2PNetDevice>(netDevice2);
    if (customNetDevice2)
    {
        NS_LOG_INFO("TraceConnectWithoutContext for switch 3.");
        customNetDevice2->TraceConnectWithoutContext("MacRx", MakeCallback(&RxCallback_switch_3));
    }

    Ptr<NetDevice> netDevice5 = switchNodes[1].switchDevices.Get(0); // switch 1 port 0
    Ptr<CustomP2PNetDevice> customNetDevice5 = DynamicCast<CustomP2PNetDevice>(netDevice5);
    if (customNetDevice5)
    {
        NS_LOG_INFO("TraceConnectWithoutContext for switch 5.");
        customNetDevice5->TraceConnectWithoutContext("MacTx", MakeCallback(&TxCallback_switch_5));
    }

    if (enableTracePcap)
    {
        p4p2p.EnablePcapAll("p4-spine-leaf-topo");
    }

    // // === Setup Tracing ===
    // 启动吞吐量统计
    Simulator::Schedule(Seconds(1.0), &CalculateThroughput);

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
