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

/**
 * This example is same with "basic exerciese" in p4lang/tutorials
 * URL: https://github.com/p4lang/tutorials/tree/master/exercises/basic
 * The P4 program implements basic ipv4 forwarding, also with ARP.
 *
 *          ┌──────────┐              ┌──────────┐
 *          │ Switch 2 \\            /│ Switch 3 │
 *          └─────┬────┘  \        // └──────┬───┘
 *                │         \    /           │
 *                │           /              │
 *          ┌─────┴────┐   /   \      ┌──────┴───┐
 *          │ Switch 0 //         \ \ │ Switch 1 │
 *      ┌───┼          │             \\          ┼────┐
 *      │   └────────┬─┘              └┬─────────┘    │
 *  ┌───┼────┐     ┌─┴──────┐    ┌─────┼──┐     ┌─────┼──┐
 *  │ host 4 │     │ host 5 │    │ host 6 │     │ host 7 │
 *  └────────┘     └────────┘    └────────┘     └────────┘
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
#include "ns3/packet-socket-address.h"
#include "ns3/packet-socket-factory.h"
#include "ns3/packet-socket-helper.h"
#include "ns3/udp-header.h"
#include "ns3/ipv4-header.h"
#include "ns3/loopback-net-device.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("P4SrcRoutingExample");
// NS_LOG_COMPONENT_DEFINE("P4BasicExample");


class SrcRouteHeader : public Header
{
  public:
  struct Hop{
    uint16_t port;
    bool bos;
  };

  std::vector<Hop> hops;
    SrcRouteHeader() {}
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("SrcRouteHeader").SetParent<Header>().SetGroupName("Tutorial");
        return tid;
    }
    void AddHop(uint16_t port, bool bos) {
        Hop hop = {port, bos};
        hops.push_back(hop);
    }
    virtual TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    virtual void Print(std::ostream& os) const override { os << "SrcRouteHeader"; }
    virtual uint32_t GetSerializedSize() const override { return hops.size()*2; }
    virtual void Serialize(Buffer::Iterator start) const override {
        for (auto &h:hops){
            uint16_t val=(h.bos<<15) | (h.port & 0x7FFF);
            start.WriteHtonU16(val);
        }
    }
    virtual uint32_t Deserialize(Buffer::Iterator start) override { return 0; }
};

class SourceRoutingApp : public Application
{
public:
    SourceRoutingApp() = default;
    virtual ~SourceRoutingApp() = default;

    void Setup(
        Ipv4Address dst,
        uint16_t port,
        uint32_t pktSize,
        DataRate dataRate,
        std::vector<uint16_t> pathPorts)
    {
        m_dst = dst;
        m_port = port;
        m_pktSize = pktSize;
        m_dataRate = dataRate;
        m_pathPorts = pathPorts;
    }

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("SourceRoutingApp")
            .SetParent<Application>()
            .SetGroupName("Tutorial")
            .AddConstructor<SourceRoutingApp>()
            .AddTraceSource("Tx", "A new packet is created and is sent",
                            MakeTraceSourceAccessor(&SourceRoutingApp::m_txTrace),
                            "ns3::Packet::TracedCallback");
        return tid;
    }

private:
    void StartApplication() override
    {
    NS_ASSERT(GetNode());
    m_socket = Socket::CreateSocket(
        GetNode(), PacketSocketFactory::GetTypeId());

    NS_ASSERT(m_socket);


    
    // Find non-loopback device
    Ptr<NetDevice> targetDevice = nullptr;
    for (uint32_t i = 0; i < GetNode()->GetNDevices(); i++)
    {
        Ptr<NetDevice> d = GetNode()->GetDevice(i);
        if (!DynamicCast<LoopbackNetDevice>(d))
        {
            targetDevice = d;
            break;
        }
    }
    NS_ASSERT_MSG(targetDevice, "No suitable network device found");

    m_socketAddr.SetSingleDevice(targetDevice->GetIfIndex());
    m_socketAddr.SetPhysicalAddress(targetDevice->GetBroadcast());
    m_socketAddr.SetProtocol(0x1234);

    //m_socket->Connect(m_socketAddr);
    SendPacket();
    }

    void StopApplication() override
    {
        if (m_event.IsRunning()) {
            m_event.Cancel();
        }
        if (m_socket)
        {
            m_socket->Close();
            m_socket = nullptr;
        }
    }

    void SendPacket()
    {
        if(!m_socket)
            return;
        NS_LOG_INFO("Sending SR packet with "<<m_pathPorts.size()<<" hops to "<<m_dst);
        Ptr<Packet> pkt = Create<Packet>(m_pktSize);

        SrcRouteHeader sr;
        for (size_t i = 0; i < m_pathPorts.size(); i++)
        {
            bool bos = (i == m_pathPorts.size() - 1);
            sr.AddHop(m_pathPorts[i], bos);
        }

        UdpHeader udp;
        udp.SetDestinationPort(m_port);
        udp.SetSourcePort(1234);

        Ipv4Header ipv4;
        ipv4.SetDestination(m_dst);
        Ptr<Ipv4> ipv4Obj = GetNode()->GetObject<Ipv4>();
        Ipv4Address srcIp = ipv4Obj->GetAddress(1, 0).GetLocal();
        ipv4.SetSource(srcIp);
        ipv4.SetProtocol(17); // UDP
        ipv4.SetTtl(64);
        ipv4.SetPayloadSize(m_pktSize + udp.GetSerializedSize());
        
        udp.InitializeChecksum(srcIp, m_dst, 17);
        ipv4.EnableChecksum();

        pkt->AddHeader(udp);
        pkt->AddHeader(ipv4);
        pkt->AddHeader(sr);
        m_txTrace(pkt);
        int ret = m_socket->SendTo(pkt, 0, m_socketAddr);
        if (ret < 0) {
            NS_LOG_INFO("Send failed, errno: " << m_socket->GetErrno());
        } else {
            NS_LOG_INFO("Sent packet, ret=" << ret);
        }

        Time next = Seconds(
            (double)m_pktSize * 8 / m_dataRate.GetBitRate());
        if(next>Seconds(0)){m_event = Simulator::Schedule(next, &SourceRoutingApp::SendPacket, this);}
    }

private:
    Ptr<Socket> m_socket;
    EventId m_event;
    Ipv4Address m_dst;
    uint16_t m_port;
    uint32_t m_pktSize;
    DataRate m_dataRate;
    std::vector<uint16_t> m_pathPorts;
    TracedCallback<Ptr<const Packet>> m_txTrace;
    PacketSocketAddress m_socketAddr;
};



unsigned long start = getTickCount();
double global_start_time = 1.0;
double sink_start_time = global_start_time + 1.0;
double client_start_time = sink_start_time + 1.0;
double client_stop_time = client_start_time + 3;
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

void
TxCallback(Ptr<const Packet> packet)
{
    NS_LOG_INFO("TxCallback invoked");
    if (first_tx)
    {
        // here we just simple jump the first 10 pkts (include some of ARP packets)
        first_packet_send_time_tx = Simulator::Now().GetSeconds();
        counter_sender_10--;
        if (counter_sender_10 == 0)
        {
            first_tx = false;
        }
    }
    else
    {
        totalTxBytes += packet->GetSize();
        last_packet_send_time_tx = Simulator::Now().GetSeconds();
    }
}

void
RxCallback(Ptr<const Packet> packet, const Address& addr)
{
    NS_LOG_INFO("RxCallback invoked");
    if (first_rx)
    {
        // here we just simple jump the first 10 pkts (include some of ARP packets)
        first_packet_received_time_rx = Simulator::Now().GetSeconds();
        counter_receiver_10--;
        if (counter_receiver_10 == 0)
        {
            first_rx = false;
        }
    }
    else
    {
        totalRxBytes += packet->GetSize();
        last_packet_received_time_rx = Simulator::Now().GetSeconds();
    }
}

void
PrintFinalThroughput()
{
    double send_time = last_packet_send_time_tx - first_packet_send_time_tx;
    double elapsed_time = last_packet_received_time_rx - first_packet_received_time_rx;

    double finalTxThroughput = (totalTxBytes * 8.0) / (send_time * 1e6);
    double finalRxThroughput = (totalRxBytes * 8.0) / (elapsed_time * 1e6);
    std::cout << "client_start_time: " << first_packet_send_time_tx
              << "client_stop_time: " << last_packet_send_time_tx
              << "sink_start_time: " << first_packet_received_time_rx
              << "sink_stop_time: " << last_packet_received_time_rx << std::endl;

    std::cout << "======================================" << std::endl;
    std::cout << "Final Simulation Results:" << std::endl;
    std::cout << "Total Transmitted Bytes: " << totalTxBytes << " bytes in time " << send_time
              << std::endl;
    std::cout << "Total Received Bytes: " << totalRxBytes << " bytes in time " << elapsed_time
              << std::endl;
    std::cout << "Final Transmitted Throughput: " << finalTxThroughput << " Mbps" << std::endl;
    std::cout << "Final Received Throughput: " << finalRxThroughput << " Mbps" << std::endl;
    std::cout << "======================================" << std::endl;
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
    // LogComponentEnable("P4BasicExample", LOG_LEVEL_INFO);
    LogComponentEnable("P4SrcRoutingExample", LOG_LEVEL_INFO);

    // ============================ parameters ============================
    int running_number = 0;
    uint16_t pktSize = 1000;           // in Bytes. 1458 to prevent fragments, default 512
    std::string appDataRate = "3Mbps"; // Default application data rate
    std::string ns3_link_rate = "1000Mbps";
    bool enableTracePcap = true;

    // Use P4SIM_DIR environment variable for portable paths
    std::string p4SrcDir = GetP4ExamplePath() + "/source_routing";
    std::string p4JsonPath = p4SrcDir + "/source_routing.json";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat("CsmaTopo");

    // ============================  command line ============================
    CommandLine cmd;
    cmd.AddValue("runnum", "running number in loops", running_number);
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

    topoReader->PrintTopology();

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
    csma.SetChannelAttribute("DataRate", StringValue(ns3_link_rate));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(0.01)));

    // NetDeviceContainer hostDevices;
    // NetDeviceContainer switchDevices;
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

    // Bridge or P4 switch configuration
    P4Helper p4SwitchHelper;
    p4SwitchHelper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(0));
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));

    for (unsigned int i = 0; i < switchNum; i++)
    {
        // std::string flowTablePath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        // p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        // NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", \n " << flowTablePath);

        p4SwitchHelper.Install(switchNode.Get(i), switchNodes[i].switchDevices);
    }

    // === Configuration for Link: h0 -----> h1 ===
    unsigned int serverI = 2;
    unsigned int clientI = 0;
    uint16_t servPort = 9093; // UDP port for the server

    // === Retrieve Server Address ===
    Ptr<Node> node = terminals.Get(serverI);
    Ptr<Ipv4> ipv4_adder = node->GetObject<Ipv4>();
    Ipv4Address serverAddr1 = ipv4_adder->GetAddress(1, 0).GetLocal();
    InetSocketAddress dst1 = InetSocketAddress(serverAddr1, servPort);

    // === Setup Packet Sink on Server ===
    PacketSinkHelper sink1("ns3::UdpSocketFactory", dst1);
    ApplicationContainer sinkApp1 = sink1.Install(terminals.Get(serverI));
    sinkApp1.Start(Seconds(sink_start_time));
    sinkApp1.Stop(Seconds(sink_stop_time));

    // === Setup OnOff Application on Client ===
    // OnOffHelper onOff1("ns3::UdpSocketFactory", dst1);
    // onOff1.SetAttribute("PacketSize", UintegerValue(pktSize));
    // onOff1.SetAttribute("DataRate", StringValue(appDataRate));
    // onOff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    // onOff1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    std::vector<uint16_t> path={1,2,0};
    Ptr<SourceRoutingApp> app=CreateObject<SourceRoutingApp>();
    app->Setup(serverAddr1, servPort, pktSize, DataRate(appDataRate), path);
    terminals.Get(clientI)->AddApplication(app);
    app->SetStartTime(Seconds(client_start_time));
    app->SetStopTime(Seconds(client_stop_time));

    // === Setup Tracing ===
    NS_LOG_INFO("Client node has " << terminals.Get(clientI)->GetNApplications() << " applications");
    Ptr<Application> genericApp = terminals.Get(clientI)->GetApplication(0);
    NS_LOG_INFO("Generic application pointer: " << genericApp);
    
    Ptr<SourceRoutingApp> ptr_app1 =
        DynamicCast<SourceRoutingApp>(genericApp);
    NS_LOG_INFO("Casted application pointer: " << ptr_app1);

    if (ptr_app1) {
        ptr_app1->TraceConnectWithoutContext("Tx", MakeCallback(&TxCallback));
    } else {
        NS_LOG_ERROR("Failed to cast application to SourceRoutingApp");
    }

    sinkApp1.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&RxCallback));

    if (enableTracePcap)
    {
        csma.EnablePcapAll("p4-basic-example");
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

    PrintFinalThroughput();

    return 0;
}
