/*
 * Copyright (c) 2026 TU Dresden
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
 * Authors: Vineet Goel <vineetgoel692@gmail.com>
 *          Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-header.h"
#include "ns3/loopback-net-device.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-net-builder.h"
#include "ns3/p4-topology-reader-helper.h"
#include "ns3/packet-socket-address.h"
#include "ns3/packet-socket-factory.h"
#include "ns3/packet-socket-helper.h"
#include "ns3/udp-header.h"

#include <filesystem>
#include <iomanip>
#include <sstream>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("P4SrcRouting");

class SrcRouteHeader : public Header
{
  public:
    struct Hop
    {
        uint16_t port;
        bool bos;
    };

    std::vector<Hop> hops;

    SrcRouteHeader()
    {
    }

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("SrcRouteHeader").SetParent<Header>().SetGroupName("Tutorial");
        return tid;
    }

    void AddHop(uint16_t port, bool bos)
    {
        Hop hop = {port, bos};
        hops.push_back(hop);
    }

    virtual TypeId GetInstanceTypeId() const override
    {
        return GetTypeId();
    }

    virtual void Print(std::ostream& os) const override
    {
        os << "SrcRouteHeader";
    }

    virtual uint32_t GetSerializedSize() const override
    {
        return hops.size() * 2;
    }

    virtual void Serialize(Buffer::Iterator start) const override
    {
        for (auto& h : hops)
        {
            uint16_t val = (h.bos << 15) | (h.port & 0x7FFF);
            start.WriteHtonU16(val);
        }
    }

    virtual uint32_t Deserialize(Buffer::Iterator start) override
    {
        return 0;
    }
};

class SourceRoutingApp : public Application
{
  public:
    SourceRoutingApp() = default;
    virtual ~SourceRoutingApp() = default;

    void Setup(Ipv4Address dst,
               uint16_t port,
               uint32_t pktSize,
               DataRate dataRate,
               std::vector<uint16_t> pathPorts,
               uint32_t maxPkts = 0)
    {
        m_dst = dst;
        m_port = port;
        m_pktSize = pktSize;
        m_dataRate = dataRate;
        m_pathPorts = pathPorts;
        m_maxPkts = maxPkts;
    }

    static TypeId GetTypeId()
    {
        static TypeId tid =
            TypeId("SourceRoutingApp")
                .SetParent<Application>()
                .SetGroupName("Tutorial")
                .AddConstructor<SourceRoutingApp>()
                .AddTraceSource("Tx",
                                "A new packet is created and is sent",
                                MakeTraceSourceAccessor(&SourceRoutingApp::m_txTrace),
                                "ns3::Packet::TracedCallback");
        return tid;
    }

  private:
    void StartApplication() override
    {
        NS_ASSERT(GetNode());
        m_socket = Socket::CreateSocket(GetNode(), PacketSocketFactory::GetTypeId());

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

        SendPacket();
    }

    void StopApplication() override
    {
        if (m_event.IsRunning())
        {
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
        if (!m_socket)
            return;
        m_pktCount++;
        std::ostringstream portList;
        for (size_t i = 0; i < m_pathPorts.size(); i++)
        {
            if (i)
                portList << " -> ";
            portList << "port " << m_pathPorts[i];
            if (i == m_pathPorts.size() - 1)
                portList << " (bos)";
        }
        NS_LOG_INFO("[pkt #" << m_pktCount << "] t=" << Simulator::Now().GetSeconds()
                             << "s  hops=" << m_pathPorts.size() << "  path: " << portList.str()
                             << "  dst=" << m_dst);
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
        if (ret < 0)
        {
            NS_LOG_INFO("Send failed, errno: " << m_socket->GetErrno());
        }
        else
        {
            NS_LOG_INFO("Sent packet, ret=" << ret);
        }

        if (m_maxPkts > 0 && m_pktCount >= m_maxPkts)
        {
            NS_LOG_INFO("[pkt #" << m_pktCount << "] Reached maxPkts=" << m_maxPkts
                                 << ", stopping.");
            return;
        }
        Time next = Seconds((double)m_pktSize * 8 / m_dataRate.GetBitRate());
        if (next > Seconds(0))
        {
            m_event = Simulator::Schedule(next, &SourceRoutingApp::SendPacket, this);
        }
    }

  private:
    Ptr<Socket> m_socket;
    EventId m_event;
    Ipv4Address m_dst;
    uint16_t m_port;
    uint32_t m_pktSize;
    DataRate m_dataRate;
    std::vector<uint16_t> m_pathPorts;
    uint32_t m_maxPkts{0};
    uint32_t m_pktCount{0};
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
    LogComponentEnable("P4SrcRouting", LOG_LEVEL_INFO);

    // ============================ parameters ============================
    uint16_t pktSize = 1000;           // in Bytes. 1458 to prevent fragments default 512
    std::string appDataRate = "3Mbps"; // Default application data rate
    std::string linkRate = "1000Mbps"; // Default link data rate
    std::string linkDelay = "0.01ms";  // Default link delay
    bool enableTracePcap = true;

    // Use P4SIM_DIR environment variable for portable paths
    std::string p4SrcDir = GetP4ExamplePath() + "/source_routing";
    std::string p4JsonPath = p4SrcDir + "/source_routing.json";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat("CsmaTopo");

    std::string pathStr = "1,2,0"; // default path: h0->s0(p1)->s1(p2)->s2(p0)->h2

    // ============================  command line ============================
    CommandLine cmd;
    cmd.AddValue("pktSize", "Packet size in bytes (default 1000)", pktSize);
    cmd.AddValue("appDataRate", "OnOff application data rate, e.g. 3Mbps", appDataRate);
    // cmd.AddValue("linkRate", "CSMA link data rate, e.g. 1000Mbps", linkRate);
    // cmd.AddValue("linkDelay", "CSMA link one-way delay, e.g. 0.01ms", linkDelay);
    cmd.AddValue("pcap", "Trace packet pcap [true] or not[false]", enableTracePcap);
    cmd.AddValue("path", "Comma-separated egress port list, e.g. \"1,2,0\"", pathStr);
    cmd.Parse(argc, argv);

    std::vector<uint16_t> path;
    {
        std::istringstream ss(pathStr);
        std::string token;
        while (std::getline(ss, token, ','))
        {
            path.push_back(static_cast<uint16_t>(std::stoi(token)));
        }
    }
    NS_ASSERT_MSG(!path.empty(), "path must have at least one hop");

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
    csma.SetChannelAttribute("DataRate", StringValue(linkRate));
    csma.SetChannelAttribute("Delay", StringValue(linkDelay));

    std::vector<SwitchNodeC_t> switchNodes(switchNum);
    std::vector<HostNodeC_t> hostNodes(hostNum);
    BuildNetworkFromTopology(topoReader, csma, switchNodes, hostNodes);

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
        Ipv4Address ipAddr = ipv4->GetAddress(1, 0).GetLocal();
        Mac48Address mac = Mac48Address::ConvertFrom(node->GetDevice(0)->GetAddress());

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

    // === Print human-readable path: resolve port numbers to node names ===
    {
        std::ostringstream pathDesc;
        pathDesc << "h" << clientI;
        unsigned int curSwitch = hostNodes[clientI].linkSwitchIndex;
        for (size_t i = 0; i < path.size(); i++)
        {
            uint16_t port = path[i];
            pathDesc << " -> s" << curSwitch << "(port " << port << ")";
            const std::string& info = switchNodes[curSwitch].switchPortInfos[port];
            if (info[0] == 'h')
            {
                pathDesc << " -> h" << info.substr(1);
            }
            else
            {
                size_t upos = info.find('_');
                curSwitch = std::stoi(info.substr(1, upos - 1));
            }
        }
        std::cout << "*** Forwarding path: " << pathDesc.str() << std::endl;
    }

    Ptr<SourceRoutingApp> app = CreateObject<SourceRoutingApp>();
    app->Setup(serverAddr1, servPort, pktSize, DataRate(appDataRate), path, 2);
    terminals.Get(clientI)->AddApplication(app);
    app->SetStartTime(Seconds(client_start_time));
    app->SetStopTime(Seconds(client_stop_time));

    if (enableTracePcap)
    {
        csma.EnablePcapAll("p4-source-routing", true);
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
