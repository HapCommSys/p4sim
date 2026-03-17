/**
 * This example is same with "calc" in p4lang/tutorials
 * URL: https://github.com/p4lang/tutorials/tree/master/exercises/calc
 * The P4 program implements basic calculation.
 *
 *
 *          ┌─────────┐
 *          │ Switch 0|
 *      ┌───┼         │
 *      │   └────────┬┘
 *  ┌───┼────┐     ┌─┴──────┐
 *  │ host 1 │     │ host 2 │
 *  └────────┘     └────────┘
 */

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/custom-header.h"
#include "ns3/custom-p2p-net-device.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-topology-reader-helper.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("p4-calc");

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

static uint32_t
ReadBe32(const uint8_t* p)
{
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

void
DecodeP4CalcFrame(Ptr<const Packet> packet)
{
    Ptr<Packet> copy = packet->Copy();

    EthernetHeader eth;
    if (!copy->RemoveHeader(eth))
    {
        return;
    }

    if (eth.GetLengthType() != 0x1234)
    {
        return;
    }

    if (copy->GetSize() < 16)
    {
        NS_LOG_INFO("p4calc frame too short: " << copy->GetSize());
        return;
    }

    uint8_t calcBytes[16];
    copy->CopyData(calcBytes, sizeof(calcBytes));

    if (calcBytes[0] != 0x50 || calcBytes[1] != 0x34 || calcBytes[2] != 0x01)
    {
        NS_LOG_INFO("p4calc signature/version mismatch");
        return;
    }

    uint8_t op = calcBytes[3];
    uint32_t opA = ReadBe32(&calcBytes[4]);
    uint32_t opB = ReadBe32(&calcBytes[8]);
    uint32_t result = ReadBe32(&calcBytes[12]);

    NS_LOG_INFO("P4Calc RX : op = 0x " << std::hex << static_cast<uint32_t>(op) << std::dec
                                       << " opA=" << opA << " opB=" << opB << " result=" << result);
}

void
SendTestPacket(Ptr<NetDevice> sender,
               Ptr<Packet> packet,
               Mac48Address src,
               Mac48Address dst,
               uint16_t protocol)
{
    sender->SendFrom(packet, src, dst, protocol);
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
    LogComponentEnable("p4-calc", LOG_LEVEL_INFO);
    ns3::PacketMetadata::Enable(); // Enable packet metadata tracing support

    // simulation parameters
    std::string appDataRate = "2.0Mbps";
    std::string ns3_link_rate = "1000Mbps";

    // Use P4SIM_DIR environment variable for portable paths
    std::string p4SrcDir = GetP4ExamplePath() + "/calc";
    std::string p4JsonPath = p4SrcDir + "/calc.json";
    std::string flowTableDirPath = p4SrcDir + "/";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat("CsmaTopo");

    // simulation time configuration
    double global_start_time = 1.0;
    double global_stop_time = global_start_time + 10;

    uint32_t operandA = 1;
    uint32_t operandB = 2;
    std::string operation = "+";

    CommandLine cmd;
    cmd.AddValue("opA", "Operand A", operandA);
    cmd.AddValue("opB", "Operand B", operandB);
    cmd.AddValue("opCode", "Operation Code (+,-,&,|,^) ", operation);
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
        std::string flowTablePath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", \n " << flowTablePath);

        p4SwitchHelper.Install(switchNode.Get(i), switchNodes[i].switchDevices);
    }

    // Build raw p4calc header bytes expected by calc.p4 parser.
    uint8_t opCode; // '+' operation code defined in calc.p4
    switch (operation[0])
    {
    case '+':
        opCode = 0x2b;
        break;
    case '-':
        opCode = 0x2d;
        break;
    case '&':
        opCode = 0x26;
        break;
    case '|':
        opCode = 0x7c;
        break;
    case '^':
        opCode = 0x5e;
        break;
    default:
        NS_LOG_ERROR("Unsupported operation: " << operation);
        return -1;
    }
    uint8_t calcBytes[16] = {
        0x50,   // p
        0x34,   // four
        0x01,   // ver
        opCode, // op ('+')
        static_cast<uint8_t>((operandA >> 24) & 0xff),
        static_cast<uint8_t>((operandA >> 16) & 0xff),
        static_cast<uint8_t>((operandA >> 8) & 0xff),
        static_cast<uint8_t>(operandA & 0xff),
        static_cast<uint8_t>((operandB >> 24) & 0xff),
        static_cast<uint8_t>((operandB >> 16) & 0xff),
        static_cast<uint8_t>((operandB >> 8) & 0xff),
        static_cast<uint8_t>(operandB & 0xff),
        0x00,
        0x00,
        0x00,
        0x00 // res (filled by switch)
    };

    Ptr<Packet> testPacket = Create<Packet>(calcBytes, sizeof(calcBytes));

    // Use topology-resolved devices for sending and reception trace.
    Ptr<NetDevice> hostTxDevice = hostNodes[0].hostDevice.Get(0);
    Ptr<NetDevice> switchIngressDevice =
        switchNodes[hostNodes[0].linkSwitchIndex].switchDevices.Get(hostNodes[0].linkSwitchPort);

    hostTxDevice->TraceConnectWithoutContext("MacRx", MakeCallback(&DecodeP4CalcFrame));

    // Send from host 0 to switch after simulation starts.
    Simulator::Schedule(Seconds(global_start_time + 0.1),
                        &SendTestPacket,
                        hostTxDevice,
                        testPacket->Copy(),
                        Mac48Address::ConvertFrom(hostTxDevice->GetAddress()),
                        Mac48Address::ConvertFrom(switchIngressDevice->GetAddress()),
                        static_cast<uint16_t>(0x1234));

    Simulator::Stop(Seconds(global_stop_time));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
