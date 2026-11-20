/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * This example is the "firewall" exercise of p4lang/tutorials
 * URL: https://github.com/p4lang/tutorials/tree/master/exercises/firewall
 * The P4 program implements a stateful firewall for TCP on switch 0: hosts 0 and 1
 * (host 4 and host 5 below) are inside, hosts 2 and 3 outside. A connection that
 * a host inside opens is let through in both directions; a connection that a host
 * outside opens is dropped. The example checks both with a TCP flow each way: the
 * first must deliver at least 90% of the bytes its client sent, the second none.
 * It exits with 1 otherwise.
 *
 * Limits of the program: only TCP is filtered, UDP and ICMP pass in both directions,
 * and traffic that stays inside or outside does not pass the firewall. Switch 0
 * remembers a connection in two Bloom filters of 4096 bits that are never cleared:
 * packets of a closed connection are still let in, and after n connections from
 * inside, a connection from outside gets through by mistake with a probability of
 * about (1 - e^(-n/4096))^2, 5% for n = 1000. The flow tables hold the port numbers
 * and MAC addresses of this topology; they must be rewritten when topo.txt changes.
 *
 *          ┌──────────┐              ┌──────────┐
 *          │ Switch 2 \\            /│ Switch 3 │
 *          └─────┬────┘  \        // └──────┬───┘
 *                │         \    /           │
 *                │           /              │
 *          ┌─────┴────┐   /   \      ┌──────┴───┐
 *          │ Switch 0 //         \ \ │ Switch 1 │
 *      ┌───┼ firewall │             \\          ┼────┐
 *      │   └────────┬─┘              └┬─────────┘    │
 *  ┌───┼────┐     ┌─┴──────┐    ┌─────┼──┐     ┌─────┼──┐
 *  │ host 4 │     │ host 5 │    │ host 6 │     │ host 7 │
 *  └────────┘     └────────┘    └────────┘     └────────┘
 *  |----Internal network----|
 *
 */

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-net-builder.h"
#include "ns3/p4-topology-reader-helper.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4Firewall");

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

/// Adds the size of \p packet, which an application sent, to \p bytes
void
CountSentBytes(uint64_t* bytes, Ptr<const Packet> packet)
{
    *bytes += packet->GetSize();
}

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4Firewall", LOG_LEVEL_INFO);

    // ============================ parameters ============================
    uint16_t pktSize = 1000;           // in Bytes. 1458 to prevent fragments, default 512
    std::string appDataRate = "1Mbps"; // Default application data rate
    std::string ns3_link_rate = "1000Mbps";
    bool enableTracePcap = true;

    // P4 files: examples/p4src in the p4sim folder of this build
    std::string p4SrcDir = GetP4ExamplePath() + "/firewall";
    std::string p4JsonPath = p4SrcDir + "/firewall.json";
    std::string flowTableDirPath = p4SrcDir + "/";
    std::string topoInput = p4SrcDir + "/topo.txt";
    std::string topoFormat("CsmaTopo");

    // ============================  command line ============================
    CommandLine cmd;
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

    std::vector<SwitchNodeC_t> switchNodes(switchNum);
    std::vector<HostNodeC_t> hostNodes(hostNum);
    BuildNetworkFromTopology(topoReader, csma, switchNodes, hostNodes);

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
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));

    for (unsigned int i = 0; i < switchNum; i++)
    {
        std::string flowTablePath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", \n " << flowTablePath);

        p4SwitchHelper.Install(switchNode.Get(i), switchNodes[i].switchDevices);
    }

    // Two TCP flows through the firewall on switch 0 (hosts 0 and 1 inside, 2 and 3 outside)
    struct Flow
    {
        std::string name;    //!< what the flow shows
        unsigned int client; //!< host that opens the connection
        unsigned int server; //!< host that receives the data
        uint16_t port;       //!< TCP port of the server
        Ptr<PacketSink> sink;
        uint64_t sent = 0; //!< bytes that the client handed to its socket
    };

    std::vector<Flow> flows = {{"inside -> outside (host 0 -> host 3)", 0, 3, 9093, nullptr},
                               {"outside -> inside (host 3 -> host 0)", 3, 0, 9094, nullptr}};
    for (Flow& flow : flows)
    {
        PacketSinkHelper sink("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), flow.port));
        ApplicationContainer sinkApp = sink.Install(terminals.Get(flow.server));
        sinkApp.Start(Seconds(sink_start_time));
        sinkApp.Stop(Seconds(sink_stop_time));
        flow.sink = DynamicCast<PacketSink>(sinkApp.Get(0));

        InetSocketAddress dst(terminalInterfaces[flow.server].GetAddress(0), flow.port);
        OnOffHelper onOff("ns3::TcpSocketFactory", dst);
        onOff.SetAttribute("PacketSize", UintegerValue(pktSize));
        onOff.SetAttribute("DataRate", StringValue(appDataRate));
        onOff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onOff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        ApplicationContainer app = onOff.Install(terminals.Get(flow.client));
        app.Start(Seconds(client_start_time));
        app.Stop(Seconds(client_stop_time));
        app.Get(0)->TraceConnectWithoutContext("Tx",
                                               MakeBoundCallback(&CountSentBytes, &flow.sent));
    }

    if (enableTracePcap)
    {
        csma.EnablePcapAll("p4-firewall");
    }

    // Run simulation
    NS_LOG_INFO("Running simulation...");
    unsigned long simulate_start = getTickCount();
    Simulator::Stop(Seconds(global_stop_time));
    Simulator::Run();

    // The connection opened from inside carries what its client sent (at least 90%, so the
    // firewall must also let the acknowledgements in, not only the handshake); the one
    // opened from outside carries nothing
    const Flow& allowed = flows[0];
    const Flow& blocked = flows[1];
    uint64_t allowedBytes = allowed.sink->GetTotalRx();
    uint64_t blockedBytes = blocked.sink->GetTotalRx();
    bool allowedPass = allowed.sent > 0 && allowedBytes * 10 >= allowed.sent * 9;
    bool blockedPass = blockedBytes == 0;
    bool pass = allowedPass && blockedPass;
    std::cout << "Firewall on switch 0 (hosts 0 and 1 inside, hosts 2 and 3 outside):\n"
              << "  [" << (allowedPass ? "PASS" : "FAIL") << "] " << allowed.name << ": "
              << allowedBytes << " of " << allowed.sent
              << " bytes received, the connection is allowed\n"
              << "  [" << (blockedPass ? "PASS" : "FAIL") << "] " << blocked.name << ": "
              << blockedBytes << " bytes received, the connection is blocked" << std::endl;
    Simulator::Destroy();

    unsigned long end = getTickCount();
    NS_LOG_INFO("Simulate Running time: " << end - simulate_start << "ms" << std::endl
                                          << "Total Running time: " << end - start << "ms"
                                          << std::endl
                                          << "Run successfully!");

    return pass ? 0 : 1;
}
