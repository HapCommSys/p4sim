/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * In-band link monitoring, the "link_monitor" exercise of p4lang/tutorials:
 * https://github.com/p4lang/tutorials/tree/master/exercises/link_monitor
 *
 *   host 0 ── 0 switch 1 1 ────── 1 switch 2 0 ── host 1
 *                  2                  2
 *                   \                /
 *                    1 switch 3 2 ──
 *                         0 ── host 2
 *
 * Every 100 ms host 0 sends a probe on the path switch 1 -> 2 -> 3 -> 1 -> host 0:
 * the probe carries the egress port of every hop. Each switch adds a record with its
 * ID, the egress port, the bytes that this port sent since the last probe, and the
 * times of the two probes. From the probes that come back host 0 computes the rate
 * of each link on the path. Meanwhile it sends UDP packets to host 1, over the first
 * link only: the program checks that the probes measure this rate there, and nearly
 * nothing on the other links.
 */

#include "example-check.h"

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-net-builder.h"
#include "ns3/p4-topology-reader-helper.h"

#include <iomanip>

using namespace ns3;

namespace
{

const uint16_t PROBE_TYPE = 0x812;              ///< EtherType of the probes
const std::vector<uint8_t> PATH = {1, 2, 1, 0}; ///< egress port of each hop
const Time PROBE_INTERVAL = MilliSeconds(100);  ///< between two probes
const uint32_t N_PROBES = 10;                   ///< probes sent
const uint32_t RECORD_SIZE = 18;                ///< bytes of a record (probe_data_t)

uint32_t g_probes = 0;                                  ///< probes that came back
std::map<std::pair<uint32_t, uint32_t>, double> g_mbps; ///< sum per (switch, port)

/// Host \p device sends a probe: hop count 0, then the egress port of each hop
void
SendProbe(Ptr<NetDevice> device)
{
    std::vector<uint8_t> bytes = {0};
    bytes.insert(bytes.end(), PATH.begin(), PATH.end());
    device->Send(Create<Packet>(bytes.data(), bytes.size()), device->GetAddress(), PROBE_TYPE);
}

/// The big-endian number in \p n bytes
uint64_t
Number(const uint8_t* bytes, uint32_t n)
{
    uint64_t value = 0;
    for (uint32_t i = 0; i < n; i++)
    {
        value = value << 8 | bytes[i];
    }
    return value;
}

/// A probe came back: read the record of each hop (the last hop comes first)
void
ReceiveProbe(Ptr<NetDevice>,
             Ptr<const Packet> packet,
             uint16_t,
             const Address&,
             const Address&,
             NetDevice::PacketType)
{
    std::vector<uint8_t> bytes(packet->GetSize());
    packet->CopyData(bytes.data(), bytes.size());
    if (bytes.size() < 1 + PATH.size() * RECORD_SIZE || bytes[0] != PATH.size())
    {
        return;
    }
    g_probes++;
    for (uint32_t hop = 0; hop < PATH.size(); hop++)
    {
        const uint8_t* record = &bytes[1 + hop * RECORD_SIZE];
        uint32_t switchId = record[0] & 0x7f;
        uint32_t port = record[1];
        uint64_t byteCount = Number(record + 2, 4);
        Time last = NanoSeconds(Number(record + 6, 6)); // P4sim's timestamps are in ns
        Time now = NanoSeconds(Number(record + 12, 6));
        if (last.IsStrictlyPositive()) // not the first probe
        {
            g_mbps[{switchId, port}] += byteCount * 8 / (now - last).GetSeconds() / 1e6;
        }
    }
}

} // namespace

int
main(int argc, char* argv[])
{
    uint16_t pktSize = 1000;
    std::string appDataRate = "10Mbps";
    bool pcap = false;
    CommandLine cmd(__FILE__);
    cmd.AddValue("pktSize", "UDP payload in bytes", pktSize);
    cmd.AddValue("appDataRate", "Data rate from host 0 to host 1", appDataRate);
    cmd.AddValue("pcap", "Write pcap files", pcap);
    cmd.Parse(argc, argv);

    // Hosts, switches and links
    std::string p4Dir = GetP4ExamplePath() + "/link_monitor";
    P4TopologyReaderHelper topoHelper;
    topoHelper.SetFileName(p4Dir + "/topo.txt");
    topoHelper.SetFileType("CsmaTopo");
    Ptr<P4TopologyReader> topo = topoHelper.GetTopologyReader();
    NS_ABORT_MSG_IF(topo->LinksSize() == 0, "Cannot read " << p4Dir << "/topo.txt");
    NodeContainer hosts = topo->GetHostNodeContainer();
    NodeContainer switches = topo->GetSwitchNodeContainer();
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("1Gbps"));
    csma.SetChannelAttribute("Delay", StringValue("10us"));
    std::vector<SwitchNodeC_t> switchNodes(switches.GetN());
    std::vector<HostNodeC_t> hostNodes(hosts.GetN());
    BuildNetworkFromTopology(topo, csma, switchNodes, hostNodes);

    InternetStackHelper internet;
    internet.Install(hosts);
    Ipv4AddressHelper ipv4("10.1.1.0", "255.255.255.0");
    for (uint32_t i = 0; i < hosts.GetN(); i++)
    {
        ipv4.Assign(hosts.Get(i)->GetDevice(0));
    }

    P4Helper p4;
    p4.SetDeviceAttribute("JsonPath", StringValue(p4Dir + "/link_monitor.json"));
    for (uint32_t i = 0; i < switches.GetN(); i++)
    {
        p4.SetDeviceAttribute("FlowTablePath",
                              StringValue(p4Dir + "/flowtable_" + std::to_string(i) + ".txt"));
        p4.Install(switches.Get(i), switchNodes[i].switchDevices);
    }

    // UDP from host 0 to host 1
    InetSocketAddress dst(hosts.Get(1)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal(), 9000);
    PacketSinkHelper sink("ns3::UdpSocketFactory", dst);
    sink.Install(hosts.Get(1));
    OnOffHelper onOff("ns3::UdpSocketFactory", dst);
    onOff.SetConstantRate(DataRate(appDataRate), pktSize);
    ApplicationContainer source = onOff.Install(hosts.Get(0));
    source.Start(Seconds(0.5));
    source.Stop(Seconds(2.5));

    // Probes from host 0 back to host 0, while the flow is running
    Ptr<NetDevice> device = hosts.Get(0)->GetDevice(0);
    hosts.Get(0)->RegisterProtocolHandler(MakeCallback(&ReceiveProbe), PROBE_TYPE, device);
    for (uint32_t i = 0; i < N_PROBES; i++)
    {
        Simulator::Schedule(Seconds(1) + i * PROBE_INTERVAL, &SendProbe, device);
    }
    if (pcap)
    {
        csma.EnablePcapAll("p4-link-monitoring");
    }

    p4sim_example::CountTraffic();
    Simulator::Stop(Seconds(3));
    Simulator::Run();
    Simulator::Destroy();

    // Frames are 42 bytes larger than their UDP payload (Ethernet, IPv4, UDP)
    double expected = DataRate(appDataRate).GetBitRate() / 1e6 * (pktSize + 42) / pktSize;
    std::cout << "switch  port   measured (Mbps)\n" << std::fixed << std::setprecision(3);
    bool rates = true;
    uint32_t lastSwitch = 0;
    for (auto& [link, sum] : g_mbps)
    {
        double mbps = sum / (N_PROBES - 1); // the first probe has no last one
        std::cout << std::setw(6) << link.first << std::setw(6) << link.second << std::setw(18)
                  << mbps << "\n";
        bool loaded = (link.first == 1 && link.second == 1); // switch 1 -> switch 2
        rates = rates &&
                (loaded ? std::abs(mbps - expected) < 0.05 * expected : mbps < 0.05 * expected);
        lastSwitch = link.first;
    }
    int failed = p4sim_example::Check(g_probes == N_PROBES,
                                      std::to_string(g_probes) + " of " + std::to_string(N_PROBES) +
                                          " probes came back");
    std::ostringstream what;
    what << "the probes measure the flow (" << expected << " Mbps) on the link 1 -> 2 only";
    failed |= p4sim_example::Check(rates && lastSwitch == 3 && g_mbps.size() == 4, what.str());
    failed |= p4sim_example::CheckDelivery();
    return failed;
}
