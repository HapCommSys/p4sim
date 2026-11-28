/*
 * Copyright (c) 2026 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * ECMP with the Hash and Counter externs of PSA.
 *
 *                ┌ 1 ── 10 us ── 1 ┐
 *   h0 ── 0 s0 ──┤                 ├── s1 0 ── h1
 *                └ 2 ── 2 ms ─── 2 ┘
 *
 * s0 spreads the UDP flows from h0 to h1 over its two links to s1: the CRC-16 of
 * the 5-tuple (Hash extern) picks the link, so all packets of a flow take the
 * same one. h0 sends 16 flows of 100 packets, from the source ports 5000 to
 * 5015. A counter of s1 counts the packets of each flow by the port they came
 * in on, that is, by the link they took; at the end the program reads it
 * (P4RuntimeApi::ReadCounter) and checks that every flow kept to one link and
 * that both links carry flows. The second link is 2 ms long and the packets of
 * a flow are 1 ms apart, so a flow split over both links would arrive out of
 * order: h1 checks that it got every packet, in order.
 */

#include "example-check.h"

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-runtime-api.h"
#include "ns3/p4-switch-core.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/switched-ethernet-helper.h"

#include <map>

using namespace ns3;

namespace
{

const uint32_t N_FLOWS = 16;
const uint32_t N_PACKETS = 100;        ///< per flow
const uint16_t FIRST_PORT = 5000;      ///< UDP source port of the first flow
const uint16_t SINK_PORT = 9;          ///< UDP port of h1
const Time INTERVAL = MilliSeconds(1); ///< between two packets of a flow
const std::string COUNTER = "IngressImpl.flow_ports";
const Time LINK_DELAY[2] = {MicroSeconds(10), MilliSeconds(2)}; ///< of the links s0-s1

/// Packets of a flow that h1 received, and how many came out of order
struct Flow
{
    uint32_t received = 0;
    uint32_t next = 0; ///< the sequence number expected next
    uint32_t outOfOrder = 0;
};

std::map<uint16_t, Flow> g_flows; ///< by UDP source port

/// A flow sends its packet \p seq: the payload starts with the sequence number
void
Send(Ptr<Socket> socket, uint32_t seq)
{
    uint8_t payload[100] = {};
    payload[0] = seq >> 24;
    payload[1] = seq >> 16 & 0xff;
    payload[2] = seq >> 8 & 0xff;
    payload[3] = seq & 0xff;
    socket->Send(Create<Packet>(payload, sizeof(payload)));
}

/// h1 received a packet
void
Receive(Ptr<const Packet> packet, const Address& from)
{
    uint8_t b[4];
    packet->CopyData(b, 4);
    uint32_t seq = uint32_t(b[0]) << 24 | uint32_t(b[1]) << 16 | uint32_t(b[2]) << 8 | b[3];
    Flow& flow = g_flows[InetSocketAddress::ConvertFrom(from).GetPort()];
    flow.received++;
    flow.outOfOrder += (seq != flow.next);
    flow.next = seq + 1;
}

} // namespace

int
main(int argc, char* argv[])
{
    std::string dir = GetP4ExamplePath() + "/psa_ecmp";
    bool pcap = false;
    CommandLine cmd(__FILE__);
    cmd.AddValue("pcap", "Write a pcap file per host (p4-psa-ecmp-<node>-0.pcap)", pcap);
    cmd.Parse(argc, argv);

    // Two PSA switches, s0 (ECMP) and s1 (forwarding)
    P4Helper p4;
    p4.SetDeviceAttribute("P4SwitchArch", UintegerValue(P4SWITCH_ARCH_PSA));
    p4.SetDeviceAttribute("JsonPath", StringValue(dir + "/psa_ecmp.json"));
    std::vector<Ptr<P4SwitchNetDevice>> sw;
    for (uint32_t s = 0; s < 2; s++)
    {
        p4.SetDeviceAttribute("FlowTablePath",
                              StringValue(dir + "/flowtable_" + std::to_string(s) + ".txt"));
        Ptr<Node> node = CreateObject<Node>();
        sw.push_back(DynamicCast<P4SwitchNetDevice>(p4.Install(node).Get(0)));
    }

    // Port 0 of each switch is its host, ports 1 and 2 are the two links
    NodeContainer hosts(2);
    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    eth.SetChannelAttribute("Delay", StringValue("10us"));
    NetDeviceContainer devices;
    devices.Add(eth.ConnectHost(sw[0], hosts.Get(0)));
    devices.Add(eth.ConnectHost(sw[1], hosts.Get(1)));
    for (uint32_t link = 0; link < 2; link++)
    {
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        channel->SetAttribute("DataRate", StringValue("100Mbps"));
        channel->SetAttribute("Delay", TimeValue(LINK_DELAY[link]));
        sw[0]->Attach(channel);
        sw[1]->Attach(channel);
    }

    // h0 10.0.0.1, h1 10.0.0.2; h0 knows the MAC address of h1
    devices.Get(0)->SetAddress(Mac48Address("00:00:00:00:00:01"));
    devices.Get(1)->SetAddress(Mac48Address("00:00:00:00:00:02"));
    InternetStackHelper internet;
    internet.Install(hosts);
    Ipv4AddressHelper ipv4("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ip = ipv4.Assign(devices);
    ArpCache::Entry* entry =
        hosts.Get(0)->GetObject<Ipv4L3Protocol>()->GetInterface(1)->GetArpCache()->Add(
            ip.GetAddress(1));
    entry->SetMacAddress(Mac48Address("00:00:00:00:00:02"));
    entry->MarkPermanent();

    // h1 receives every flow; h0 sends the flows from their own source ports
    Ptr<Application> sink = PacketSinkHelper("ns3::UdpSocketFactory",
                                             InetSocketAddress(Ipv4Address::GetAny(), SINK_PORT))
                                .Install(hosts.Get(1))
                                .Get(0);
    sink->TraceConnectWithoutContext("Rx", MakeCallback(&Receive));
    for (uint32_t f = 0; f < N_FLOWS; f++)
    {
        Ptr<Socket> socket = Socket::CreateSocket(hosts.Get(0), UdpSocketFactory::GetTypeId());
        socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), FIRST_PORT + f));
        socket->Connect(InetSocketAddress(ip.GetAddress(1), SINK_PORT));
        for (uint32_t seq = 0; seq < N_PACKETS; seq++)
        {
            Simulator::Schedule(Seconds(1) + seq * INTERVAL + f * MicroSeconds(50),
                                &Send,
                                socket,
                                seq);
        }
    }
    if (pcap)
    {
        eth.EnablePcap("p4-psa-ecmp", devices, true);
    }

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    // The packets of each flow that came in on each link at s1 (its ports 1 and 2),
    // read before the switches are destroyed
    P4RuntimeApi api(*sw[1]->GetCore());
    std::vector<std::vector<uint16_t>> flowsOn(2); // source ports of the flows on each link
    bool oneLink = true;
    for (uint32_t f = 0; f < N_FLOWS; f++)
    {
        uint16_t port = FIRST_PORT + f;
        uint64_t onLink[2] = {};
        for (uint32_t link = 0; link < 2; link++)
        {
            bm::MatchTableAbstract::counter_value_t bytes = 0;
            bm::MatchTableAbstract::counter_value_t packets = 0;
            NS_ABORT_MSG_IF(
                api.ReadCounter(COUNTER, (port & 0x3f) * 4 + 1 + link, &bytes, &packets) != 0,
                "Cannot read the counter");
            onLink[link] = packets;
        }
        bool first = onLink[0] == N_PACKETS && onLink[1] == 0;
        bool second = onLink[0] == 0 && onLink[1] == N_PACKETS;
        oneLink = oneLink && (first || second);
        flowsOn[second ? 1 : 0].push_back(port);
    }
    Simulator::Destroy();

    uint32_t received = 0;
    uint32_t outOfOrder = 0;
    for (auto& [port, flow] : g_flows)
    {
        received += flow.received;
        outOfOrder += flow.outOfOrder;
    }
    for (uint32_t link = 0; link < 2; link++)
    {
        std::cout << "link " << link + 1 << " (port " << link + 1 << " of s0 and s1, "
                  << LINK_DELAY[link].GetMicroSeconds() << " us): " << flowsOn[link].size()
                  << " flows, from the source ports";
        for (uint16_t port : flowsOn[link])
        {
            std::cout << " " << port;
        }
        std::cout << "\n";
    }

    using p4sim_example::Check;
    int failed = Check(oneLink, "each flow kept to one link (the counter of s1)");
    failed |= Check(flowsOn[0].size() >= N_FLOWS / 4 && flowsOn[1].size() >= N_FLOWS / 4,
                    "both links carry at least a quarter of the flows");
    failed |= Check(received == N_FLOWS * N_PACKETS,
                    "h1 received " + std::to_string(received) + " of " +
                        std::to_string(N_FLOWS * N_PACKETS) + " packets");
    failed |= Check(outOfOrder == 0,
                    std::to_string(outOfOrder) + " packets arrived out of the order of their flow");
    return failed;
}
