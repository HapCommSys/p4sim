/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * Priority queues: a P4 program classifies the packets, and the switch serves
 * its queues in strict priority.
 *
 *   host0 (10.1.1.1) ──1 Gbps──┐
 *                               ├── P4 switch ──100 Mbps──> host2 (10.1.1.3)
 *   host1 (10.1.1.2) ──1 Gbps──┘
 *
 * host0 sends a small flow (2 Mbps) to UDP port 5000, host1 a bulk flow
 * (140 Mbps) to UDP port 6000, so the port to host2 is congested. The P4
 * program (queueing.p4) maps UDP port 5000 to priority 7, which the switch
 * serves first: the small flow passes the congestion with almost no queueing
 * delay, while the bulk flow fills queue 0 and loses what does not fit. A
 * packet of the small flow only waits for the bulk packet on the wire, at most
 * 83 us (1042 bytes at 100 Mbps): strict priority does not pre-empt. With
 * --priority=0 the classification table is emptied before the simulation
 * starts: both flows share queue 0, and the small flow waits behind the bulk
 * and loses packets too. How many is a matter of timing, not of the queue: both
 * sources send at a constant rate, so whether a packet of the small flow finds
 * the queue full depends on when it arrives relative to the bulk packets. With
 * the defaults the small flow loses 35% of its packets, close to the bulk
 * flow's 32%, but only because both flows start at the same time: starting it 3
 * to 79 us later gives 38% to 96%, while the bulk flow still loses 31% to 32%.
 * Other rates vary in the same way. With the priority, the small flow loses
 * nothing.
 *
 * The receiver measures the one-way delay of every packet from the time its
 * sender wrote into it (SeqTsSizeHeader). The P4 program counts, per queue,
 * the packets, their time in the queue and the deepest queue, in registers.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-switch-core.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/switched-ethernet-helper.h"

#include <algorithm>
#include <cmath>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4PriorityQueues");

namespace
{

/// A flow and the one-way delays of its packets
struct Flow
{
    std::string name;        ///< for the output
    uint32_t sent{0};        ///< packets sent
    std::vector<Time> delay; ///< one-way delay of each packet received
};

void
Sent(Flow* flow, Ptr<const Packet>)
{
    flow->sent++;
}

void
Received(Flow* flow, Ptr<const Packet>, const Address&, const Address&, const SeqTsSizeHeader& h)
{
    flow->delay.push_back(Simulator::Now() - h.GetTs());
}

/// Fills the ARP caches of the hosts with each other's addresses: the P4
/// program forwards IPv4 only, so ARP requests would go nowhere
void
FillArpCaches(const Ipv4InterfaceContainer& interfaces)
{
    for (uint32_t i = 0; i < interfaces.GetN(); i++)
    {
        auto [ipv4, ifIndex] = interfaces.Get(i);
        Ptr<ArpCache> cache =
            DynamicCast<Ipv4L3Protocol>(ipv4)->GetInterface(ifIndex)->GetArpCache();
        for (uint32_t j = 0; j < interfaces.GetN(); j++)
        {
            if (i != j)
            {
                ArpCache::Entry* entry = cache->Add(interfaces.GetAddress(j));
                entry->SetMacAddress(
                    interfaces.Get(j).first->GetNetDevice(interfaces.Get(j).second)->GetAddress());
                entry->MarkPermanent();
            }
        }
    }
}

/// Entry \p index of register MyEgress.<name> of the switch
uint64_t
Register(Ptr<P4SwitchNetDevice> sw, const std::string& name, size_t index)
{
    bm::Data value;
    sw->GetCore()->register_read(0, "MyEgress." + name, index, &value);
    return value.get<uint64_t>();
}

} // namespace

int
main(int argc, char* argv[])
{
    bool priority = true;
    std::string bulkRate = "140Mbps";
    double seconds = 1.0;
    CommandLine cmd;
    cmd.AddValue("priority",
                 "Map UDP port 5000 to priority 7 (0: all packets in queue 0)",
                 priority);
    cmd.AddValue("bulkRate", "Data rate of the bulk flow", bulkRate);
    cmd.AddValue("seconds", "How long the flows send", seconds);
    cmd.Parse(argc, argv);

    std::string p4Dir = GetP4ExamplePath() + "/queueing";
    NodeContainer hosts;
    hosts.Create(3);
    Ptr<Node> switchNode = CreateObject<Node>();

    P4Helper p4;
    p4.SetDeviceAttribute("JsonPath", StringValue(p4Dir + "/queueing.json"));
    p4.SetDeviceAttribute("FlowTablePath", StringValue(p4Dir + "/flowtable_0.txt"));
    p4.SetDeviceAttribute("P4SwitchArch", UintegerValue(P4SWITCH_ARCH_V1MODEL));
    Ptr<P4SwitchNetDevice> sw = DynamicCast<P4SwitchNetDevice>(p4.Install(switchNode).Get(0));

    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", StringValue("1Gbps"));
    eth.SetChannelAttribute("Delay", StringValue("1us"));
    NetDeviceContainer devices = eth.Install(sw, hosts);
    // The link to host 2 is the bottleneck
    sw->GetPortChannel(2)->SetAttribute("DataRate", DataRateValue(DataRate("100Mbps")));

    InternetStackHelper internet;
    internet.Install(hosts);
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);
    FillArpCaches(interfaces);

    // The switch loads its flow table now; without priorities, empty the classifier
    sw->Initialize();
    if (!priority)
    {
        sw->GetCore()->mt_clear_entries(0, "MyIngress.udp_priority", false);
    }

    Flow flows[2] = {{"small, UDP port 5000"}, {"bulk,  UDP port 6000"}};
    const uint16_t ports[2] = {5000, 6000};
    const std::string rates[2] = {"2Mbps", bulkRate};
    for (uint32_t f = 0; f < 2; f++)
    {
        PacketSinkHelper sink("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), ports[f]));
        sink.SetAttribute("EnableSeqTsSizeHeader", BooleanValue(true));
        ApplicationContainer sinkApp = sink.Install(hosts.Get(2));
        sinkApp.Get(0)->TraceConnectWithoutContext("RxWithSeqTsSize",
                                                   MakeBoundCallback(&Received, &flows[f]));

        OnOffHelper source("ns3::UdpSocketFactory",
                           InetSocketAddress(interfaces.GetAddress(2), ports[f]));
        source.SetConstantRate(DataRate(rates[f]), 1000);
        source.SetAttribute("EnableSeqTsSizeHeader", BooleanValue(true));
        ApplicationContainer sourceApp = source.Install(hosts.Get(f));
        sourceApp.Start(Seconds(0.1));
        sourceApp.Stop(Seconds(0.1 + seconds));
        sourceApp.Get(0)->TraceConnectWithoutContext("Tx", MakeBoundCallback(&Sent, &flows[f]));
    }

    Simulator::Stop(Seconds(seconds + 1));
    Simulator::Run();

    std::cout << "Priority queues "
              << (priority ? "on: UDP port 5000 -> priority 7" : "off: all packets in queue 0")
              << "\n\n"
              << "flow                     sent  received    lost   one-way delay (us):  mean"
                 "      p99      max\n";
    for (Flow& f : flows)
    {
        std::sort(f.delay.begin(), f.delay.end());
        double mean = 0;
        for (const Time& d : f.delay)
        {
            mean += d.GetMicroSeconds();
        }
        size_t n = f.delay.size();
        mean = n ? mean / n : 0;
        double p99 =
            n ? f.delay[std::max<size_t>(1, std::ceil(0.99 * n)) - 1].GetMicroSeconds() : 0;
        double max = n ? f.delay.back().GetMicroSeconds() : 0;
        double lost = f.sent ? 100.0 * (f.sent - n) / f.sent : 0;
        std::cout << std::left << std::setw(22) << f.name << std::right << std::setw(7) << f.sent
                  << std::setw(10) << n << std::fixed << std::setprecision(1) << std::setw(7)
                  << lost << "%" << std::setw(28) << mean << std::setw(9) << p99 << std::setw(9)
                  << max << "\n";
    }

    std::cout << "\nThe P4 program's registers, per queue of the port to host 2:\n"
              << "queue   packets   time in queue (us): mean      max   deepest queue\n";
    for (size_t q : {size_t{0}, size_t{7}})
    {
        uint64_t n = Register(sw, "packets", q);
        double mean = n ? Register(sw, "queue_time", q) / 1000.0 / n : 0;
        std::cout << std::setw(5) << q << std::setw(10) << n << std::fixed << std::setprecision(1)
                  << std::setw(27) << mean << std::setw(9)
                  << Register(sw, "max_queue_time", q) / 1000.0 << std::setw(16)
                  << Register(sw, "max_qdepth", q) << "\n";
    }

    Simulator::Destroy();
    return 0;
}
