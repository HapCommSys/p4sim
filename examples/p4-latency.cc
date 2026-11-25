/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * Latency: what makes up the one-way delay of a packet through a P4 switch.
 *
 *   host0 (10.1.1.1) ──link──> P4 switch ──link──> host1 (10.1.1.2)
 *
 * host0 sends 1000-byte UDP packets at a constant rate to host1, which
 * measures the one-way delay of each packet from the time host0 wrote into it
 * (SeqTsSizeHeader). The example runs four times:
 *  1. base: 1 Gbps links with 1 us of propagation delay, 50 Mbps of traffic.
 *     Each hop stores a frame completely before it sends it on, so a packet
 *     takes two serialisations and two propagation delays. The links use
 *     Ethernet framing: a packet takes 1054 bytes on the wire (1000 bytes of
 *     payload, 8 of UDP, 20 of IPv4, 14 of Ethernet, 8 of preamble and 4 of
 *     FCS), 8.432 us at 1 Gbps.
 *  2. PipelineDelay of 5 us: every packet arrives 5 us later; the throughput
 *     stays the same.
 *  3. 10 us of propagation delay per link: every packet arrives 2 x 9 us later.
 *  4. a 100 Mbps link to host1 and 120 Mbps of traffic: the egress queue of
 *     the switch fills, and queueing makes up most of the delay. The P4
 *     program (queueing.p4) measures the time each packet spends in the queue
 *     itself (deq_timedelta) and adds it up in a register; the example shows
 *     the mean.
 *
 * The column "no queue" is the delay that these parts add up to without any
 * queueing; the shortest delay measured matches it in every run.
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
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4Latency");

namespace
{

/// What a run configures
struct Scenario
{
    std::string name;   ///< for the output
    Time pipelineDelay; ///< PipelineDelay of the switch
    Time linkDelay;     ///< propagation delay of each link
    std::string toHost; ///< data rate of the link to host1
    std::string rate;   ///< data rate of the traffic

    /// The one-way delay without any queueing: two serialisations, two
    /// propagation delays and the pipeline
    Time NoQueue() const
    {
        const uint32_t wireBytes = 1054; // see above
        return DataRate("1Gbps").CalculateBytesTxTime(wireBytes) +
               DataRate(toHost).CalculateBytesTxTime(wireBytes) + 2 * linkDelay + pipelineDelay;
    }
};

/// What a run measures
struct Result
{
    uint32_t sent{0};        ///< packets sent
    std::vector<Time> delay; ///< one-way delay of each packet received
    double queueTime{0};     ///< mean time in the queue, measured by the P4 program (us)
};

void
Sent(Result* r, Ptr<const Packet>)
{
    r->sent++;
}

void
Received(Result* r, Ptr<const Packet>, const Address&, const Address&, const SeqTsSizeHeader& h)
{
    r->delay.push_back(Simulator::Now() - h.GetTs());
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

/// One run: host0 sends for \p seconds
Result
Run(const Scenario& s, double seconds)
{
    std::string p4Dir = GetP4ExamplePath() + "/queueing";
    NodeContainer hosts;
    hosts.Create(2);
    Ptr<Node> switchNode = CreateObject<Node>();

    P4Helper p4;
    p4.SetDeviceAttribute("JsonPath", StringValue(p4Dir + "/queueing.json"));
    p4.SetDeviceAttribute("FlowTablePath", StringValue(p4Dir + "/flowtable_0.txt"));
    p4.SetDeviceAttribute("P4SwitchArch", UintegerValue(P4SWITCH_ARCH_V1MODEL));
    p4.SetDeviceAttribute("PipelineDelay", TimeValue(s.pipelineDelay));
    Ptr<P4SwitchNetDevice> sw = DynamicCast<P4SwitchNetDevice>(p4.Install(switchNode).Get(0));

    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", StringValue("1Gbps"));
    eth.SetChannelAttribute("Delay", TimeValue(s.linkDelay));
    eth.SetChannelAttribute("Framing", StringValue("Ethernet"));
    NetDeviceContainer devices = eth.Install(sw, hosts);
    sw->GetPortChannel(1)->SetAttribute("DataRate", DataRateValue(DataRate(s.toHost)));

    InternetStackHelper internet;
    internet.Install(hosts);
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);
    FillArpCaches(interfaces);

    Result r;
    PacketSinkHelper sink("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), 6000));
    sink.SetAttribute("EnableSeqTsSizeHeader", BooleanValue(true));
    ApplicationContainer sinkApp = sink.Install(hosts.Get(1));
    sinkApp.Get(0)->TraceConnectWithoutContext("RxWithSeqTsSize", MakeBoundCallback(&Received, &r));

    OnOffHelper source("ns3::UdpSocketFactory", InetSocketAddress(interfaces.GetAddress(1), 6000));
    source.SetConstantRate(DataRate(s.rate), 1000);
    source.SetAttribute("EnableSeqTsSizeHeader", BooleanValue(true));
    ApplicationContainer sourceApp = source.Install(hosts.Get(0));
    sourceApp.Start(Seconds(0.1));
    sourceApp.Stop(Seconds(0.1 + seconds));
    sourceApp.Get(0)->TraceConnectWithoutContext("Tx", MakeBoundCallback(&Sent, &r));

    Simulator::Stop(Seconds(seconds + 1));
    Simulator::Run();
    uint64_t packets = Register(sw, "packets", 0); // all packets use queue 0
    r.queueTime = packets ? Register(sw, "queue_time", 0) / 1000.0 / packets : 0;
    Simulator::Destroy();
    return r;
}

} // namespace

int
main(int argc, char* argv[])
{
    double seconds = 0.5;
    CommandLine cmd;
    cmd.AddValue("seconds", "How long host0 sends in each run", seconds);
    cmd.Parse(argc, argv);

    const Scenario scenarios[] = {
        {"1 base", Seconds(0), MicroSeconds(1), "1Gbps", "50Mbps"},
        {"2 PipelineDelay 5 us", MicroSeconds(5), MicroSeconds(1), "1Gbps", "50Mbps"},
        {"3 link delay 10 us", Seconds(0), MicroSeconds(10), "1Gbps", "50Mbps"},
        {"4 120 Mbps on 100 Mbps", Seconds(0), MicroSeconds(1), "100Mbps", "120Mbps"},
    };

    std::cout << "run                        sent  received   one-way delay (us): no queue      min"
                 "     mean      max   in the queue (P4, mean us)\n";
    for (const Scenario& s : scenarios)
    {
        Result r = Run(s, seconds);
        std::sort(r.delay.begin(), r.delay.end());
        double mean = 0;
        for (const Time& d : r.delay)
        {
            mean += d.GetNanoSeconds() / 1000.0;
        }
        size_t n = r.delay.size();
        mean = n ? mean / n : 0;
        double min = n ? r.delay.front().GetNanoSeconds() / 1000.0 : 0;
        double max = n ? r.delay.back().GetNanoSeconds() / 1000.0 : 0;
        std::cout << std::left << std::setw(25) << s.name << std::right << std::setw(6) << r.sent
                  << std::setw(10) << n << std::fixed << std::setprecision(2) << std::setw(30)
                  << s.NoQueue().GetNanoSeconds() / 1000.0 << std::setw(9) << min << std::setw(9)
                  << mean << std::setw(9) << max << std::setw(15) << r.queueTime << "\n";
    }
    return 0;
}
