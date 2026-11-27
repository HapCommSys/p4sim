/*
 * Copyright (c) 2026 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * A policer with the Meter and Counter externs of PSA.
 *
 *   h0 ── port 0 ┐
 *                ├── s0 (psa_meter.p4) ── port 2 ── h2
 *   h1 ── port 1 ┘
 *
 * Every ingress port of s0 has a two-rate three-color meter (RFC 2698) of frame
 * bytes. At 0.5 s the control plane sets all of them to a committed rate of
 * 5 Mbps and a peak rate of 10 Mbps (P4RuntimeApi::SetMeterArrayRates). From 1 to 3 s,
 * h0 sends 4 Mbps of UDP to h2, within the committed rate, and h1 sends 20 Mbps,
 * twice the peak rate. The switch drops the red frames, those over the peak rate,
 * so h1's flow arrives at the peak rate while h0's arrives whole. A counter counts
 * the frames of each port and color; at the end the program reads it
 * (P4RuntimeApi::ReadCounter) and checks it against what the hosts sent and
 * received.
 *
 * The meters count simulation time, so the result is the same in every run.
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
#include "ns3/switched-ethernet-helper.h"

#include <iomanip>

using namespace ns3;

namespace
{

const uint32_t PAYLOAD = 1000;                ///< UDP payload of a packet, in bytes
const uint32_t FRAME = PAYLOAD + 8 + 20 + 14; ///< the frame that the meter measures
const DataRate COMMITTED("5Mbps");            ///< committed rate of every meter
const DataRate PEAK("10Mbps");                ///< peak rate of every meter
const uint32_t BURST = 10 * FRAME;            ///< both burst sizes, in bytes
const Time START = Seconds(1);                ///< the hosts start sending
const Time STOP = Seconds(3);                 ///< and stop

/// A rate of the meter: BMv2 counts bytes per microsecond
bm::Meter::rate_config_t
Rate(DataRate rate, uint32_t burst)
{
    return bm::Meter::rate_config_t::make(rate.GetBitRate() / 8.0 / 1e6, burst);
}

/// The control plane sets the rates of every meter of the switch
void
SetRates(Ptr<P4SwitchNetDevice> sw)
{
    P4RuntimeApi api(*sw->GetCore());
    int rc = api.SetMeterArrayRates("IngressImpl.port_meter",
                                    {Rate(COMMITTED, BURST), Rate(PEAK, BURST)});
    NS_ABORT_MSG_IF(rc != 0, "Cannot set the rates of the meters");
}

/// Count a packet that an application sent
void
CountSent(uint64_t* packets, Ptr<const Packet>)
{
    ++*packets;
}

} // namespace

int
main(int argc, char* argv[])
{
    std::string dir = GetP4ExamplePath() + "/psa_meter";
    bool pcap = false;
    CommandLine cmd(__FILE__);
    cmd.AddValue("pcap", "Write a pcap file per host (p4-psa-meter-<node>-0.pcap)", pcap);
    cmd.Parse(argc, argv);

    // A PSA switch; host i on port i
    P4Helper p4;
    p4.SetDeviceAttribute("P4SwitchArch", UintegerValue(P4SWITCH_ARCH_PSA));
    p4.SetDeviceAttribute("JsonPath", StringValue(dir + "/psa_meter.json"));
    p4.SetDeviceAttribute("FlowTablePath", StringValue(dir + "/flowtable.txt"));
    Ptr<Node> switchNode = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = DynamicCast<P4SwitchNetDevice>(p4.Install(switchNode).Get(0));
    NodeContainer hosts(3);
    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    eth.SetChannelAttribute("Delay", StringValue("10us"));
    NetDeviceContainer devices = eth.Install(sw, hosts);

    // Addresses 10.0.0.<i+1>; the hosts know each other's MAC addresses
    std::vector<Mac48Address> mac;
    for (uint32_t i = 0; i < 3; i++)
    {
        mac.emplace_back(("00:00:00:00:00:0" + std::to_string(i + 1)).c_str());
        devices.Get(i)->SetAddress(mac[i]);
    }
    InternetStackHelper internet;
    internet.Install(hosts);
    Ipv4AddressHelper ipv4("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ip = ipv4.Assign(devices);
    for (uint32_t i = 0; i < 3; i++)
    {
        Ptr<ArpCache> arp =
            hosts.Get(i)->GetObject<Ipv4L3Protocol>()->GetInterface(1)->GetArpCache();
        for (uint32_t j = 0; j < 3; j++)
        {
            if (i != j)
            {
                ArpCache::Entry* entry = arp->Add(ip.GetAddress(j));
                entry->SetMacAddress(mac[j]);
                entry->MarkPermanent();
            }
        }
    }

    // h0 -> h2 at 4 Mbps and h1 -> h2 at 20 Mbps, each to its own port of h2
    const std::vector<DataRate> rates = {DataRate("4Mbps"), DataRate("20Mbps")};
    std::vector<Ptr<PacketSink>> sinks;
    std::vector<uint64_t> sent(2, 0);
    for (uint32_t h = 0; h < 2; h++)
    {
        InetSocketAddress dst(ip.GetAddress(2), 9000 + h);
        sinks.push_back(DynamicCast<PacketSink>(
            PacketSinkHelper("ns3::UdpSocketFactory", dst).Install(hosts.Get(2)).Get(0)));
        OnOffHelper onOff("ns3::UdpSocketFactory", dst);
        onOff.SetConstantRate(rates[h], PAYLOAD);
        ApplicationContainer app = onOff.Install(hosts.Get(h));
        app.Start(START);
        app.Stop(STOP);
        app.Get(0)->TraceConnectWithoutContext("Tx", MakeBoundCallback(&CountSent, &sent[h]));
    }
    Simulator::Schedule(Seconds(0.5), &SetRates, sw);
    if (pcap)
    {
        eth.EnablePcap("p4-psa-meter", devices, true);
    }

    Simulator::Stop(Seconds(4));
    Simulator::Run();

    // The counter of each port and color, read before the switch is destroyed
    P4RuntimeApi api(*sw->GetCore());
    uint64_t counted[2][3] = {};
    for (uint32_t port = 0; port < 2; port++)
    {
        for (uint32_t color = 0; color < 3; color++)
        {
            bm::MatchTableAbstract::counter_value_t bytes = 0;
            bm::MatchTableAbstract::counter_value_t packets = 0;
            NS_ABORT_MSG_IF(
                api.ReadCounter("IngressImpl.colors", 3 * port + color, &bytes, &packets) != 0,
                "Cannot read the counter");
            counted[port][color] = packets;
        }
    }
    std::vector<uint64_t> received = {sinks[0]->GetTotalRx() / PAYLOAD,
                                      sinks[1]->GetTotalRx() / PAYLOAD};
    Simulator::Destroy();

    // The bucket of a rate is full when h1 starts (BURST bytes) and gains the rate
    // between two packets of h1. A frame that passes takes FRAME bytes from it, and
    // h1 sends faster than both rates, so of its n packets
    // (BURST + rate * (n - 1) * interval) / FRAME pass the bucket: those within the
    // peak rate are received, those within the committed rate are green
    const double interval = rates[1].CalculateBytesTxTime(PAYLOAD).GetSeconds();
    auto passing = [&](DataRate rate) {
        return static_cast<uint64_t>((BURST + rate.GetBitRate() / 8.0 * (sent[1] - 1) * interval) /
                                     FRAME);
    };
    const uint64_t expected = passing(PEAK);
    const uint64_t expectedGreen = passing(COMMITTED);
    auto near = [](uint64_t a, uint64_t b) { return a <= b + 1 && b <= a + 1; };
    auto mbps = [](DataRate rate) { return std::to_string(rate.GetBitRate() / 1000000) + " Mbps"; };
    std::cout << "Meters: committed rate " << mbps(COMMITTED) << ", peak rate " << mbps(PEAK)
              << " (of frame bytes)\n"
              << "host     rate   sent  received  green  yellow    red\n";
    for (uint32_t h = 0; h < 2; h++)
    {
        std::cout << "  h" << h << std::setw(10) << mbps(rates[h]) << std::setw(7) << sent[h]
                  << std::setw(10) << received[h] << std::setw(7) << counted[h][0] << std::setw(8)
                  << counted[h][1] << std::setw(7) << counted[h][2] << "\n";
    }

    using p4sim_example::Check;
    int failed = Check(received[0] == sent[0] && counted[0][0] == sent[0] && counted[0][1] == 0 &&
                           counted[0][2] == 0,
                       "h0, within the committed rate: all " + std::to_string(sent[0]) +
                           " packets green and received");
    failed |=
        Check(near(received[1], expected),
              "h1, over the peak rate: " + std::to_string(received[1]) + " packets received, " +
                  std::to_string(expected) + " expected from the peak rate and the burst size");
    failed |= Check(counted[1][2] > 0 && counted[1][2] == sent[1] - received[1],
                    "h1: the switch dropped the " + std::to_string(counted[1][2]) +
                        " red packets, and no other");
    failed |=
        Check(near(counted[1][0], expectedGreen) && counted[1][0] + counted[1][1] == received[1],
              "h1: " + std::to_string(counted[1][0]) + " green packets, " +
                  std::to_string(expectedGreen) + " expected from the committed rate; the other " +
                  std::to_string(counted[1][1]) + " received ones yellow");
    return failed;
}
