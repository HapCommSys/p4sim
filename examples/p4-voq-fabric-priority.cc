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
 * Authors: Vineet Goel <vineetgoel692@gmail.com>
 */

/**
 * Strict-priority demonstration for the VOQ + fabric Traffic Manager.
 *
 * Two saturating UDP flows from two different sender hosts converge on one
 * receiver through a V1model switch running the `qos` P4 program, which
 * classifies packets by UDP destination port and writes
 * standard_metadata.priority (aliased to intrinsic_metadata.priority, which the
 * Traffic Manager reads):
 *
 *   dport 4000 -> priority 3 (HIGH)
 *   dport 2000 -> priority 1 (LOW)
 *
 *   hostH (10.1.1.1, port 0) ── HIGH (prio 3) ─┐
 *                                               ├─► switch ─►[bottleneck]─► hostR
 *   hostL (10.1.1.2, port 1) ── LOW  (prio 1) ─┘                           (10.1.1.3, port 2)
 *
 * The HIGH and LOW flows enter on *separate* ingress ports, so each has its own
 * host NIC and its own Virtual Output Queue (VOQ[in][out=2][prio]); they only
 * contend inside the switch, at the shared output port 2.  That output link is
 * the bottleneck and each flow is offered at 0.7x its line rate, so their
 * combined 1.4x oversubscribes it.
 *
 * The switch egress runs strict priority across the 8 per-port queues and the
 * fabric grants priority-first, so the HIGH class is protected (served in full)
 * while the LOW class is throttled to the leftover capacity.  A finite egress
 * buffer (set via P4TrafficManager attribute defaults) makes the excess
 * low-priority load visible as Traffic-Manager drops instead of unbounded
 * queueing.
 *
 *   ./ns3 run p4-voq-fabric-priority
 *
 * Exit code 0 = strict priority observed (HIGH protected, HIGH > LOW, excess
 * dropped); non-zero = a check failed.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/data-rate.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4-traffic-manager.h"
#include "ns3/packet-sink.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/switched-ethernet-helper.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4VoqFabricPriority");

namespace
{

int g_failures = 0;

void
Check(bool cond, const std::string& what)
{
    std::cout << "  [" << (cond ? "PASS" : "FAIL") << "] " << what << "\n";
    if (!cond)
    {
        ++g_failures;
    }
}

} // namespace

int
main(int argc, char* argv[])
{
    std::string egressLink = "100Mbps"; // bottleneck: switch(port 2) -> receiver
    std::string ingressLink = "10Gbps"; // kept fast: senders -> switch
    uint32_t pktSize = 1400;            // UDP payload bytes
    double perFlowFactor = 0.7;         // each flow offered = factor * egress line
    double flowDuration = 0.2;          // seconds of saturating traffic
    uint32_t egressBufferBytes = 65536; // finite per-output egress buffer
    double protectThreshold = 0.85;     // HIGH must retain >= this fraction of offered

    CommandLine cmd;
    cmd.AddValue("egressLink", "Bottleneck egress link rate switch->receiver", egressLink);
    cmd.AddValue("ingressLink", "Ingress link rate senders->switch (kept fast)", ingressLink);
    cmd.AddValue("pktSize", "UDP payload size in bytes", pktSize);
    cmd.AddValue("perFlowFactor", "Per-flow offered load as a multiple of the egress line", perFlowFactor);
    cmd.AddValue("flowDuration", "Duration of the saturating flows (s)", flowDuration);
    cmd.AddValue("egressBufferBytes", "Per-output egress buffer limit in bytes (0 = unlimited)", egressBufferBytes);
    cmd.AddValue("protectThreshold", "HIGH must retain >= this fraction of its offered load", protectThreshold);
    cmd.Parse(argc, argv);

    const uint64_t egressBps = DataRate(egressLink).GetBitRate();
    const uint64_t perFlowBps = static_cast<uint64_t>(egressBps * perFlowFactor);
    std::ostringstream perFlowRate;
    perFlowRate << perFlowBps << "bps";

    std::cout << "=== VOQ+fabric strict-priority demo ===\n"
              << "  egressLink=" << egressLink << "  ingressLink=" << ingressLink
              << "  pktSize=" << pktSize << "  perFlow=" << perFlowFactor
              << "x egress line (combined " << (2 * perFlowFactor) << "x)\n"
              << "  HIGH=dport 4000 (prio 3) from host0   LOW=dport 2000 (prio 1) from host1\n"
              << "  egressBuffer=" << egressBufferBytes << " B\n";

    // A finite egress buffer turns the oversubscribed low-priority backlog into
    // Traffic-Manager drops.  The core creates the TM with CreateObject, so the
    // attribute default set here is picked up (the core only overrides port
    // count, rate, and the event-driven flags — not the buffer limits).
    if (egressBufferBytes > 0)
    {
        Config::SetDefault("ns3::P4TrafficManager::EgressPortLimit",
                           UintegerValue(egressBufferBytes));
    }

    // ---- Topology: host0 (HIGH), host1 (LOW) -> switch -> host2 (receiver) ----
    NodeContainer terminals;
    terminals.Create(3); // 0 = HIGH sender, 1 = LOW sender, 2 = receiver
    Ptr<Node> switchNode = CreateObject<Node>();

    InternetStackHelper internet;
    internet.Install(terminals);
    internet.Install(switchNode);

    Ipv4AddressHelper ipv4Addr;
    ipv4Addr.SetBase("10.1.1.0", "255.255.255.0");

    const std::string p4Dir = GetP4ExamplePath() + "/qos";

    P4Helper p4;
    p4.SetDeviceAttribute("JsonPath", StringValue(p4Dir + "/qos.json"));
    p4.SetDeviceAttribute("FlowTablePath", StringValue(p4Dir + "/flowtable_priority.txt"));
    p4.SetDeviceAttribute("P4SwitchArch", UintegerValue(0)); // V1model
    p4.SetDeviceAttribute("SwitchRate", UintegerValue(10000));
    p4.SetDeviceAttribute("EnableVoqFabric", BooleanValue(true));
    Ptr<P4SwitchNetDevice> sw = DynamicCast<P4SwitchNetDevice>(p4.Install(switchNode).Get(0));

    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", StringValue(ingressLink));
    eth.SetChannelAttribute("Delay", StringValue("1us"));
    NetDeviceContainer hostDevs = eth.Install(sw, terminals);

    // The qos flowtable rewrites the destination MAC on forwarding:
    //   10.1.1.1 -> port 0, MAC ...:01   (host0, HIGH sender)
    //   10.1.1.2 -> port 1, MAC ...:03   (host1, LOW sender)
    //   10.1.1.3 -> port 2, MAC ...:05   (host2, receiver)
    hostDevs.Get(0)->SetAddress(Mac48Address("00:00:00:00:00:01"));
    hostDevs.Get(1)->SetAddress(Mac48Address("00:00:00:00:00:03"));
    hostDevs.Get(2)->SetAddress(Mac48Address("00:00:00:00:00:05"));
    ipv4Addr.Assign(hostDevs.Get(0));
    ipv4Addr.Assign(hostDevs.Get(1));
    ipv4Addr.Assign(hostDevs.Get(2));

    // Slow down only the egress link switch(port 2) -> receiver so it is the
    // sole bottleneck; the ingress links keep the fast ingressLink rate.
    Ptr<SwitchedEthernetChannel> egressCh = sw->GetPortChannel(2);
    egressCh->SetAttribute("DataRate", DataRateValue(DataRate(egressLink)));

    // ---- Two competing UDP flows -> receiver (host2) ----
    const uint16_t highPort = 4000; // qos: prio 3 (HIGH)
    const uint16_t lowPort = 2000;  // qos: prio 1 (LOW)
    Ipv4Address rxAddr = terminals.Get(2)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();

    PacketSinkHelper highSink("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), highPort));
    PacketSinkHelper lowSink("ns3::UdpSocketFactory",
                             InetSocketAddress(Ipv4Address::GetAny(), lowPort));
    ApplicationContainer highSinkApp = highSink.Install(terminals.Get(2));
    ApplicationContainer lowSinkApp = lowSink.Install(terminals.Get(2));
    highSinkApp.Start(Seconds(1.0));
    lowSinkApp.Start(Seconds(1.0));
    highSinkApp.Stop(Seconds(2.0 + flowDuration + 1.0));
    lowSinkApp.Stop(Seconds(2.0 + flowDuration + 1.0));

    auto makeFlow = [&](uint32_t senderIdx, uint16_t dport) {
        OnOffHelper onOff("ns3::UdpSocketFactory", InetSocketAddress(rxAddr, dport));
        onOff.SetAttribute("PacketSize", UintegerValue(pktSize));
        onOff.SetAttribute("DataRate", StringValue(perFlowRate.str()));
        onOff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onOff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        ApplicationContainer app = onOff.Install(terminals.Get(senderIdx));
        app.Start(Seconds(2.0));
        app.Stop(Seconds(2.0 + flowDuration));
        return app;
    };
    makeFlow(0, highPort); // host0 -> HIGH
    makeFlow(1, lowPort);  // host1 -> LOW

    Simulator::Stop(Seconds(2.0 + flowDuration + 1.0));
    Simulator::Run();

    // ---- Capture results while the core / TM still exist ----
    const uint64_t highRx = DynamicCast<PacketSink>(highSinkApp.Get(0))->GetTotalRx();
    const uint64_t lowRx = DynamicCast<PacketSink>(lowSinkApp.Get(0))->GetTotalRx();

    uint64_t txPrioHigh = 0;
    uint64_t txPrioLow = 0;
    uint64_t tmReceived = 0;
    uint64_t tmDropped = 0;
    P4CoreV1model* core = sw->GetV1ModelCore();
    Ptr<P4TrafficManager> tm = core ? core->GetTrafficManager() : nullptr;
    if (tm)
    {
        const auto& s = tm->GetStats();
        txPrioHigh = s.perPriorityTransmitted[3];
        txPrioLow = s.perPriorityTransmitted[1];
        tmReceived = s.totalReceived;
        tmDropped = s.totalDropped;
    }

    Simulator::Destroy();

    // ---- Results ----
    const double highMbps = highRx * 8.0 / flowDuration / 1e6;
    const double lowMbps = lowRx * 8.0 / flowDuration / 1e6;
    const double offeredMbps = perFlowBps / 1e6;
    const double highRetained = (offeredMbps > 0) ? (highMbps / offeredMbps) : 0.0;

    std::cout << std::fixed << std::setprecision(2)
              << "  HIGH: rx=" << highRx << " B  ~" << highMbps << " Mbps  (offered ~"
              << offeredMbps << " Mbps, retained " << (highRetained * 100.0) << "%)\n"
              << "  LOW : rx=" << lowRx << " B  ~" << lowMbps << " Mbps  (offered ~" << offeredMbps
              << " Mbps)\n"
              << "  [TM] received=" << tmReceived << " transmitted prio3=" << txPrioHigh
              << " prio1=" << txPrioLow << " dropped=" << tmDropped << "\n";

    Check(tm != nullptr, "Traffic Manager active on the switch");
    Check(highRx > 0 && lowRx > 0, "Both priority classes carried some traffic");
    Check(highRx > lowRx, "HIGH priority delivered more than LOW under congestion");
    Check(txPrioHigh > txPrioLow, "TM transmitted more prio-3 frames than prio-1 frames");
    Check(highRetained >= protectThreshold, "HIGH priority protected (retained offered load)");
    Check(tmDropped > 0, "TM dropped the excess low-priority load (port oversubscribed)");

    std::cout << "=== " << (g_failures == 0 ? "STRICT PRIORITY OBSERVED" : "CHECKS FAILED") << " ("
              << g_failures << " failure(s)) ===\n";
    return g_failures == 0 ? 0 : 1;
}
