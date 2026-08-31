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
 * Throughput benchmark for the VOQ + fabric Traffic Manager datapath.
 *
 * A single saturating UDP flow (offered load above link capacity) is sent
 * host0 -> host1 through a V1model switch running IPv4 forwarding, and the
 * goodput received at the sink is compared against the link's line rate.
 *
 * Because the VOQ datapath serialises each egress port at the port's own line
 * rate (PortRate, seeded from the channel) and is driven by the transmit
 * completion signal rather than a fixed timer, the delivered goodput should
 * sit just below line rate (the small gap is Ethernet/IP/UDP header overhead),
 * with no artificial timer bottleneck.
 *
 * One link rate per invocation (bmv2 cannot be re-initialised in a process):
 *   ./ns3 run "p4-voq-fabric-throughput --linkRate=100Mbps"
 *   ./ns3 run "p4-voq-fabric-throughput --linkRate=1000Mbps"
 *
 * Exit code 0 = goodput reached the near-line-rate threshold; non-zero = below.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/data-rate.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4-traffic-manager.h"
#include "ns3/packet-sink.h"
#include "ns3/switched-ethernet-helper.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4VoqFabricThroughput");

namespace
{

uint64_t g_rxBytes = 0;
double g_firstRx = -1.0;
double g_lastRx = 0.0;

void
RxTrace(uint32_t payloadSize, Ptr<const Packet> pkt, const Address&)
{
    // Count only full data packets (skip stray/short frames).
    if (pkt->GetSize() != payloadSize)
    {
        return;
    }
    double now = Simulator::Now().GetSeconds();
    if (g_firstRx < 0.0)
    {
        g_firstRx = now;
    }
    g_lastRx = now;
    g_rxBytes += pkt->GetSize();
}

} // namespace

int
main(int argc, char* argv[])
{
    std::string linkRate = "1000Mbps";   // egress (bottleneck) link switch -> host1
    std::string hostLinkRate = "10Gbps";  // ingress link host0 -> switch (kept fast)
    uint32_t pktSize = 1400;       // UDP payload bytes
    double offeredFactor = 1.2;    // offered load = offeredFactor * linkRate
    double flowDuration = 0.2;     // seconds of saturating traffic
    bool voq = true;               // use the VOQ + fabric datapath
    double passThreshold = 0.80;   // PASS if goodput >= threshold * linkRate

    CommandLine cmd;
    cmd.AddValue("linkRate", "Egress (bottleneck) link rate switch->host1", linkRate);
    cmd.AddValue("hostLinkRate", "Ingress link rate host0->switch (kept fast)", hostLinkRate);
    cmd.AddValue("pktSize", "UDP payload size in bytes", pktSize);
    cmd.AddValue("offeredFactor", "Offered load as a multiple of the egress link rate", offeredFactor);
    cmd.AddValue("flowDuration", "Duration of the saturating flow (s)", flowDuration);
    cmd.AddValue("voq", "Use the VOQ+fabric datapath (else legacy)", voq);
    cmd.AddValue("passThreshold", "PASS if goodput >= threshold * linkRate", passThreshold);
    cmd.Parse(argc, argv);

    const uint64_t linkBps = DataRate(linkRate).GetBitRate();
    const uint64_t offeredBps = static_cast<uint64_t>(linkBps * offeredFactor);
    std::ostringstream offeredRate;
    offeredRate << offeredBps << "bps";

    // The ingress link host0->switch is kept fast so the host NIC (which has no
    // tx queue and drops on a busy channel) never becomes the limiter; the
    // switch's egress port switch->host1 is the sole bottleneck under test.
    std::cout << "=== VOQ+fabric throughput benchmark ===\n"
              << "  egressLink=" << linkRate << "  ingressLink=" << hostLinkRate
              << "  datapath=" << (voq ? "VOQ+fabric" : "legacy") << "  pktSize=" << pktSize
              << "  offered=" << offeredFactor << "x egress line\n";

    // ---- Topology: host0 -> switch -> host1 ----
    NodeContainer terminals;
    terminals.Create(2);
    Ptr<Node> switchNode = CreateObject<Node>();

    InternetStackHelper internet;
    internet.Install(terminals);
    internet.Install(switchNode);

    Ipv4AddressHelper ipv4Addr;
    ipv4Addr.SetBase("10.1.1.0", "255.255.255.0");

    const std::string p4Dir = GetP4ExamplePath() + "/simple_v1model";

    P4Helper p4;
    p4.SetDeviceAttribute("JsonPath", StringValue(p4Dir + "/simple_v1model.json"));
    p4.SetDeviceAttribute("FlowTablePath", StringValue(p4Dir + "/flowtable_0.txt"));
    p4.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));
    p4.SetDeviceAttribute("SwitchRate", UintegerValue(10000));
    p4.SetDeviceAttribute("EnableVoqFabric", BooleanValue(voq));
    Ptr<P4SwitchNetDevice> sw = DynamicCast<P4SwitchNetDevice>(p4.Install(switchNode).Get(0));

    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", StringValue(hostLinkRate));
    eth.SetChannelAttribute("Delay", StringValue("1us"));
    NetDeviceContainer hostDevs = eth.Install(sw, terminals);

    for (uint32_t i = 0; i < terminals.GetN(); ++i)
    {
        std::ostringstream mac;
        mac << "00:00:00:00:00:" << std::hex << std::setfill('0') << std::setw(2) << (i + 1);
        hostDevs.Get(i)->SetAddress(Mac48Address(mac.str().c_str()));
        ipv4Addr.Assign(hostDevs.Get(i));
    }

    // Slow down only the egress link switch(port 1) -> host1 so it is the
    // bottleneck; the ingress link keeps the fast hostLinkRate set above.
    Ptr<SwitchedEthernetChannel> egressCh = sw->GetPortChannel(1);
    egressCh->SetAttribute("DataRate", DataRateValue(DataRate(linkRate)));

    // ---- Saturating UDP flow host0 -> host1 ----
    const uint16_t serverPort = 9000;
    Ipv4Address serverAddr = terminals.Get(1)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();

    PacketSinkHelper sink("ns3::UdpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), serverPort));
    ApplicationContainer sinkApp = sink.Install(terminals.Get(1));
    sinkApp.Start(Seconds(1.0));
    sinkApp.Stop(Seconds(2.0 + flowDuration + 1.0));

    OnOffHelper onOff("ns3::UdpSocketFactory", InetSocketAddress(serverAddr, serverPort));
    onOff.SetAttribute("PacketSize", UintegerValue(pktSize));
    onOff.SetAttribute("DataRate", StringValue(offeredRate.str()));
    onOff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer clientApp = onOff.Install(terminals.Get(0));
    clientApp.Start(Seconds(2.0));
    clientApp.Stop(Seconds(2.0 + flowDuration));

    sinkApp.Get(0)->TraceConnectWithoutContext("Rx", MakeBoundCallback(&RxTrace, pktSize));

    Simulator::Stop(Seconds(2.0 + flowDuration + 1.0));
    Simulator::Run();

    if (voq)
    {
        P4CoreV1model* core = sw->GetV1ModelCore();
        Ptr<P4TrafficManager> tm = core ? core->GetTrafficManager() : nullptr;
        if (tm)
        {
            const auto& s = tm->GetStats();
            std::cout << "  [TM] received=" << s.totalReceived << " voqEnq=" << s.totalVoqEnqueued
                      << " transmitted=" << s.totalTransmitted << " dropped=" << s.totalDropped
                      << "\n";
        }
    }

    Simulator::Destroy();

    // ---- Results ----
    const double window = (g_lastRx > g_firstRx) ? (g_lastRx - g_firstRx) : flowDuration;
    const double goodputMbps = (window > 0) ? (g_rxBytes * 8.0 / window / 1e6) : 0.0;
    const double linkMbps = linkBps / 1e6;
    const double pctOfLink = (linkMbps > 0) ? (goodputMbps / linkMbps * 100.0) : 0.0;

    // Header-overhead ceiling for reference: payload / (payload + Eth+IP+UDP).
    const double ceilingPct = 100.0 * pktSize / (pktSize + 14 + 20 + 8);

    std::cout << std::fixed << std::setprecision(2) << "  rxBytes=" << g_rxBytes
              << "  window=" << window << "s\n"
              << "  goodput=" << goodputMbps << " Mbps of " << linkMbps << " Mbps line ("
              << pctOfLink << "% of line; header-overhead ceiling ~" << ceilingPct << "%)\n";

    const bool pass = pctOfLink >= passThreshold * 100.0;
    std::cout << "  [" << (pass ? "PASS" : "FAIL") << "] goodput >= " << (passThreshold * 100.0)
              << "% of line rate\n"
              << "=== " << (pass ? "NEAR LINE RATE" : "BELOW THRESHOLD") << " ===\n";
    return pass ? 0 : 1;
}
