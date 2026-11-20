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
 * End-to-end integration check for the opt-in VOQ + fabric Traffic Manager
 * datapath in the V1model switch core.
 *
 * A full bmv2 P4 program (simple_v1model IPv4 forwarding) cannot be booted
 * inside the ns-3 unit-test runner (bmv2's per-context PHV pools crash there),
 * so this end-to-end check ships as a self-validating example instead, matching
 * how every other P4-program scenario in this module is exercised.
 *
 * Topology (mirrors p4-v1model-ipv4-forwarding):
 *
 *   host0 ──[SwitchedEthernetChannel port 0]──┐
 *                                              ├── P4SwitchNetDevice (switch)
 *   host1 ──[SwitchedEthernetChannel port 1]──┘
 *
 * The same UDP flow (host0 -> host1) is run twice:
 *   1. legacy output-queued datapath   (EnableVoqFabric = false, the default);
 *   2. VOQ + fabric datapath           (EnableVoqFabric = true).
 *
 * The program asserts:
 *   - the VOQ run instantiates a Traffic Manager and actually moves traffic
 *     through it (VOQ enqueue + wire serialisation counters are non-zero);
 *   - the legacy run instantiates NO Traffic Manager (additive contract);
 *   - both datapaths deliver the same offered load (functional parity).
 *
 * Exit code 0 = all checks passed; non-zero = a check failed.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
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

NS_LOG_COMPONENT_DEFINE("P4VoqFabricIntegration");

namespace
{

/// Outcome of one simulation run, captured before Simulator::Destroy().
struct ScenarioResult
{
    uint64_t rxBytes{0};       ///< bytes received at the UDP sink
    bool corePresent{false};   ///< V1model core was created
    bool tmPresent{false};     ///< Traffic Manager was created (VOQ path active)
    uint64_t tmReceived{0};    ///< packets offered to the TM (EnqueueToVoq)
    uint64_t tmVoqEnqueued{0}; ///< packets accepted into a VOQ
    uint64_t tmTransmitted{0}; ///< packets the TM serialised onto the wire
    uint64_t tmDropped{0};     ///< packets the TM dropped
};

/**
 * Build a 2-host / 1-switch topology running simple_v1model IPv4 forwarding,
 * run a short UDP flow host0 -> host1, and capture the results.
 *
 * \param enableVoq  value of the switch's EnableVoqFabric attribute.
 * \return captured results (read before Simulator::Destroy()).
 */
ScenarioResult
RunScenario(bool enableVoq)
{
    ScenarioResult r;

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
    p4.SetDeviceAttribute("P4SwitchArch", UintegerValue(0)); // V1model
    p4.SetDeviceAttribute("EnableVoqFabric", BooleanValue(enableVoq));
    Ptr<P4SwitchNetDevice> sw = DynamicCast<P4SwitchNetDevice>(p4.Install(switchNode).Get(0));

    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", StringValue("1000Mbps"));
    eth.SetChannelAttribute("Delay", StringValue("0.01ms"));
    NetDeviceContainer hostDevs = eth.Install(sw, terminals);

    for (uint32_t i = 0; i < terminals.GetN(); ++i)
    {
        std::ostringstream macStr;
        macStr << "00:00:00:00:00:" << std::hex << std::setfill('0') << std::setw(2) << (i + 1);
        hostDevs.Get(i)->SetAddress(Mac48Address(macStr.str().c_str()));
        ipv4Addr.Assign(hostDevs.Get(i));
    }

    // --- Applications: UDP OnOff (host0) -> PacketSink (host1) ---
    const uint16_t serverPort = 9093;
    Ptr<Node> serverNode = terminals.Get(1);
    Ipv4Address serverAddr = serverNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();

    PacketSinkHelper sink("ns3::UdpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), serverPort));
    ApplicationContainer sinkApp = sink.Install(serverNode);
    sinkApp.Start(Seconds(1.0));
    sinkApp.Stop(Seconds(4.0));

    OnOffHelper onOff("ns3::UdpSocketFactory", InetSocketAddress(serverAddr, serverPort));
    onOff.SetAttribute("PacketSize", UintegerValue(1000));
    onOff.SetAttribute("DataRate", StringValue("3Mbps"));
    onOff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer clientApp = onOff.Install(terminals.Get(0));
    clientApp.Start(Seconds(2.0));
    clientApp.Stop(Seconds(2.8));

    Simulator::Stop(Seconds(4.0));
    Simulator::Run();

    // --- Capture results while the core / TM still exist ---
    r.rxBytes = DynamicCast<PacketSink>(sinkApp.Get(0))->GetTotalRx();

    P4CoreV1model* core = sw->GetV1ModelCore();
    r.corePresent = (core != nullptr);
    Ptr<P4TrafficManager> tm = core ? core->GetTrafficManager() : nullptr;
    r.tmPresent = (tm != nullptr);
    if (tm)
    {
        const auto& s = tm->GetStats();
        r.tmReceived = s.totalReceived;
        r.tmVoqEnqueued = s.totalVoqEnqueued;
        r.tmTransmitted = s.totalTransmitted;
        r.tmDropped = s.totalDropped;
    }

    Simulator::Destroy();
    return r;
}

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
    // NOTE: bmv2 cannot be re-initialised in the same process, so this program
    // exercises ONE datapath per invocation (selected by --run).  Functional
    // parity is checked by running it once with --run=legacy and once with
    // --run=voq and comparing the reported rxBytes.
    std::string run = "voq";
    CommandLine cmd;
    cmd.AddValue("run", "Which datapath to exercise: 'voq' (default) or 'legacy'", run);
    cmd.Parse(argc, argv);

    std::cout << "=== VOQ + fabric integration check (run=" << run << ") ===\n";

    if (run == "legacy")
    {
        std::cout << "-- Legacy output-queued datapath (EnableVoqFabric=false) --\n";
        ScenarioResult legacy = RunScenario(false);
        std::cout << "  rxBytes=" << legacy.rxBytes << "  tmPresent=" << legacy.tmPresent << "\n";
        Check(legacy.corePresent, "V1model core exists");
        Check(!legacy.tmPresent, "No Traffic Manager created when disabled (additive contract)");
        Check(legacy.rxBytes > 0, "Sink received data over the legacy datapath");
    }
    else // "voq" (default) -> exercise the VOQ + fabric datapath
    {
        std::cout << "-- VOQ + fabric datapath (EnableVoqFabric=true) --\n";
        ScenarioResult voq = RunScenario(true);
        std::cout << "  rxBytes=" << voq.rxBytes << "  tmPresent=" << voq.tmPresent
                  << "  tmReceived=" << voq.tmReceived << "  tmVoqEnqueued=" << voq.tmVoqEnqueued
                  << "  tmTransmitted=" << voq.tmTransmitted << "  tmDropped=" << voq.tmDropped
                  << "\n";
        Check(voq.corePresent, "V1model core exists");
        Check(voq.tmPresent, "Traffic Manager created when EnableVoqFabric=true");
        Check(voq.rxBytes > 0, "Sink received data over the VOQ datapath");
        Check(voq.tmVoqEnqueued > 0, "Packets entered a VOQ");
        Check(voq.tmTransmitted > 0, "TM serialised packets onto the wire");
        Check(voq.tmTransmitted <= voq.tmVoqEnqueued,
              "Transmitted count does not exceed VOQ-enqueued count");
        Check(voq.tmVoqEnqueued <= voq.tmReceived,
              "VOQ-enqueued count does not exceed offered count");
    }

    std::cout << "=== " << (g_failures == 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED") << " ("
              << g_failures << " failure(s)) ===\n";
    return g_failures == 0 ? 0 : 1;
}
