/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * L2 learning: the controller learns from the digests of the switch.
 *
 *   host0 ──┐
 *   host1 ──┼── P4 switch (l2_learning.p4) ── digests ──> P4Controller
 *   host2 ──┘                              <── table entries ──
 *
 * The switch floods a frame to an unknown address to all other ports, and
 * sends a digest (source MAC, ingress port) for a frame from an unknown source.
 * The controller adds that address to the tables smac and dmac, so that later
 * frames to it go to its port only, and frames from it send no more digests.
 *
 * host0 and host2 each send five UDP echo requests to another host. Only the
 * ARP requests (broadcasts) are flooded, and each host sends one digest. With
 * --learn=0 the controller ignores the digests: every frame is flooded and
 * sends a digest.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-controller.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-runtime-api.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-helper.h"

#include <iomanip>
#include <set>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4L2Learning");

namespace
{

/// The controller of the example: it learns the port of each address
class Learner
{
  public:
    Learner(Ptr<P4Controller> controller, bool learn)
        : m_controller(controller),
          m_learn(learn)
    {
    }

    /// A digest of switch \p sw: learn_t {source MAC, ingress port}
    void OnDigest(uint32_t sw, const P4Digest& digest)
    {
        m_digests++;
        const std::string& mac = digest.fields[0].value; // 6 bytes
        uint32_t port = static_cast<uint32_t>(digest.fields[1].GetUint64());
        std::cout << std::fixed << std::setprecision(6) << Simulator::Now().GetSeconds()
                  << " s  switch " << sw << ": digest " << digest;
        // Digests of frames that reached the switch before the entries did
        if (!m_learn || !m_known.insert(mac).second)
        {
            std::cout << "\n";
            return;
        }
        std::vector<bm::MatchKeyParam> key = {
            bm::MatchKeyParam(bm::MatchKeyParam::Type::EXACT, mac)};
        bm::entry_handle_t handle = 0;
        m_controller->AddFlowEntry(sw, "MyIngress.smac", key, "MyIngress.known", {}, handle);
        bm::ActionData toPort;
        toPort.push_back_action_data(bm::Data(port));
        m_controller->AddFlowEntry(sw,
                                   "MyIngress.dmac",
                                   key,
                                   "MyIngress.forward",
                                   std::move(toPort),
                                   handle);
        std::cout << "  -> learned: port " << port << "\n";
    }

    uint32_t m_digests{0}; ///< digests received

  private:
    Ptr<P4Controller> m_controller;
    bool m_learn;                  ///< add table entries
    std::set<std::string> m_known; ///< the learned addresses
};

uint32_t g_echoes = 0; ///< echo replies received

void
EchoReply(Ptr<const Packet>)
{
    g_echoes++;
}

} // namespace

int
main(int argc, char* argv[])
{
    bool learn = true;
    CommandLine cmd;
    cmd.AddValue("learn", "The controller adds table entries for the digests", learn);
    cmd.Parse(argc, argv);

    std::string p4Dir = GetP4ExamplePath() + "/l2_learning";

    NodeContainer hosts;
    hosts.Create(3);
    Ptr<Node> switchNode = CreateObject<Node>();

    P4Helper p4;
    p4.SetDeviceAttribute("JsonPath", StringValue(p4Dir + "/l2_learning.json"));
    p4.SetDeviceAttribute("FlowTablePath", StringValue(p4Dir + "/flowtable.txt")); // flood group
    p4.SetDeviceAttribute("P4SwitchArch", UintegerValue(P4SWITCH_ARCH_V1MODEL));
    Ptr<P4SwitchNetDevice> sw = DynamicCast<P4SwitchNetDevice>(p4.Install(switchNode).Get(0));

    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", StringValue("1Gbps"));
    eth.SetChannelAttribute("Delay", StringValue("10us"));
    NetDeviceContainer hostDevs = eth.Install(sw, hosts);

    InternetStackHelper internet;
    internet.Install(hosts);
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    for (uint32_t i = 0; i < hosts.GetN(); ++i)
    {
        std::ostringstream mac;
        mac << "00:00:00:00:00:0" << i + 1;
        hostDevs.Get(i)->SetAddress(Mac48Address(mac.str().c_str()));
    }
    Ipv4InterfaceContainer addresses = ipv4.Assign(hostDevs);

    // The controller gets the digests of the switch
    Ptr<P4Controller> controller = CreateObject<P4Controller>();
    controller->RegisterSwitch(sw);
    Learner learner(controller, learn);
    controller->SetDigestCallback(MakeCallback(&Learner::OnDigest, &learner));

    // host0 -> host1 from 1 s, host2 -> host0 from 2 s: five echo requests each
    UdpEchoServerHelper server(9);
    server.Install(hosts.Get(0)).Start(Seconds(0.5));
    server.Install(hosts.Get(1)).Start(Seconds(0.5));
    const std::pair<uint32_t, uint32_t> flows[] = {{0, 1}, {2, 0}};
    for (const auto& [from, to] : flows)
    {
        UdpEchoClientHelper client(addresses.GetAddress(to), 9);
        client.SetAttribute("MaxPackets", UintegerValue(5));
        client.SetAttribute("Interval", TimeValue(MilliSeconds(100)));
        ApplicationContainer app = client.Install(hosts.Get(from));
        app.Start(Seconds(1.0 + from / 2.0));
        app.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&EchoReply));
    }

    Simulator::Stop(Seconds(4));
    Simulator::Run();

    // The counter of the P4 program, read with the BMv2 runtime API
    bm::MatchTableAbstract::counter_value_t bytes = 0;
    bm::MatchTableAbstract::counter_value_t flooded = 0;
    P4RuntimeApi(*sw->GetCore()).ReadCounter("MyIngress.flooded", 0, &bytes, &flooded);
    std::cout << "Echo replies: " << g_echoes << " of 10\n"
              << "Digests: " << learner.m_digests << "\n"
              << "Flooded frames: " << flooded << "\n"
              << "Entries in dmac: " << controller->GetTableEntryCount(0, "MyIngress.dmac") << "\n";

    Simulator::Destroy();
    return 0;
}
