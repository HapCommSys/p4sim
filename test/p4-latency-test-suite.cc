// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * The latency models of the target profiles (doc/latency-model.md).
 * - A1-A8: Model A, the Tofino ingress pipeline latency of Franco et al., with
 *   the coefficients of profiles/tofino-like.json: each term within 0.01 ns of
 *   the vectors of the handoff spec, which the formula gives. Inputs outside
 *   the model's range give warnings.
 * - The latency features of a program: its parse states and tables from the
 *   BMv2 JSON, and per packet the parse states it passed and the tables it
 *   matched, from BMv2's pipeline events (p4src/latency).
 * - Store-and-forward with the tofino-like profile: a frame leaves the switch
 *   MAC receive + Model A + egress after its last bit; the switch reports the
 *   first and last bit of each frame; a short frame does not overtake a long
 *   one in the pipeline; with SwitchRate, the latency follows the wait for the
 *   pipeline; a profile's queue_capacity sizes the output queues.
 * - C1-C9: the zero-buffer cut-through switch of the cut-through-reference
 *   profile, in the 3-port configuration (C1 and C6 also with 4 ports), cycle
 *   for cycle as the RTL simulation of the handoff spec: fixed latency from the
 *   first bit, drops at a busy egress port, flooding per port, one lookup per
 *   cycle (p4src/cut_through).
 * - Learning: a table of 4 entries (the profile's capacity, or the P4 table's
 *   size) that replaces the oldest and ages entries after 300 s (data plane),
 *   the control-plane path with its delay, and a program swap, after which
 *   the table learns again.
 */

#include "ns3/core-module.h"
#include "ns3/eth-net-device.h"
#include "ns3/format-utils.h"
#include "ns3/link-framing.h"
#include "ns3/network-module.h"
#include "ns3/p4-latency-features.h"
#include "ns3/p4-runtime-api.h"
#include "ns3/p4-switch-core.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4sim-ns3-compat.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/target-profile.h"
#include "ns3/test.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <functional>
#include <sstream>
#include <tuple>

using namespace ns3;

namespace
{

constexpr double TOLERANCE_NS = 0.01;  ///< the spec's tolerance for the Model A vectors
constexpr uint16_t ETHERTYPE = 0x88b5; ///< of the test frames without IPv4
constexpr uint32_t FCS_BYTES = 4;      ///< the frame check sequence, which ns-3 frames lack

/// A table that the packet matched
LatencyTableFeature
Table(const std::string& matchType, uint32_t keyBits, uint32_t keyCount = 1)
{
    return LatencyTableFeature{"t", matchType, keyBits, keyCount};
}

/// \p count copies of \p table
std::vector<LatencyTableFeature>
Tables(uint32_t count, const LatencyTableFeature& table)
{
    return std::vector<LatencyTableFeature>(count, table);
}

/// One Model A vector: inputs and the expected terms in ns
struct ModelAVector
{
    std::string id;                          ///< A1 ... A8
    double speedBps;                         ///< port speed
    uint32_t packetBytes;                    ///< p
    std::vector<uint32_t> parseStates;       ///< h_n after Ethernet
    std::vector<LatencyTableFeature> tables; ///< tables matched
    double base;                             ///< L_B
    double parser;                           ///< L_PD
    double control;                          ///< L_C
    double total;                            ///< L(T1->T2)
};

/// \return whether one of \p warnings contains \p text
bool
HasWarning(const std::vector<std::string>& warnings, const std::string& text)
{
    return std::any_of(warnings.begin(), warnings.end(), [&](const std::string& w) {
        return w.find(text) != std::string::npos;
    });
}

/// A switch with one host per port, on switched-Ethernet links with Ethernet framing
struct Network
{
    Ptr<P4SwitchNetDevice> sw;                          ///< the switch
    std::vector<Ptr<SwitchedEthernetHostDevice>> hosts; ///< host i on port i
};

/// The settings of a test network
struct Setup
{
    std::string json;            ///< P4 program, relative to test/p4src
    std::string flowTable;       ///< flow-table file, relative to test/p4src; "": none
    std::string profile;         ///< TargetProfile
    uint32_t ports{3};           ///< ports (and hosts)
    std::string rate{"100Mbps"}; ///< data rate of every link
    bool learning{false};        ///< LearningTable MyIngress.dmac, action MyIngress.forward
    Time controlPlaneDelay{NanoSeconds(-1)}; ///< ControlPlaneDelay
    uint64_t switchRate{0};                  ///< SwitchRate
    uint32_t queueBufferSize{0};             ///< QueueBufferSize; 0: its default
    bool enableSwap{false};                  ///< EnableSwap
};

/// The MAC address of host \p i: A, B, C, D = 00:00:00:00:00:0a, 0b, 0c, 0d
Mac48Address
HostMac(uint32_t i)
{
    std::ostringstream text;
    text << "00:00:00:00:00:0" << static_cast<char>('a' + i);
    return Mac48Address(text.str().c_str());
}

/// Build the network of \p setup
Network
Build(const Setup& setup)
{
    Network net;
    Ptr<Node> switchNode = CreateObject<Node>();
    net.sw = CreateObject<P4SwitchNetDevice>();
    net.sw->SetAttribute("P4SwitchArch", UintegerValue(P4SWITCH_ARCH_V1MODEL));
    net.sw->SetAttribute("JsonPath", StringValue(GetP4TestPath() + "/" + setup.json));
    net.sw->SetAttribute(
        "FlowTablePath",
        StringValue(setup.flowTable.empty() ? "" : GetP4TestPath() + "/" + setup.flowTable));
    net.sw->SetAttribute("TargetProfile", StringValue(setup.profile));
    if (setup.learning)
    {
        net.sw->SetAttribute("LearningTable", StringValue("MyIngress.dmac"));
        net.sw->SetAttribute("LearningAction", StringValue("MyIngress.forward"));
        net.sw->SetAttribute("ControlPlaneDelay", TimeValue(setup.controlPlaneDelay));
    }
    net.sw->SetAttribute("SwitchRate", UintegerValue(setup.switchRate));
    if (setup.queueBufferSize > 0)
    {
        net.sw->SetAttribute("QueueBufferSize", UintegerValue(setup.queueBufferSize));
    }
    net.sw->SetAttribute("EnableSwap", BooleanValue(setup.enableSwap));
    switchNode->AddDevice(net.sw);
    for (uint32_t i = 0; i < setup.ports; i++)
    {
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        channel->SetAttribute("DataRate", DataRateValue(DataRate(setup.rate)));
        channel->SetAttribute("Delay", TimeValue(Seconds(0)));
        channel->SetAttribute("Framing",
                              P4SIM_ENUM_VALUE(LinkFraming::Type)(LinkFraming::ETHERNET));
        net.sw->Attach(channel);
        Ptr<Node> node = CreateObject<Node>();
        Ptr<SwitchedEthernetHostDevice> host = CreateObject<SwitchedEthernetHostDevice>();
        host->SetAddress(HostMac(i));
        node->AddDevice(host);
        host->Attach(channel);
        net.hosts.push_back(host);
    }
    net.sw->Initialize();
    return net;
}

/// Host \p host sends a frame of \p frameBytes (Ethernet header included, FCS not) to \p dst
void
SendFrame(Ptr<SwitchedEthernetHostDevice> host, Mac48Address dst, uint32_t frameBytes)
{
    host->Send(Create<Packet>(frameBytes - 14), dst, ETHERTYPE);
}

/// Host \p host sends a frame with \p source as its source address
void
SendFrom(Ptr<SwitchedEthernetHostDevice> host, Mac48Address source, uint32_t frameBytes)
{
    host->SendFrom(Create<Packet>(frameBytes - 14),
                   source,
                   Mac48Address::GetBroadcast(),
                   ETHERTYPE);
}

/**
 * Host \p host sends an IPv4/UDP frame of \p frameBytes from 10.0.0.1 to
 * 10.0.0.2, port 4000 to 5000 (p4src/latency routes it to port 1)
 */
void
SendUdp(Ptr<SwitchedEthernetHostDevice> host, uint32_t frameBytes)
{
    const uint32_t ipBytes = frameBytes - 14;
    const uint32_t udpBytes = ipBytes - 20;
    std::vector<uint8_t> bytes(ipBytes, 0);
    const uint8_t headers[28] = {0x45,
                                 0,
                                 uint8_t(ipBytes >> 8),
                                 uint8_t(ipBytes),
                                 0,
                                 0,
                                 0,
                                 0,
                                 64,
                                 17,
                                 0,
                                 0,
                                 10,
                                 0,
                                 0,
                                 1,
                                 10,
                                 0,
                                 0,
                                 2,
                                 0x0f,
                                 0xa0,
                                 0x13,
                                 0x88,
                                 uint8_t(udpBytes >> 8),
                                 uint8_t(udpBytes),
                                 0,
                                 0};
    std::copy(std::begin(headers), std::end(headers), bytes.begin());
    host->Send(Create<Packet>(bytes.data(), ipBytes), Mac48Address("00:00:00:00:00:0b"), 0x0800);
}

/// A frame that a host received: when, and its size and addresses
struct Received
{
    uint32_t port;    ///< the host (= switch port)
    Time at;          ///< when its last bit arrived
    uint32_t bytes;   ///< its size, Ethernet header included
    Mac48Address src; ///< its source
    Mac48Address dst; ///< its destination
};

/// Record a frame delivered to host \p port, unless the host sent it
void
RecordFrame(std::vector<Received>* frames,
            uint32_t port,
            Mac48Address self,
            Ptr<const Packet> frame)
{
    EthernetHeader eth;
    frame->PeekHeader(eth);
    if (eth.GetSource() != self)
    {
        frames->push_back(
            {port, Simulator::Now(), frame->GetSize(), eth.GetSource(), eth.GetDestination()});
    }
}

/// Record every frame that reaches a host of \p net
void
RecordAll(const Network& net, std::vector<Received>* frames)
{
    for (uint32_t i = 0; i < net.hosts.size(); i++)
    {
        net.hosts[i]->TraceConnectWithoutContext(
            "PromiscSniffer",
            MakeBoundCallback(&RecordFrame,
                              frames,
                              i,
                              Mac48Address::ConvertFrom(net.hosts[i]->GetAddress())));
    }
}

} // namespace

/**
 * \ingroup p4sim-tests
 * One vector of Model A: the three terms and their sum
 */
class ModelAVectorTestCase : public TestCase
{
  public:
    ModelAVectorTestCase(const ModelAVector& vector)
        : TestCase("Model A vector " + vector.id),
          m_vector(vector)
    {
    }

  private:
    void DoRun() override
    {
        std::shared_ptr<const TargetProfile> profile = TargetProfile::Load("tofino-like");
        IngressLatencyEstimate estimate = profile->TofinoIngressLatencyNs(m_vector.packetBytes,
                                                                          m_vector.speedBps,
                                                                          m_vector.parseStates,
                                                                          m_vector.tables);
        NS_TEST_EXPECT_MSG_EQ_TOL(estimate.baseNs, m_vector.base, TOLERANCE_NS, "L_B");
        NS_TEST_EXPECT_MSG_EQ_TOL(estimate.parserNs, m_vector.parser, TOLERANCE_NS, "L_PD");
        NS_TEST_EXPECT_MSG_EQ_TOL(estimate.controlNs, m_vector.control, TOLERANCE_NS, "L_C");
        NS_TEST_EXPECT_MSG_EQ_TOL(estimate.TotalNs(), m_vector.total, TOLERANCE_NS, "Total");
    }

    ModelAVector m_vector; ///< the vector
};

/**
 * \ingroup p4sim-tests
 * Model A warns, and does not fail, outside the range it was fitted on
 */
class ModelAWarningsTestCase : public TestCase
{
  public:
    ModelAWarningsTestCase()
        : TestCase("Model A warns outside its range")
    {
    }

  private:
    void DoRun() override
    {
        std::shared_ptr<const TargetProfile> profile = TargetProfile::Load("tofino-like");
        IngressLatencyEstimate inRange =
            profile->TofinoIngressLatencyNs(300, 100e9, {20}, {Table("exact", 32)});
        NS_TEST_EXPECT_MSG_EQ(inRange.warnings.size(), 0, "Warnings inside the range");

        IngressLatencyEstimate e = profile->TofinoIngressLatencyNs(
            50,
            25e9,
            {30},
            {Table("ternary", 8), Table("exact", 48), Table("lpm", 16, 2)});
        const std::vector<std::string>& w = e.warnings;
        NS_TEST_EXPECT_MSG_EQ(HasWarning(w, "no coefficients for 25 Gbps"), true, "Port speed");
        NS_TEST_EXPECT_MSG_EQ(HasWarning(w, "100 to 1400 bytes, not 50"), true, "Packet size");
        NS_TEST_EXPECT_MSG_EQ(HasWarning(w, "header bytes per parse state, not 30"),
                              true,
                              "Header size");
        NS_TEST_EXPECT_MSG_EQ(HasWarning(w, "no coefficient for ternary"), true, "Match type");
        NS_TEST_EXPECT_MSG_EQ(HasWarning(w, "not 48"), true, "Key width");
        NS_TEST_EXPECT_MSG_EQ(HasWarning(w, "several keys only"), true, "LPM with two keys");
        NS_TEST_EXPECT_MSG_EQ(HasWarning(w, "did not fit on a mix"), true, "Mixed tables");
        NS_TEST_EXPECT_MSG_GT(e.TotalNs(), 0, "No latency");

        // At 10G the model is linear up to 800 bytes, 5 states and 5 bytes per state
        IngressLatencyEstimate nonLinear =
            profile->TofinoIngressLatencyNs(1000, 10e9, {2}, {Table("exact", 8)});
        NS_TEST_EXPECT_MSG_EQ(HasWarning(nonLinear.warnings, "linear only up to"),
                              true,
                              "Non-linear range at 10G");
    }
};

/**
 * \ingroup p4sim-tests
 * The latency features of a program from its BMv2 JSON, and per packet from
 * BMv2's events: an IPv4/UDP frame through p4src/latency passes three parse
 * states (14, 20, 8 bytes), matches route and source and misses port_filter
 */
class ProgramFeaturesTestCase : public TestCase
{
  public:
    ProgramFeaturesTestCase()
        : TestCase("Latency features of a program and of a packet")
    {
    }

  private:
    void DoRun() override
    {
        P4LatencyFeatures program;
        std::string error;
        NS_TEST_ASSERT_MSG_EQ(
            program.LoadFile(GetP4TestPath() + "/latency/latency_v1model.json", &error),
            true,
            error);

        std::vector<std::string> states;
        for (const P4LatencyFeatures::ParseState& state : program.GetParseStates())
        {
            states.push_back(state.parser + ":" + state.name + ":" +
                             (state.extracts.empty() ? "" : state.extracts.front()));
        }
        std::vector<std::string> expectedStates = {"parser:start:ethernet",
                                                   "parser:parse_ipv4:ipv4",
                                                   "parser:parse_udp:udp"};
        NS_TEST_EXPECT_MSG_EQ((states == expectedStates), true, "Parse states");

        const LatencyTableFeature* route = program.FindTable("MyIngress.route");
        const LatencyTableFeature* source = program.FindTable("MyIngress.source");
        const LatencyTableFeature* filter = program.FindTable("MyIngress.port_filter");
        NS_TEST_ASSERT_MSG_EQ((route && source && filter), true, "Tables missing");
        NS_TEST_EXPECT_MSG_EQ(route->matchType + std::to_string(route->keyBits) + "/" +
                                  std::to_string(route->keyCount),
                              "exact32/1",
                              "route");
        NS_TEST_EXPECT_MSG_EQ(source->matchType + std::to_string(source->keyBits),
                              "lpm32",
                              "source");
        NS_TEST_EXPECT_MSG_EQ(filter->matchType + std::to_string(filter->keyBits),
                              "exact16",
                              "port_filter");

        // One frame through a switch with the tofino-like profile: the features
        // that its ingress pass collects from BMv2's events
        Setup setup;
        setup.json = "latency/latency_v1model.json";
        setup.flowTable = "latency/flowtable.txt";
        setup.profile = "tofino-like";
        setup.ports = 2;
        setup.rate = "10Gbps";
        Network net = Build(setup);
        PacketLatencyFeatures features;
        {
            // The same collection that IngressPass runs, around a parse and the ingress
            P4SwitchCore* core = net.sw->GetCore();
            std::vector<uint8_t> frame(14 + 28 + 100, 0);
            const uint8_t eth[14] = {0, 0, 0, 0, 0, 0x0b, 0, 0, 0, 0, 0, 0x0a, 0x08, 0x00};
            const uint8_t ipUdp[28] = {0x45, 0,    0,    128,  0, 0,   0,  0, 64, 17,
                                       0,    0,    10,   0,    0, 1,   10, 0, 0,  2,
                                       0x0f, 0xa0, 0x13, 0x88, 0, 108, 0,  0};
            std::copy(std::begin(eth), std::end(eth), frame.begin());
            std::copy(std::begin(ipUdp), std::end(ipUdp), frame.begin() + 14);
            auto packet =
                core->new_packet_ptr(0,
                                     0,
                                     frame.size(),
                                     bm::PacketBuffer(frame.size() + 512,
                                                      reinterpret_cast<char*>(frame.data()),
                                                      frame.size()));
            LatencyFeatureCollector collector(&features, "parser", "ingress");
            core->get_parser("parser")->parse(packet.get());
            core->get_pipeline("ingress")->apply(packet.get());
        }
        Simulator::Destroy();

        std::vector<uint32_t> stateBytes =
            program.GetStateBytes("parser", features.extractedHeaders);
        NS_TEST_EXPECT_MSG_EQ((stateBytes == std::vector<uint32_t>{14, 20, 8}),
                              true,
                              "Header bytes per parse state");
        NS_TEST_EXPECT_MSG_EQ(
            (features.hitTables == std::vector<std::string>{"MyIngress.route", "MyIngress.source"}),
            true,
            "Tables that matched");
        NS_TEST_EXPECT_MSG_EQ(
            (features.missedTables == std::vector<std::string>{"MyIngress.port_filter"}),
            true,
            "Tables that missed");
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * Store-and-forward with the tofino-like profile at 10 Gbps: an 800-byte
 * IPv4/UDP frame leaves the switch MAC receive + Model A + egress after its
 * last bit arrived; FrameArrival reports its first and last bit
 */
class StoreAndForwardLatencyTestCase : public TestCase
{
  public:
    StoreAndForwardLatencyTestCase()
        : TestCase("Store-and-forward: MAC receive + Model A + egress after the last bit")
    {
    }

  private:
    void DoRun() override
    {
        Setup setup;
        setup.json = "latency/latency_v1model.json";
        setup.flowTable = "latency/flowtable.txt";
        setup.profile = "tofino-like";
        setup.ports = 2;
        setup.rate = "10Gbps";
        Network net = Build(setup);
        std::vector<Received> frames;
        RecordAll(net, &frames);
        std::vector<std::tuple<uint32_t, Time, Time>> arrivals;
        net.sw->TraceConnectWithoutContext(
            "FrameArrival",
            MakeBoundCallback(
                +[](std::vector<std::tuple<uint32_t, Time, Time>>* a,
                    Ptr<const Packet>,
                    uint32_t port,
                    Time firstBit,
                    Time lastBit) { a->emplace_back(port, firstBit, lastBit); },
                &arrivals));

        const uint32_t FRAME = 800;
        const Time sent = MilliSeconds(1);
        Simulator::Schedule(sent, &SendUdp, net.hosts[0], FRAME);
        Simulator::Stop(MilliSeconds(2));
        Simulator::Run();
        Simulator::Destroy();

        // The expected latency, from the profile: 2 parse states after
        // Ethernet (20 and 8 bytes), route (exact, 32 bits) and source (LPM,
        // 32 bits) matched; port_filter missed and adds nothing
        std::shared_ptr<const TargetProfile> profile = TargetProfile::Load("tofino-like");
        IngressLatencyEstimate a =
            profile->TofinoIngressLatencyNs(FRAME,
                                            10e9,
                                            {20, 8},
                                            {Table("exact", 32), Table("lpm", 32)});
        double latencyNs = profile->macRxDelay.meanNs + a.TotalNs() + profile->egressDelay.meanNs;
        double wireNs = LinkFraming(LinkFraming::ETHERNET).GetWireBytes(FRAME) * 8 / 10.0;

        NS_TEST_ASSERT_MSG_EQ(arrivals.size(), 1, "FrameArrival");
        NS_TEST_EXPECT_MSG_EQ(std::get<0>(arrivals[0]), 0, "Ingress port");
        NS_TEST_EXPECT_MSG_EQ_TOL(std::get<1>(arrivals[0]).GetNanoSeconds(),
                                  sent.GetNanoSeconds(),
                                  1,
                                  "First bit");
        NS_TEST_EXPECT_MSG_EQ_TOL(std::get<2>(arrivals[0]).GetNanoSeconds(),
                                  sent.GetNanoSeconds() + wireNs,
                                  1,
                                  "Last bit");

        NS_TEST_ASSERT_MSG_EQ(frames.size(), 1, "The frame did not arrive at host 1");
        NS_TEST_EXPECT_MSG_EQ(frames[0].port, 1, "Wrong port");
        // Last bit in, the latency, then the frame's time on the wire out
        double expectedNs = sent.GetNanoSeconds() + wireNs + latencyNs + wireNs;
        NS_TEST_EXPECT_MSG_EQ_TOL(frames[0].at.GetNanoSeconds(), expectedNs, 2, "Arrival");
    }
};

/**
 * \ingroup p4sim-tests
 * A 100-byte frame right behind a 1400-byte frame has the smaller Model A
 * latency, but does not overtake it: it leaves right behind it
 */
class PipelineOrderTestCase : public TestCase
{
  public:
    PipelineOrderTestCase()
        : TestCase("Per-packet latency: the packets keep their order")
    {
    }

  private:
    void DoRun() override
    {
        Setup setup;
        setup.json = "latency/latency_v1model.json";
        setup.flowTable = "latency/flowtable.txt";
        setup.profile = "tofino-like";
        setup.ports = 2;
        setup.rate = "10Gbps";
        Network net = Build(setup);
        std::vector<Received> frames;
        RecordAll(net, &frames);
        Simulator::Schedule(MilliSeconds(1), &SendUdp, net.hosts[0], 1400);
        Simulator::Schedule(MilliSeconds(1), &SendUdp, net.hosts[0], 100);
        Simulator::Stop(MilliSeconds(2));
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(frames.size(), 2, "Frames lost");
        NS_TEST_EXPECT_MSG_EQ(frames[0].bytes, 1400, "The short frame overtook the long one");
        NS_TEST_EXPECT_MSG_EQ(frames[1].bytes, 100, "Second frame");
        // Back to back on the egress: the gap, then the short frame
        LinkFraming ethernet(LinkFraming::ETHERNET);
        double spacingNs = (ethernet.GetGapBytes() + ethernet.GetWireBytes(100)) * 8 / 10.0;
        NS_TEST_EXPECT_MSG_EQ_TOL((frames[1].at - frames[0].at).GetNanoSeconds(),
                                  spacingNs,
                                  2,
                                  "Spacing");
    }
};

/**
 * \ingroup p4sim-tests
 * Store-and-forward with SwitchRate: three 800-byte frames back to back, with
 * a pipeline that takes one packet per 10 us. A frame that waits for the
 * pipeline gets Model A and the egress delay after the wait (the MAC receive
 * delay passes during it), as PipelineDelay is added after the wait.
 */
class SwitchRateLatencyTestCase : public TestCase
{
  public:
    SwitchRateLatencyTestCase()
        : TestCase("Store-and-forward with SwitchRate: the latency follows the wait")
    {
    }

  private:
    void DoRun() override
    {
        const uint64_t RATE = 100000; // packets per second: one per 10 us
        Setup setup;
        setup.json = "latency/latency_v1model.json";
        setup.flowTable = "latency/flowtable.txt";
        setup.profile = "tofino-like";
        setup.ports = 2;
        setup.rate = "10Gbps";
        setup.switchRate = RATE;
        Network net = Build(setup);
        std::vector<Received> frames;
        RecordAll(net, &frames);
        std::vector<Time> lastBits;
        net.sw->TraceConnectWithoutContext(
            "FrameArrival",
            MakeBoundCallback(
                +[](std::vector<Time>* t, Ptr<const Packet>, uint32_t, Time, Time lastBit) {
                    t->push_back(lastBit);
                },
                &lastBits));

        const uint32_t FRAME = 800;
        const uint32_t N = 3;
        for (uint32_t k = 0; k < N; k++)
        {
            Simulator::Schedule(MilliSeconds(1), &SendUdp, net.hosts[0], FRAME);
        }
        Simulator::Stop(MilliSeconds(2));
        Simulator::Run();
        Simulator::Destroy();

        std::shared_ptr<const TargetProfile> profile = TargetProfile::Load("tofino-like");
        IngressLatencyEstimate a =
            profile->TofinoIngressLatencyNs(FRAME,
                                            10e9,
                                            {20, 8},
                                            {Table("exact", 32), Table("lpm", 32)});
        double macRxNs = profile->macRxDelay.meanNs;
        double inPipelineNs = a.TotalNs() + profile->egressDelay.meanNs;
        double wireNs = LinkFraming(LinkFraming::ETHERNET).GetWireBytes(FRAME) * 8 / 10.0;
        double serviceNs = 1e9 / RATE;

        NS_TEST_ASSERT_MSG_EQ(lastBits.size(), N, "FrameArrival");
        NS_TEST_ASSERT_MSG_EQ(frames.size(), N, "Frames lost");
        // The pipeline takes a frame at its last bit if it is idle, else when
        // it has served the previous one
        double startNs = 0;
        for (uint32_t k = 0; k < N; k++)
        {
            double lastBitNs = lastBits[k].GetNanoSeconds();
            startNs = (k == 0) ? lastBitNs : std::max(lastBitNs, startNs + serviceNs);
            double expectedNs = std::max(lastBitNs + macRxNs, startNs) + inPipelineNs + wireNs;
            NS_TEST_EXPECT_MSG_EQ_TOL(frames[k].at.GetNanoSeconds(), expectedNs, 2, "Frame " << k);
        }
    }
};

namespace
{

/// A frame sent in a Model C scenario
struct Stimulus
{
    uint32_t port;   ///< the sending host (= switch port)
    std::string dst; ///< "A", "B", "C", "D" (hosts 0 to 3) or "U" (unknown)
    uint32_t bytes;  ///< bytes after the delimiter, FCS included
    int64_t cycle;   ///< when its first preamble bit enters the switch
};

/// A frame that left the switch, in cycles from the first frame's first preamble bit
struct Output
{
    uint32_t port;    ///< the egress port
    std::string src;  ///< "A" ... "D": the host that sent it
    int64_t preamble; ///< its first preamble bit
    int64_t dmac;     ///< its first destination MAC bit
    int64_t idle;     ///< the first idle cycle after it

    bool operator<(const Output& o) const
    {
        return std::tie(port, src, preamble) < std::tie(o.port, o.src, o.preamble);
    }

    bool operator==(const Output& o) const
    {
        return port == o.port && src == o.src && preamble == o.preamble;
    }
};

/// The address of a host letter, or of the unknown destination
Mac48Address
MacOf(const std::string& who)
{
    if (who == "U")
    {
        return Mac48Address("00:00:00:00:00:99");
    }
    return HostMac(static_cast<uint32_t>(who[0] - 'A'));
}

/**
 * Run a Model C scenario on a switch with the cut-through-reference profile:
 * every host first sends a broadcast (so A, B, C, D are learned on ports 0 to
 * 3), then, from T0 = 10 ms, the stimuli
 * \return the frames that left the switch, in cycles from T0
 */
std::vector<Output>
RunScenario(uint32_t ports, const std::vector<Stimulus>& stimuli)
{
    std::shared_ptr<const TargetProfile> profile = TargetProfile::Load("cut-through-reference");
    const Time cycle = profile->clockPeriod;
    Setup setup;
    setup.json = "cut_through/l2_switch_v1model.json";
    setup.flowTable = "cut_through/flowtable_" + std::to_string(ports) + "ports.txt";
    setup.profile = "cut-through-reference";
    setup.ports = ports;
    setup.learning = true;
    Network net = Build(setup);
    std::vector<Received> frames;
    RecordAll(net, &frames);

    for (uint32_t i = 0; i < ports; i++)
    {
        Simulator::Schedule(MilliSeconds(1) + MicroSeconds(100 * i),
                            &SendFrame,
                            net.hosts[i],
                            Mac48Address::GetBroadcast(),
                            64 - FCS_BYTES);
    }
    const Time t0 = MilliSeconds(10);
    for (const Stimulus& s : stimuli)
    {
        Simulator::Schedule(t0 + cycle * s.cycle,
                            &SendFrame,
                            net.hosts[s.port],
                            MacOf(s.dst),
                            s.bytes - FCS_BYTES);
    }
    Simulator::Stop(t0 + MilliSeconds(1));
    Simulator::Run();
    Simulator::Destroy();

    DataRate rate(setup.rate);
    LinkFraming ethernet(LinkFraming::ETHERNET);
    std::vector<Output> outputs;
    for (const Received& f : frames)
    {
        if (f.at < t0)
        {
            continue; // the broadcasts that taught the addresses
        }
        Time preamble = f.at - rate.CalculateBytesTxTime(ethernet.GetWireBytes(f.bytes));
        Time dmac = preamble + rate.CalculateBytesTxTime(profile->preambleBytes);
        uint8_t mac[6];
        f.src.CopyTo(mac);
        outputs.push_back({f.port,
                           std::string(1, static_cast<char>('A' + mac[5] - 0x0a)),
                           (preamble - t0).GetTimeStep() / cycle.GetTimeStep(),
                           (dmac - t0).GetTimeStep() / cycle.GetTimeStep(),
                           (f.at - t0).GetTimeStep() / cycle.GetTimeStep()});
    }
    std::sort(outputs.begin(), outputs.end());
    return outputs;
}

/// \return the outputs as text, for messages
std::string
Describe(const std::vector<Output>& outputs)
{
    std::ostringstream text;
    for (const Output& o : outputs)
    {
        text << " [port " << o.port << ": " << o.src << " preamble +" << o.preamble << " dmac +"
             << o.dmac << " idle +" << o.idle << "]";
    }
    return outputs.empty() ? " none" : text.str();
}

} // namespace

/**
 * \ingroup p4sim-tests
 * One Model C scenario of the handoff spec: the frames that leave the switch,
 * their ports and their timing in cycles
 */
class CutThroughScenarioTestCase : public TestCase
{
  public:
    /**
     * \param id C1 ... C9
     * \param ports 3 or 4
     * \param stimuli what the hosts send
     * \param expected what leaves the switch (port, source, preamble; dmac and
     *        idle are checked where given, -1 elsewhere)
     */
    CutThroughScenarioTestCase(const std::string& id,
                               uint32_t ports,
                               const std::vector<Stimulus>& stimuli,
                               const std::vector<Output>& expected)
        : TestCase("Model C scenario " + id + ", " + std::to_string(ports) + " ports"),
          m_ports(ports),
          m_stimuli(stimuli),
          m_expected(expected)
    {
    }

  private:
    void DoRun() override
    {
        std::vector<Output> outputs = RunScenario(m_ports, m_stimuli);
        std::vector<Output> expected = m_expected;
        std::sort(expected.begin(), expected.end());
        NS_TEST_ASSERT_MSG_EQ((outputs == expected),
                              true,
                              "Expected" << Describe(expected) << ", got" << Describe(outputs));
        for (size_t i = 0; i < outputs.size(); i++)
        {
            if (expected[i].dmac >= 0)
            {
                NS_TEST_EXPECT_MSG_EQ(outputs[i].dmac, expected[i].dmac, "Destination MAC");
            }
            if (expected[i].idle >= 0)
            {
                NS_TEST_EXPECT_MSG_EQ(outputs[i].idle, expected[i].idle, "First idle cycle");
            }
        }
    }

    uint32_t m_ports;                ///< 3 or 4
    std::vector<Stimulus> m_stimuli; ///< the frames sent
    std::vector<Output> m_expected;  ///< the frames that leave the switch
};

/**
 * \ingroup p4sim-tests
 * The learning table of the cut-through reference (data plane): an entry is
 * there for the next frame; 4 entries (the profile's capacity, or the size of
 * the P4 table), a new address replaces the one refreshed least recently;
 * entries age out 300 s after their last frame
 */
class LearningLimitsTestCase : public TestCase
{
  public:
    /**
     * \param p4TableSize false: the profile cut-through-reference (capacity
     * 4); true: a copy without table_capacity
     * (p4src/cut_through/profile_table_size.json), so that the P4 table (size
     * 4) limits the learning table
     */
    explicit LearningLimitsTestCase(bool p4TableSize)
        : TestCase(std::string("Learning table: capacity (") +
                   (p4TableSize ? "the P4 table's" : "the profile's") +
                   "), replace the oldest, aging (data plane)"),
          m_p4TableSize(p4TableSize)
    {
    }

  private:
    bool m_p4TableSize; ///< see the constructor

    void DoRun() override
    {
        Setup setup;
        setup.json = "cut_through/l2_switch_v1model.json";
        setup.flowTable = "cut_through/flowtable_3ports.txt";
        setup.profile = m_p4TableSize ? GetP4TestPath() + "/cut_through/profile_table_size.json"
                                      : "cut-through-reference";
        setup.learning = true;
        Network net = Build(setup);
        P4LearningTable* table = net.sw->GetCore()->GetLearningTable();
        NS_TEST_ASSERT_MSG_EQ((table != nullptr), true, "No learning table");

        // Sources S1 ... S5 from host 0, one per millisecond; S1 again before S5
        auto source = [](int i) {
            std::ostringstream text;
            text << "00:00:00:00:01:0" << i;
            return Mac48Address(text.str().c_str());
        };
        auto key = [](Mac48Address mac) {
            uint8_t bytes[6];
            mac.CopyTo(bytes);
            return std::string(reinterpret_cast<char*>(bytes), 6);
        };
        for (int i = 1; i <= 4; i++)
        {
            Simulator::Schedule(MilliSeconds(i), &SendFrom, net.hosts[0], source(i), 60);
        }
        Simulator::Schedule(MilliSeconds(5), &SendFrom, net.hosts[0], source(1), 60);
        Simulator::Schedule(MilliSeconds(6), &SendFrom, net.hosts[0], source(5), 60);

        std::vector<std::string> params;
        bool learnedAtOnce = false;
        std::vector<bool> heldAfterEviction;
        uint32_t afterEviction = 0;
        uint32_t afterAging1 = 0;
        uint32_t afterAging2 = 0;
        uint32_t bmv2Entries = 0;
        // S1's frame has passed the switch 10 us after it was sent (60 bytes at 100 Mbps)
        Simulator::Schedule(MilliSeconds(1) + MicroSeconds(10),
                            [&]() { learnedAtOnce = table->Lookup(key(source(1)), &params); });
        Simulator::Schedule(MilliSeconds(7), [&]() {
            afterEviction = table->GetNEntries();
            for (int i = 1; i <= 5; i++)
            {
                heldAfterEviction.push_back(table->Lookup(key(source(i)), &params));
            }
            bmv2Entries = static_cast<uint32_t>(
                P4RuntimeApi(*net.sw->GetCore()).GetNumEntries("MyIngress.dmac"));
        });
        // S3 and S4 (last seen at 3 and 4 ms) have aged out at 300.0045 s,
        // S1 and S5 (5 and 6 ms) not yet; at 300.0065 s all have
        Simulator::Schedule(Seconds(300) + MicroSeconds(4500),
                            [&]() { afterAging1 = table->GetNEntries(); });
        Simulator::Schedule(Seconds(300) + MicroSeconds(6500),
                            [&]() { afterAging2 = table->GetNEntries(); });
        Simulator::Stop(Seconds(301));
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_EXPECT_MSG_EQ(learnedAtOnce, true, "S1 was not learned with its frame");
        NS_TEST_EXPECT_MSG_EQ(afterEviction, 4, "The table holds more than its capacity");
        NS_TEST_EXPECT_MSG_EQ(bmv2Entries, 4, "BMv2's table differs from the learning table");
        std::vector<bool> expected = {true, false, true, true, true};
        NS_TEST_EXPECT_MSG_EQ((heldAfterEviction == expected),
                              true,
                              "S2, refreshed least recently, should have been replaced");
        NS_TEST_EXPECT_MSG_EQ(afterAging1, 2, "Entries aged out too early or too late");
        NS_TEST_EXPECT_MSG_EQ(afterAging2, 0, "Entries did not age out");
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * The control-plane learning path (tofino-like profile): an entry is installed
 * ControlPlaneDelay after the digest, not before
 */
class ControlPlaneLearningTestCase : public TestCase
{
  public:
    ControlPlaneLearningTestCase()
        : TestCase("Learning table: control-plane path with its delay")
    {
    }

  private:
    void DoRun() override
    {
        Setup setup;
        setup.json = "cut_through/l2_switch_v1model.json";
        setup.flowTable = "cut_through/flowtable_3ports.txt";
        setup.profile = "tofino-like";
        setup.rate = "10Gbps";
        setup.learning = true;
        setup.controlPlaneDelay = MilliSeconds(1);
        Network net = Build(setup);
        P4LearningTable* table = net.sw->GetCore()->GetLearningTable();
        NS_TEST_ASSERT_MSG_EQ((table != nullptr), true, "No learning table");

        Simulator::Schedule(MilliSeconds(1),
                            &SendFrame,
                            net.hosts[0],
                            Mac48Address::GetBroadcast(),
                            60);
        uint32_t before = 0;
        uint32_t after = 0;
        Simulator::Schedule(MicroSeconds(1900), [&]() { before = table->GetNEntries(); });
        Simulator::Schedule(MicroSeconds(2100), [&]() { after = table->GetNEntries(); });
        Simulator::Stop(MilliSeconds(3));
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_EXPECT_MSG_EQ(before, 0, "Installed before the control-plane delay");
        NS_TEST_EXPECT_MSG_EQ(after, 1, "Not installed after the control-plane delay");
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * A program swap: the tables of the new program start empty, so the learning
 * table forgets its entries, and the next frame of a known address installs
 * it again, in the new program's table
 */
class LearningSwapTestCase : public TestCase
{
  public:
    LearningSwapTestCase()
        : TestCase("Learning table: a program swap empties it, and it learns again")
    {
    }

  private:
    void DoRun() override
    {
        Setup setup;
        setup.json = "cut_through/l2_switch_v1model.json";
        setup.flowTable = "cut_through/flowtable_3ports.txt";
        setup.profile = "cut-through-reference";
        setup.learning = true;
        setup.enableSwap = true;
        Network net = Build(setup);
        P4SwitchCore* core = net.sw->GetCore();
        P4LearningTable* table = core->GetLearningTable();
        NS_TEST_ASSERT_MSG_EQ((table != nullptr), true, "No learning table");

        std::ifstream file(GetP4TestPath() + "/" + setup.json);
        std::stringstream json;
        json << file.rdbuf();
        const Mac48Address source("00:00:00:00:01:01");
        auto bmv2Entries = [core]() {
            return static_cast<uint32_t>(P4RuntimeApi(*core).GetNumEntries("MyIngress.dmac"));
        };

        uint32_t learned = 0;
        uint32_t afterSwap = 0;
        uint32_t afterSwapBmv2 = 0;
        uint32_t relearned = 0;
        uint32_t relearnedBmv2 = 0;
        int loaded = -1;
        int swapped = -1;
        Simulator::Schedule(MilliSeconds(1), &SendFrom, net.hosts[0], source, 60);
        Simulator::Schedule(MilliSeconds(2), [&]() {
            learned = table->GetNEntries();
            loaded = core->load_new_config(json.str());
            swapped = core->swap_configs(); // the switch is idle: at once
            afterSwap = table->GetNEntries();
            afterSwapBmv2 = bmv2Entries();
        });
        Simulator::Schedule(MilliSeconds(3), &SendFrom, net.hosts[0], source, 60);
        Simulator::Schedule(MilliSeconds(4), [&]() {
            relearned = table->GetNEntries();
            relearnedBmv2 = bmv2Entries();
        });
        Simulator::Stop(MilliSeconds(5));
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_EXPECT_MSG_EQ(learned, 1, "The address was not learned");
        NS_TEST_EXPECT_MSG_EQ(loaded, bm::RuntimeInterface::SUCCESS, "load_new_config failed");
        NS_TEST_EXPECT_MSG_EQ(swapped, bm::RuntimeInterface::SUCCESS, "swap_configs failed");
        NS_TEST_EXPECT_MSG_EQ(afterSwapBmv2, 0, "The new program's table is not empty");
        NS_TEST_EXPECT_MSG_EQ(afterSwap, 0, "The learning table kept the old program's entries");
        NS_TEST_EXPECT_MSG_EQ(relearned, 1, "The address was not learned again");
        NS_TEST_EXPECT_MSG_EQ(relearnedBmv2, 1, "The new program's table lacks the address");
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * A profile's queue_capacity sets the size of the output queues: hosts 0 and
 * 2 each send 20 frames to host 1 at once, so port 1 queues them. With
 * queue_capacity 2 (p4src/latency/profile_queue2.json, no latency) the switch
 * delivers the same frames at the same times as with QueueBufferSize 2 and no
 * profile, and fewer than with the default queues.
 */
class QueueCapacityTestCase : public TestCase
{
  public:
    QueueCapacityTestCase()
        : TestCase("queue_capacity of a profile: the size of the output queues")
    {
    }

  private:
    /// The frames host 1 receives with \p profile and \p queueBufferSize
    static std::vector<Received> Run(const std::string& profile, uint32_t queueBufferSize)
    {
        Setup setup;
        setup.json = "latency/latency_v1model.json";
        setup.flowTable = "latency/flowtable.txt";
        setup.profile = profile;
        setup.rate = "10Gbps";
        setup.queueBufferSize = queueBufferSize;
        Network net = Build(setup);
        std::vector<Received> frames;
        RecordAll(net, &frames);
        for (uint32_t k = 0; k < 20; k++)
        {
            Simulator::Schedule(MilliSeconds(1), &SendUdp, net.hosts[0], 800);
            Simulator::Schedule(MilliSeconds(1), &SendUdp, net.hosts[2], 800);
        }
        Simulator::Stop(MilliSeconds(2));
        Simulator::Run();
        Simulator::Destroy();
        frames.erase(std::remove_if(frames.begin(),
                                    frames.end(),
                                    [](const Received& f) { return f.port != 1; }),
                     frames.end());
        return frames;
    }

    void DoRun() override
    {
        std::vector<Received> withProfile =
            Run(GetP4TestPath() + "/latency/profile_queue2.json", 0);
        std::vector<Received> withAttribute = Run("", 2);
        std::vector<Received> withDefault = Run("", 0);

        NS_TEST_EXPECT_MSG_EQ(withDefault.size(), 40, "The default queues dropped frames");
        NS_TEST_EXPECT_MSG_LT(withProfile.size(), 40, "queue_capacity 2 dropped no frame");
        NS_TEST_ASSERT_MSG_EQ(withProfile.size(),
                              withAttribute.size(),
                              "queue_capacity 2 differs from QueueBufferSize 2");
        for (size_t i = 0; i < withProfile.size(); i++)
        {
            NS_TEST_EXPECT_MSG_EQ(withProfile[i].at, withAttribute[i].at, "Frame " << i);
        }
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * The latency models of the target profiles
 */
static class P4LatencyTestSuite : public TestSuite
{
  public:
    P4LatencyTestSuite()
        : TestSuite("p4-latency", TestSuite::Type::UNIT)
    {
        const double G10 = 10e9;
        const double G100 = 100e9;
        const std::vector<ModelAVector> vectors = {
            {"A1", G10, 100, {}, {}, 176.120, 0, 0, 176.120},
            {"A2", G10, 1400, {}, {}, 484.220, 0, 0, 484.220},
            {"A3", G100, 100, {}, {}, 149.041, 0, 0, 149.041},
            {"A4", G100, 1400, {}, {}, 221.841, 0, 0, 221.841},
            {"A5",
             G10,
             800,
             {20, 8},
             Tables(3, Table("exact", 32)),
             342.020,
             11.960,
             1.803,
             355.783},
            {"A6",
             G100,
             800,
             {20, 8},
             Tables(3, Table("exact", 32)),
             188.241,
             5.802,
             2.055,
             196.098},
            {"A7",
             G10,
             300,
             {20},
             {Table("lpm", 32), Table("exact", 8)},
             223.520,
             7.306,
             1.379,
             232.205},
            {"A8",
             G100,
             1300,
             {20, 20, 8},
             Tables(10, Table("lpm", 32)),
             216.241,
             9.333,
             8.960,
             234.534},
        };
        for (const ModelAVector& vector : vectors)
        {
            AddTestCase(new ModelAVectorTestCase(vector), P4SIM_TEST_QUICK);
        }
        AddTestCase(new ModelAWarningsTestCase(), P4SIM_TEST_QUICK);
        AddTestCase(new ProgramFeaturesTestCase(), P4SIM_TEST_QUICK);
        AddTestCase(new StoreAndForwardLatencyTestCase(), P4SIM_TEST_QUICK);
        AddTestCase(new PipelineOrderTestCase(), P4SIM_TEST_QUICK);
        AddTestCase(new SwitchRateLatencyTestCase(), P4SIM_TEST_QUICK);
        AddTestCase(new QueueCapacityTestCase(), P4SIM_TEST_QUICK);

        // Model C, 3 ports unless stated: (port, destination, bytes, start cycle)
        // -> (egress port, source, preamble, destination MAC, first idle cycle)
        const int64_t X = -1; // not checked
        AddTestCase(new CutThroughScenarioTestCase("C1",
                                                   3,
                                                   {{0, "U", 64, 0}},
                                                   {{1, "A", 63, 95, 351}, {2, "A", 63, 95, 351}}),
                    P4SIM_TEST_QUICK);
        AddTestCase(new CutThroughScenarioTestCase(
                        "C1",
                        4,
                        {{0, "U", 64, 0}},
                        {{1, "A", 63, 95, 351}, {2, "A", 63, 95, 351}, {3, "A", 63, 95, 351}}),
                    P4SIM_TEST_QUICK);
        AddTestCase(
            new CutThroughScenarioTestCase("C2", 3, {{1, "A", 64, 0}}, {{0, "B", 63, X, X}}),
            P4SIM_TEST_QUICK);
        AddTestCase(new CutThroughScenarioTestCase("C3",
                                                   3,
                                                   {{0, "B", 400, 0}, {2, "B", 64, 300}},
                                                   {{1, "A", 63, X, 1695}}),
                    P4SIM_TEST_QUICK);
        AddTestCase(new CutThroughScenarioTestCase("C4",
                                                   3,
                                                   {{0, "B", 64, 0}, {2, "B", 64, 338}},
                                                   {{1, "A", 63, X, 351}}),
                    P4SIM_TEST_QUICK);
        AddTestCase(new CutThroughScenarioTestCase("C5",
                                                   3,
                                                   {{0, "B", 64, 0}, {2, "B", 64, 339}},
                                                   {{1, "A", 63, X, 351}, {1, "C", 402, X, X}}),
                    P4SIM_TEST_QUICK);
        AddTestCase(new CutThroughScenarioTestCase("C6",
                                                   3,
                                                   {{0, "B", 400, 0}, {2, "U", 64, 300}},
                                                   {{1, "A", 63, X, 1695}, {0, "C", 363, X, X}}),
                    P4SIM_TEST_QUICK);
        AddTestCase(new CutThroughScenarioTestCase(
                        "C6",
                        4,
                        {{0, "B", 400, 0}, {2, "U", 64, 300}},
                        {{1, "A", 63, X, 1695}, {0, "C", 363, X, X}, {3, "C", 363, X, X}}),
                    P4SIM_TEST_QUICK);
        AddTestCase(new CutThroughScenarioTestCase("C7",
                                                   3,
                                                   {{0, "B", 64, 0}, {2, "A", 64, 0}},
                                                   {{1, "A", 63, X, X}}),
                    P4SIM_TEST_QUICK);
        AddTestCase(new CutThroughScenarioTestCase("C8",
                                                   3,
                                                   {{0, "B", 64, 0}, {2, "A", 64, 1}},
                                                   {{1, "A", 63, X, X}, {0, "C", 64, X, X}}),
                    P4SIM_TEST_QUICK);
        AddTestCase(new CutThroughScenarioTestCase("C9", 3, {{0, "A", 64, 0}}, {}),
                    P4SIM_TEST_QUICK);

        AddTestCase(new LearningLimitsTestCase(false), P4SIM_TEST_QUICK);
        AddTestCase(new LearningLimitsTestCase(true), P4SIM_TEST_QUICK);
        AddTestCase(new ControlPlaneLearningTestCase(), P4SIM_TEST_QUICK);
        AddTestCase(new LearningSwapTestCase(), P4SIM_TEST_QUICK);
    }
} g_p4LatencyTestSuite;
