// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * PipelineDelay: the time a packet spends in the P4 pipeline of a switch
 * (v1model, PSA and the pipeline core). Host 0 sends frames, one per
 * microsecond, through the switch to host 1. Each case runs twice, without and
 * with the delay.
 * - With the delay, every frame arrives exactly PipelineDelay later, and the
 *   frames keep their spacing: the pipeline takes the next packet while the
 *   previous one is still in it, so the delay adds latency but does not lower
 *   the throughput. This holds for the default egress path, the VOQ path and
 *   PSA, together with SwitchRate, and on a congested port, whose frames still
 *   leave back to back at its line rate.
 * - A switch with packets in its pipeline can be destroyed: the packets are
 *   freed with it, and none of them leaves it afterwards.
 */

#include "ns3/core-module.h"
#include "ns3/eth-net-device.h"
#include "ns3/network-module.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

#include <algorithm>

using namespace ns3;

namespace
{

constexpr uint32_t PAYLOAD = 1000; ///< bytes; with the Ethernet header a frame has 1014

/// Records the arrival time of a frame
void
Record(std::vector<Time>* arrivals, Ptr<const Packet> frame)
{
    arrivals->push_back(Simulator::Now());
}

/// Host \p from sends one frame to \p to
void
Send(Ptr<SwitchedEthernetHostDevice> from, Address to)
{
    from->Send(Create<Packet>(PAYLOAD), to, 0x88b5);
}

/// A switch with two ports: host 0 on port 0, host 1 on port 1
struct Network
{
    Ptr<P4SwitchNetDevice> sw;                ///< the switch
    Ptr<SwitchedEthernetHostDevice> hosts[2]; ///< the hosts
};

/// What a case configures
struct Scenario
{
    std::string archName;   ///< "v1model", "psa" or "pipeline"
    uint32_t arch;          ///< P4SWITCH_ARCH_*
    bool voq;               ///< EnableVoqFabric
    uint64_t switchRate;    ///< SwitchRate (pps), 0 = no limit
    std::string egressRate; ///< data rate of the link of port 1 (port 0: 10 Gbps)
    uint32_t frames;        ///< frames sent by host 0, one per microsecond
};

/**
 * The P4 program of a scenario
 * \param s the scenario
 * \return the JSON file, relative to the test folder; the pipeline core runs
 *         the v1model program
 */
std::string
JsonFile(const Scenario& s)
{
    const std::string program = (s.arch == P4SWITCH_ARCH_PIPELINE) ? "v1model" : s.archName;
    return "p4src/egress_ports/egress_ports_" + program + ".json";
}

/**
 * Build the switch and its two hosts
 * \param s the scenario
 * \param json the P4 program
 * \param delay the PipelineDelay of the switch
 * \return the network
 */
Network
Build(const Scenario& s, const std::string& json, Time delay)
{
    Network net;
    Ptr<Node> switchNode = CreateObject<Node>();
    net.sw = CreateObject<P4SwitchNetDevice>();
    net.sw->SetAttribute("P4SwitchArch", UintegerValue(s.arch));
    net.sw->SetAttribute("JsonPath", StringValue(json));
    net.sw->SetAttribute("FlowTablePath", StringValue(""));
    net.sw->SetAttribute("SwitchRate", UintegerValue(s.switchRate));
    net.sw->SetAttribute("EnableVoqFabric", BooleanValue(s.voq));
    net.sw->SetAttribute("PipelineDelay", TimeValue(delay));
    switchNode->AddDevice(net.sw);

    // Port 0: host 0 (00:..:10); port 1: host 1 (00:..:01), where
    // egress_ports_*.p4 sends frames for 00:00:00:00:00:01
    const char* macs[] = {"00:00:00:00:00:10", "00:00:00:00:00:01"};
    const std::string rates[] = {"10Gbps", s.egressRate};
    for (uint32_t i = 0; i < 2; i++)
    {
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        channel->SetAttribute("DataRate", DataRateValue(DataRate(rates[i])));
        net.sw->Attach(channel);
        Ptr<Node> node = CreateObject<Node>();
        net.hosts[i] = CreateObject<SwitchedEthernetHostDevice>();
        net.hosts[i]->SetAddress(Mac48Address(macs[i]));
        node->AddDevice(net.hosts[i]);
        net.hosts[i]->Attach(channel);
    }
    net.sw->Initialize();
    return net;
}

} // namespace

/// Every frame is delayed by exactly PipelineDelay, and the frames keep their spacing
class PipelineDelayTestCase : public TestCase
{
  public:
    /**
     * Constructor
     * \param name the name of the case
     * \param scenario the scenario
     * \param delay the PipelineDelay of the second run
     * \param firstArrival when the first frame arrives without the delay; 0 = not checked
     */
    PipelineDelayTestCase(const std::string& name,
                          const Scenario& scenario,
                          Time delay,
                          Time firstArrival)
        : TestCase(name),
          m_scenario(scenario),
          m_delay(delay),
          m_firstArrival(firstArrival)
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        std::vector<Time> without = Run(Time(0));
        std::vector<Time> with = Run(m_delay);

        NS_TEST_ASSERT_MSG_EQ(without.size(), m_scenario.frames, "Frames lost without the delay");
        NS_TEST_ASSERT_MSG_EQ(with.size(), m_scenario.frames, "Frames lost with the delay");
        // The test runner may continue after a failed assert: read only frames that arrived
        if (!m_firstArrival.IsZero() && !without.empty())
        {
            NS_TEST_EXPECT_MSG_EQ(without[0], m_firstArrival, "Wrong arrival without the delay");
        }
        for (size_t k = 0; k < std::min(with.size(), without.size()); k++)
        {
            NS_TEST_EXPECT_MSG_EQ(with[k] - without[k],
                                  m_delay,
                                  "Frame " << k << " was not delayed by exactly PipelineDelay");
        }
    }

    /// Host 0 sends the frames; return when they arrive at host 1
    std::vector<Time> Run(Time delay)
    {
        Network net = Build(m_scenario, CreateDataDirFilename(JsonFile(m_scenario)), delay);
        std::vector<Time> arrivals;
        net.hosts[1]->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&Record, &arrivals));
        for (uint32_t k = 0; k < m_scenario.frames; k++)
        {
            Simulator::Schedule(MicroSeconds(1 + k),
                                &Send,
                                net.hosts[0],
                                net.hosts[1]->GetAddress());
        }
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
        Simulator::Destroy();
        return arrivals;
    }

    Scenario m_scenario; ///< the scenario
    Time m_delay;        ///< the PipelineDelay of the second run
    Time m_firstArrival; ///< the first arrival without the delay; 0 = not checked
};

/// A switch with packets in its pipeline can be destroyed
class PipelineDelayTeardownTestCase : public TestCase
{
  public:
    PipelineDelayTeardownTestCase()
        : TestCase("v1model: a switch with packets in its pipeline can be destroyed")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        const Scenario s{"v1model", P4SWITCH_ARCH_V1MODEL, false, 0, "10Gbps", 5};
        Network net = Build(s,
                            CreateDataDirFilename("p4src/egress_ports/egress_ports_v1model.json"),
                            MilliSeconds(1));
        std::vector<Time> arrivals;
        net.hosts[1]->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&Record, &arrivals));
        for (uint32_t k = 0; k < s.frames; k++)
        {
            Simulator::Schedule(MicroSeconds(1 + k),
                                &Send,
                                net.hosts[0],
                                net.hosts[1]->GetAddress());
        }

        // At 100 us the switch has received the frames; they stay in its
        // pipeline until 1 ms
        Simulator::Stop(MicroSeconds(100));
        Simulator::Run();
        NS_TEST_ASSERT_MSG_EQ(arrivals.size(), 0u, "Frames left the pipeline too early");

        // Dispose the switch, which deletes its P4 core, and run past 1 ms
        net.sw->Dispose();
        NS_TEST_ASSERT_MSG_EQ((net.sw->GetV1ModelCore() == nullptr),
                              true,
                              "The P4 core was not deleted");
        Simulator::Stop(MilliSeconds(2));
        Simulator::Run();
        NS_TEST_EXPECT_MSG_EQ(arrivals.size(), 0u, "Frames left a destroyed switch");
        Simulator::Destroy();
    }
};

static class P4PipelineDelayTestSuite : public TestSuite
{
  public:
    P4PipelineDelayTestSuite()
        : TestSuite("p4-pipeline-delay", UNIT)
    {
        // Sent at 1 us, then one serialisation on each of the two 10 Gbps links
        const Time txTime = DataRate("10Gbps").CalculateBytesTxTime(PAYLOAD + 14);
        const Time first = MicroSeconds(1) + txTime + txTime;
        const Time delay = MicroSeconds(5); // longer than the 1 us between two frames

        AddTestCase(
            new PipelineDelayTestCase("v1model: every frame arrives PipelineDelay later",
                                      {"v1model", P4SWITCH_ARCH_V1MODEL, false, 0, "10Gbps", 20},
                                      delay,
                                      first),
            TestCase::QUICK);
        AddTestCase(
            new PipelineDelayTestCase("v1model: the VOQ path is delayed the same way",
                                      {"v1model", P4SWITCH_ARCH_V1MODEL, true, 0, "10Gbps", 20},
                                      delay,
                                      Time(0)),
            TestCase::QUICK);
        AddTestCase(new PipelineDelayTestCase("psa: every frame arrives PipelineDelay later",
                                              {"psa", P4SWITCH_ARCH_PSA, false, 0, "10Gbps", 20},
                                              delay,
                                              first),
                    TestCase::QUICK);
        AddTestCase(
            new PipelineDelayTestCase("pipeline: every frame arrives PipelineDelay later",
                                      {"pipeline", P4SWITCH_ARCH_PIPELINE, false, 0, "10Gbps", 20},
                                      delay,
                                      first),
            TestCase::QUICK);
        AddTestCase(new PipelineDelayTestCase(
                        "v1model: with SwitchRate, the frames keep its spacing",
                        {"v1model", P4SWITCH_ARCH_V1MODEL, false, 100000, "10Gbps", 20},
                        delay,
                        first),
                    TestCase::QUICK);
        // Port 1 runs at 1 Gbps: its frames queue up and leave back to back every
        // 8.1 us. A delay longer than that shows that the pipeline does not hold
        // one packet at a time.
        AddTestCase(
            new PipelineDelayTestCase("v1model: a congested port still sends back to back",
                                      {"v1model", P4SWITCH_ARCH_V1MODEL, false, 0, "1Gbps", 10},
                                      MicroSeconds(20),
                                      Time(0)),
            TestCase::QUICK);
        AddTestCase(new PipelineDelayTeardownTestCase, TestCase::QUICK);
    }
} g_p4PipelineDelayTestSuite;
