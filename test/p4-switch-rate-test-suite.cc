// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * SwitchRate: how many packets per second the P4 pipeline of a switch
 * processes. Host 0 sends frames, one per microsecond, through the switch to
 * host 1; both links run at 10 Gbps, so they never limit the switch.
 * - SwitchRate 0 (the default) adds no limit: the frames arrive as they were
 *   sent.
 * - SwitchRate R lets the pipeline take one packet per 1/R. An idle pipeline
 *   takes a packet at once, so the first frame is not held back; the others
 *   wait in the input buffer and leave one per 1/R. This holds for the default
 *   egress path, the VOQ path and PSA. A packet that finds the input buffer
 *   full is dropped and reported through MacRxDrop.
 * - An egress queue rate (SetAllEgressQueueRates()) does not hold back the
 *   first packet either.
 */

#include "ns3/core-module.h"
#include "ns3/eth-net-device.h"
#include "ns3/network-module.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

using namespace ns3;

namespace
{

constexpr uint32_t PAYLOAD = 1000;   ///< bytes; with the Ethernet header a frame has 1014
constexpr uint64_t RATE = 100000;    ///< SwitchRate or queue rate of the limited cases (pps)

/// Records the arrival time of a frame
void
Record(std::vector<Time>* arrivals, Ptr<const Packet> frame)
{
    arrivals->push_back(Simulator::Now());
}

/// Counts a dropped packet
void
Count(uint32_t* drops, Ptr<const Packet> packet)
{
    (*drops)++;
}

} // namespace

/// One switch with two 10 Gbps ports; host 0 sends frames to host 1
class SwitchRateTestCase : public TestCase
{
  public:
    /// What the case configures
    struct Config
    {
        std::string name;         ///< test case name
        std::string archName;     ///< "v1model" or "psa"
        uint32_t arch;            ///< P4SWITCH_ARCH_*
        bool voq;                 ///< EnableVoqFabric
        uint64_t switchRate;      ///< SwitchRate (pps), 0 = not set (the default, 0)
        uint64_t queueRate;       ///< SetAllEgressQueueRates() (pps), 0 = not called
        uint32_t inputBuffer;     ///< InputBufferSizeLow, 0 = default
        uint32_t frames;          ///< frames sent by host 0
        uint32_t expectArrivals;  ///< frames that reach host 1
        uint32_t expectDrops;     ///< MacRxDrop count of the switch
        Time expectGap;           ///< time between two arrivals
        bool checkFirst;          ///< check that the first frame is not held back
    };

    SwitchRateTestCase(const Config& config)
        : TestCase(config.name),
          m_config(config)
    {
    }

  private:
    void DoRun() override;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// Host 0 sends one frame to host 1
    void Send();

    Config m_config;
    Ptr<SwitchedEthernetHostDevice> m_hosts[2];
};

void
SwitchRateTestCase::Send()
{
    m_hosts[0]->Send(Create<Packet>(PAYLOAD), m_hosts[1]->GetAddress(), 0x88b5);
}

void
SwitchRateTestCase::DoRun()
{
    SetDataDir(NS_TEST_SOURCEDIR);
    Ptr<Node> switchNode = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("P4SwitchArch", UintegerValue(m_config.arch));
    sw->SetAttribute("JsonPath",
                     StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_" +
                                                       m_config.archName + ".json")));
    sw->SetAttribute("FlowTablePath", StringValue(""));
    if (m_config.switchRate > 0)
    {
        sw->SetAttribute("SwitchRate", UintegerValue(m_config.switchRate));
    }
    sw->SetAttribute("EnableVoqFabric", BooleanValue(m_config.voq));
    if (m_config.inputBuffer > 0)
    {
        sw->SetAttribute("InputBufferSizeLow", UintegerValue(m_config.inputBuffer));
    }
    switchNode->AddDevice(sw);

    // Port 0: host 0 (00:..:10); port 1: host 1 (00:..:01), where
    // egress_ports_*.p4 sends frames for 00:00:00:00:00:01
    const char* macs[] = {"00:00:00:00:00:10", "00:00:00:00:00:01"};
    for (uint32_t i = 0; i < 2; i++)
    {
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        channel->SetAttribute("DataRate", DataRateValue(DataRate("10Gbps")));
        sw->Attach(channel);
        Ptr<Node> node = CreateObject<Node>();
        m_hosts[i] = CreateObject<SwitchedEthernetHostDevice>();
        m_hosts[i]->SetAddress(Mac48Address(macs[i]));
        node->AddDevice(m_hosts[i]);
        m_hosts[i]->Attach(channel);
    }
    sw->Initialize();
    if (m_config.queueRate > 0)
    {
        sw->GetV1ModelCore()->SetAllEgressQueueRates(m_config.queueRate);
    }

    std::vector<Time> arrivals;
    uint32_t drops = 0;
    m_hosts[1]->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&Record, &arrivals));
    sw->TraceConnectWithoutContext("MacRxDrop", MakeBoundCallback(&Count, &drops));
    for (uint32_t k = 0; k < m_config.frames; k++)
    {
        Simulator::Schedule(MicroSeconds(1 + k), &SwitchRateTestCase::Send, this);
    }
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_EXPECT_MSG_EQ(arrivals.size(), m_config.expectArrivals, "Wrong number of frames");
    NS_TEST_EXPECT_MSG_EQ(drops, m_config.expectDrops, "Wrong number of MacRxDrop");
    if (arrivals.empty())
    {
        return;
    }
    if (m_config.checkFirst)
    {
        // Sent at 1 us, then one serialisation on each of the two links
        Time txTime = DataRate("10Gbps").CalculateBytesTxTime(PAYLOAD + 14);
        NS_TEST_EXPECT_MSG_EQ(arrivals[0],
                              MicroSeconds(1) + txTime + txTime,
                              "The first frame was held back");
    }
    for (size_t k = 1; k < arrivals.size(); k++)
    {
        NS_TEST_EXPECT_MSG_EQ(arrivals[k] - arrivals[k - 1],
                              m_config.expectGap,
                              "Frame " << k << ": wrong time since the previous one");
    }
}

static class P4SwitchRateTestSuite : public TestSuite
{
  public:
    P4SwitchRateTestSuite()
        : TestSuite("p4-switch-rate", UNIT)
    {
        const Time gap = Seconds(1.0 / static_cast<double>(RATE)); // 10 us
        const std::vector<SwitchRateTestCase::Config> configs = {
            {"v1model: the default SwitchRate (0) adds no limit",
             "v1model", P4SWITCH_ARCH_V1MODEL, false, 0, 0, 0, 20, 20, 0, MicroSeconds(1), true},
            {"v1model: SwitchRate limits the pipeline",
             "v1model", P4SWITCH_ARCH_V1MODEL, false, RATE, 0, 0, 20, 20, 0, gap, true},
            {"v1model: SwitchRate limits the VOQ path too",
             "v1model", P4SWITCH_ARCH_V1MODEL, true, RATE, 0, 0, 20, 20, 0, gap, false},
            {"psa: SwitchRate limits the pipeline",
             "psa", P4SWITCH_ARCH_PSA, false, RATE, 0, 0, 20, 20, 0, gap, true},
            {"v1model: a full input buffer drops packets",
             "v1model", P4SWITCH_ARCH_V1MODEL, false, RATE, 0, 2, 10, 3, 7, gap, true},
            {"v1model: an egress queue rate does not hold back the first packet",
             "v1model", P4SWITCH_ARCH_V1MODEL, false, 0, RATE, 0, 20, 20, 0, gap, true},
        };
        for (const auto& config : configs)
        {
            AddTestCase(new SwitchRateTestCase(config), TestCase::QUICK);
        }
    }
} g_p4SwitchRateTestSuite;
