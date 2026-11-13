// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * The transmit queue of SwitchedEthernetHostDevice: two hosts on one 1 Gbps
 * channel, host 0 hands its device a burst of frames at the same time. The
 * device must queue what it cannot send at once and send it back to back, and
 * drop only what does not fit into the queue.
 */

#include "ns3/core-module.h"
#include "ns3/eth-net-device.h"
#include "ns3/network-module.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

using namespace ns3;

namespace
{

constexpr uint32_t BURST = 10;
constexpr uint32_t PAYLOAD = 1000; ///< bytes; with the Ethernet header a frame has 1014

/// Records the arrival time of a frame
void
Record(std::vector<Time>* arrivals, Ptr<const Packet> frame)
{
    arrivals->push_back(Simulator::Now());
}

/// Counts a dropped frame
void
Count(uint32_t* drops, Ptr<const Packet> frame)
{
    (*drops)++;
}

} // namespace

/// Host 0 sends BURST frames at once; queueSize 0 keeps the default queue
class HostTxQueueTestCase : public TestCase
{
  public:
    HostTxQueueTestCase(uint32_t queueSize)
        : TestCase(queueSize == 0 ? "A burst is sent back to back"
                                  : "A full queue drops what does not fit"),
          m_queueSize(queueSize)
    {
    }

  private:
    void DoRun() override;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// Host 0 hands BURST frames to its device
    void SendBurst();

    uint32_t m_queueSize;
    Ptr<SwitchedEthernetHostDevice> m_hosts[2];
};

void
HostTxQueueTestCase::SendBurst()
{
    for (uint32_t k = 0; k < BURST; k++)
    {
        m_hosts[0]->Send(Create<Packet>(PAYLOAD), m_hosts[1]->GetAddress(), 0x88b5);
    }
}

void
HostTxQueueTestCase::DoRun()
{
    Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
    channel->SetAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
    for (auto& host : m_hosts)
    {
        Ptr<Node> node = CreateObject<Node>();
        host = CreateObject<SwitchedEthernetHostDevice>();
        host->SetAddress(Mac48Address::Allocate());
        node->AddDevice(host);
        host->Attach(channel);
    }
    if (m_queueSize > 0)
    {
        m_hosts[0]->GetQueue()->SetAttribute(
            "MaxSize",
            QueueSizeValue(QueueSize(std::to_string(m_queueSize) + "p")));
    }
    std::vector<Time> arrivals;
    uint32_t drops = 0;
    m_hosts[1]->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&Record, &arrivals));
    m_hosts[0]->TraceConnectWithoutContext("MacTxDrop", MakeBoundCallback(&Count, &drops));

    Simulator::Schedule(MicroSeconds(1), &HostTxQueueTestCase::SendBurst, this);
    Simulator::Run();

    // The first frame goes on the wire at once, the queue holds the next ones
    uint32_t sent = (m_queueSize == 0) ? BURST : 1 + m_queueSize;
    NS_TEST_EXPECT_MSG_EQ(arrivals.size(), sent, "Wrong number of frames received");
    NS_TEST_EXPECT_MSG_EQ(drops, BURST - sent, "Wrong number of frames dropped");
    Time txTime = DataRate("1Gbps").CalculateBytesTxTime(PAYLOAD + 14);
    for (size_t k = 1; k < arrivals.size(); k++)
    {
        NS_TEST_EXPECT_MSG_EQ(arrivals[k] - arrivals[k - 1],
                              txTime,
                              "Frame " << k << " not sent back to back");
    }
}

static class SwitchedEthernetHostTestSuite : public TestSuite
{
  public:
    SwitchedEthernetHostTestSuite()
        : TestSuite("switched-ethernet-host", UNIT)
    {
        AddTestCase(new HostTxQueueTestCase(0), TestCase::QUICK);
        AddTestCase(new HostTxQueueTestCase(5), TestCase::QUICK);
    }
} g_switchedEthernetHostTestSuite;
