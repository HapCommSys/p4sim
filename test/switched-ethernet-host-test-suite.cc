// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * The transmit queue of SwitchedEthernetHostDevice: two hosts on one 1 Gbps
 * channel, host 0 hands its device a burst of frames at the same time. The
 * device must queue what it cannot send at once and send it back to back, and
 * drop only what does not fit into the queue. When the link of host 0 is
 * detached, its device drops the frames and reports them: through MacTxDrop
 * before a frame is sent, through PhyTxDrop for the frame being sent.
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

/// Records the size of a dropped frame
void
RecordSize(std::vector<uint32_t>* sizes, Ptr<const Packet> frame)
{
    sizes->push_back(frame->GetSize());
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

/// The link of host 0 is detached before a burst, and during the first frame of
/// another burst; then it is attached again
class HostDetachTestCase : public TestCase
{
  public:
    HostDetachTestCase()
        : TestCase("Frames on a detached link are dropped and counted")
    {
    }

  private:
    void DoRun() override;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// Host 0 hands \p n frames to its device
    void Send(uint32_t n);

    Ptr<SwitchedEthernetHostDevice> m_hosts[2];
};

void
HostDetachTestCase::Send(uint32_t n)
{
    for (uint32_t k = 0; k < n; k++)
    {
        m_hosts[0]->Send(Create<Packet>(PAYLOAD), m_hosts[1]->GetAddress(), 0x88b5);
    }
}

void
HostDetachTestCase::DoRun()
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
    const uint32_t slot = 0; // host 0 was attached first
    std::vector<Time> arrivals;
    uint32_t macDrops = 0;
    std::vector<uint32_t> phyDrops;
    m_hosts[1]->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&Record, &arrivals));
    m_hosts[0]->TraceConnectWithoutContext("MacTxDrop", MakeBoundCallback(&Count, &macDrops));
    m_hosts[0]->TraceConnectWithoutContext("PhyTxDrop",
                                           MakeBoundCallback(&RecordSize, &phyDrops));

    // 1) Detached: a burst of 3 frames is dropped (MacTxDrop)
    Simulator::Schedule(MicroSeconds(1), [channel]() { channel->Detach(slot); });
    Simulator::Schedule(MicroSeconds(2), &HostDetachTestCase::Send, this, 3);
    // 2) Attached, then detached 2 us into the first frame of a burst of 3: the
    //    first frame is lost (PhyTxDrop), the other two are dropped (MacTxDrop)
    Simulator::Schedule(MicroSeconds(50), [channel]() { channel->Reattach(slot); });
    Simulator::Schedule(MicroSeconds(60), &HostDetachTestCase::Send, this, 3);
    Simulator::Schedule(MicroSeconds(62), [channel]() { channel->Detach(slot); });
    // 3) Attached again: a burst of 2 frames arrives, back to back
    Simulator::Schedule(MicroSeconds(100), [channel]() { channel->Reattach(slot); });
    Simulator::Schedule(MicroSeconds(110), &HostDetachTestCase::Send, this, 2);
    Simulator::Run();

    NS_TEST_EXPECT_MSG_EQ(macDrops, 5, "Wrong number of frames dropped before sending");
    NS_TEST_EXPECT_MSG_EQ(phyDrops.size(), 1, "Wrong number of frames lost while sending");
    if (!phyDrops.empty())
    {
        NS_TEST_EXPECT_MSG_EQ(phyDrops[0], PAYLOAD + 14, "PhyTxDrop reported the wrong frame");
    }
    NS_TEST_EXPECT_MSG_EQ(arrivals.size(), 2, "Wrong number of frames received");
    if (arrivals.size() == 2)
    {
        NS_TEST_EXPECT_MSG_EQ(arrivals[1] - arrivals[0],
                              DataRate("1Gbps").CalculateBytesTxTime(PAYLOAD + 14),
                              "The last burst was not sent back to back");
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
        AddTestCase(new HostDetachTestCase(), TestCase::QUICK);
    }
} g_switchedEthernetHostTestSuite;
