// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * PNA on switched-Ethernet ports. Host 0 sends three frames through a PNA
 * switch: one to the host on port 1, one to the host on port 2, and one with
 * an unknown destination, for which the program does not call send_to_port().
 * The first two must arrive, and the switch must send nothing else. (A frame
 * sent back to host 0 would not show at host 0, whose MAC address does not
 * match, so the test counts the frames the switch sends.) This also checks
 * that the switch loads the JSON of a current p4c, where the loopback flag is
 * named "loopedback".
 *
 * Each port has an output queue of QueueBufferSize frames (p4-egress checks
 * that a congested port sends back to back); a frame that finds it full is
 * dropped. A switch can be destroyed in the instant a port refuses a frame.
 */

#include "ns3/core-module.h"
#include "ns3/eth-net-device.h"
#include "ns3/network-module.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

using namespace ns3;

namespace
{

/// Counts the frames a host receives
void
Count(uint32_t* frames, Ptr<const Packet> frame)
{
    (*frames)++;
}

/// \p host sends a frame with a payload of \p bytes bytes to \p to
void
SendFrame(Ptr<SwitchedEthernetHostDevice> host, Mac48Address to, uint32_t bytes)
{
    host->Send(Create<Packet>(bytes), to, 0x88b5);
}

/// The switch dropped a frame: dispose it in the same instant. The event runs
/// before the ones that the switch schedules after the drop.
void
DisposeOnDrop(Ptr<P4SwitchNetDevice> sw, uint32_t* drops, Ptr<const Packet> frame)
{
    if ((*drops)++ == 0)
    {
        Simulator::ScheduleNow(&Object::Dispose, sw);
    }
}

} // namespace

/// Host 0 sends one frame to port 1, one to port 2 and one nowhere
class PnaForwardTestCase : public TestCase
{
  public:
    PnaForwardTestCase()
        : TestCase("pna: a frame leaves on the port the program selects, otherwise it is dropped")
    {
    }

  private:
    void DoRun() override;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// Host 0 sends one frame to \p dst
    void Send(Mac48Address dst);

    std::vector<Ptr<SwitchedEthernetHostDevice>> m_hosts; ///< the host on each port
    uint32_t m_frames[3]{0, 0, 0};                        ///< frames received per host
    uint32_t m_switchTx{0};                               ///< frames the switch sends
};

void
PnaForwardTestCase::Send(Mac48Address dst)
{
    m_hosts[0]->Send(Create<Packet>(100), dst, 0x88b5);
}

void
PnaForwardTestCase::DoRun()
{
    SetDataDir(NS_TEST_SOURCEDIR);
    Ptr<Node> switchNode = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("P4SwitchArch", UintegerValue(P4NIC_ARCH_PNA));
    sw->SetAttribute(
        "JsonPath",
        StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_pna.json")));
    sw->SetAttribute("FlowTablePath", StringValue(""));
    switchNode->AddDevice(sw);

    const char* macs[] = {"00:00:00:00:00:10", "00:00:00:00:00:01", "00:00:00:00:00:02"};
    for (uint32_t i = 0; i < 3; i++)
    {
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        sw->Attach(channel);
        Ptr<Node> node = CreateObject<Node>();
        Ptr<SwitchedEthernetHostDevice> host = CreateObject<SwitchedEthernetHostDevice>();
        host->SetAddress(Mac48Address(macs[i]));
        node->AddDevice(host);
        host->Attach(channel);
        host->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&Count, &m_frames[i]));
        m_hosts.push_back(host);
    }
    sw->TraceConnectWithoutContext("MacTx", MakeBoundCallback(&Count, &m_switchTx));
    sw->Initialize();

    Simulator::Schedule(MicroSeconds(1),
                        &PnaForwardTestCase::Send,
                        this,
                        Mac48Address("00:00:00:00:00:01"));
    Simulator::Schedule(MicroSeconds(100),
                        &PnaForwardTestCase::Send,
                        this,
                        Mac48Address("00:00:00:00:00:02"));
    Simulator::Schedule(MicroSeconds(200),
                        &PnaForwardTestCase::Send,
                        this,
                        Mac48Address("00:00:00:00:00:99"));
    Simulator::Stop(MilliSeconds(1));
    Simulator::Run();

    NS_TEST_EXPECT_MSG_EQ(m_frames[1], 1, "The frame to port 1 did not arrive");
    NS_TEST_EXPECT_MSG_EQ(m_frames[2], 1, "The frame to port 2 did not arrive");
    NS_TEST_EXPECT_MSG_EQ(m_switchTx,
                          2,
                          "A frame for which the program selected no port was not dropped");
}

/**
 * Host 0 sends 20 frames, one per microsecond, on a 10 Gbps link to the host
 * on port 1, whose 1 Gbps link takes 8.112 us per frame. With QueueBufferSize
 * 4, port 1 holds 4 frames besides the one it sends; a frame that finds the
 * queue full is dropped. Frames 0 to 4, 9 and 17 arrive (with a queue of 3,
 * 6 frames would arrive; without a limit, all 20).
 */
class PnaQueueFullTestCase : public TestCase
{
  public:
    PnaQueueFullTestCase()
        : TestCase("pna: a frame that finds the output queue of its port full is dropped")
    {
    }

  private:
    void DoRun() override;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    uint32_t m_frames{0}; ///< frames the host on port 1 receives
};

void
PnaQueueFullTestCase::DoRun()
{
    SetDataDir(NS_TEST_SOURCEDIR);
    Ptr<Node> switchNode = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("P4SwitchArch", UintegerValue(P4NIC_ARCH_PNA));
    sw->SetAttribute(
        "JsonPath",
        StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_pna.json")));
    sw->SetAttribute("FlowTablePath", StringValue(""));
    sw->SetAttribute("QueueBufferSize", UintegerValue(4));
    switchNode->AddDevice(sw);

    const char* macs[] = {"00:00:00:00:00:10", "00:00:00:00:00:01"};
    const char* rates[] = {"10Gbps", "1Gbps"};
    std::vector<Ptr<SwitchedEthernetHostDevice>> hosts;
    for (uint32_t i = 0; i < 2; i++)
    {
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        channel->SetAttribute("DataRate", DataRateValue(DataRate(rates[i])));
        sw->Attach(channel);
        Ptr<Node> node = CreateObject<Node>();
        Ptr<SwitchedEthernetHostDevice> host = CreateObject<SwitchedEthernetHostDevice>();
        host->SetAddress(Mac48Address(macs[i]));
        node->AddDevice(host);
        host->Attach(channel);
        hosts.push_back(host);
    }
    hosts[1]->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&Count, &m_frames));
    sw->Initialize();

    for (uint32_t k = 0; k < 20; k++)
    {
        Simulator::Schedule(MicroSeconds(1 + k), &SendFrame, hosts[0], Mac48Address(macs[1]), 1000);
    }
    Simulator::Stop(MilliSeconds(1));
    Simulator::Run();

    NS_TEST_EXPECT_MSG_EQ(m_frames, 7, "The output queue did not hold 4 frames");
}

/**
 * A port that refuses a frame is freed by a PortTxComplete() in the same
 * instant. A switch destroyed in that instant must cancel this event, which
 * points to its PNA core. The switch has one port; the program sends a frame
 * for 00:00:00:00:00:01 to port 1, which does not exist, so the switch refuses
 * it and drops it, and the test disposes the switch then. Without the
 * cancellation the event runs on the deleted core: valgrind reports invalid
 * reads; a plain run may not notice.
 */
class PnaRefusedTeardownTestCase : public TestCase
{
  public:
    PnaRefusedTeardownTestCase()
        : TestCase("pna: a switch can be destroyed when a port refuses a frame")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        Ptr<Node> switchNode = CreateObject<Node>();
        Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
        sw->SetAttribute("P4SwitchArch", UintegerValue(P4NIC_ARCH_PNA));
        sw->SetAttribute(
            "JsonPath",
            StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_pna.json")));
        sw->SetAttribute("FlowTablePath", StringValue(""));
        switchNode->AddDevice(sw);
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        sw->Attach(channel);
        Ptr<Node> hostNode = CreateObject<Node>();
        Ptr<SwitchedEthernetHostDevice> host = CreateObject<SwitchedEthernetHostDevice>();
        host->SetAddress(Mac48Address("00:00:00:00:00:10"));
        hostNode->AddDevice(host);
        host->Attach(channel);
        sw->Initialize();

        uint32_t drops = 0;
        sw->TraceConnectWithoutContext("MacTxDrop", MakeBoundCallback(&DisposeOnDrop, sw, &drops));
        Simulator::Schedule(MicroSeconds(1),
                            &SendFrame,
                            host,
                            Mac48Address("00:00:00:00:00:01"),
                            100);
        Simulator::Run();
        Simulator::Destroy();
        NS_TEST_EXPECT_MSG_EQ(drops, 1, "The switch did not refuse the frame");
    }
};

static class P4PnaTestSuite : public TestSuite
{
  public:
    P4PnaTestSuite()
        : TestSuite("p4-pna", UNIT)
    {
        AddTestCase(new PnaForwardTestCase(), TestCase::QUICK);
        AddTestCase(new PnaQueueFullTestCase(), TestCase::QUICK);
        AddTestCase(new PnaRefusedTeardownTestCase(), TestCase::QUICK);
    }
} g_p4PnaTestSuite;
