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

static class P4PnaTestSuite : public TestSuite
{
  public:
    P4PnaTestSuite()
        : TestSuite("p4-pna", UNIT)
    {
        AddTestCase(new PnaForwardTestCase(), TestCase::QUICK);
    }
} g_p4PnaTestSuite;
