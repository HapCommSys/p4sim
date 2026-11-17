// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * Flow control between SwitchedEthernetHostDevice and the ns-3 traffic control
 * layer, as set up by SwitchedEthernetHelper. A host is connected to a P4
 * switch and sends UDP broadcasts; the switch drops them, the test only looks
 * at the order in which the host puts its frames on the link.
 */

#include "ns3/core-module.h"
#include "ns3/eth-net-device.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-helper.h"
#include "ns3/test.h"
#include "ns3/traffic-control-module.h"

using namespace ns3;

namespace
{

constexpr uint32_t N_LOW = 10;      ///< low-priority packets in the burst
constexpr uint32_t LOW_SIZE = 1000; ///< UDP payload of a low-priority packet
constexpr uint32_t HIGH_SIZE = 500; ///< UDP payload of the high-priority packet
constexpr uint32_t HEADERS = 42;    ///< Ethernet, IPv4 and UDP headers

/// Records the size of a frame that goes on the link
void
RecordFrame(std::vector<uint32_t>* frames, Ptr<const Packet> frame)
{
    frames->push_back(frame->GetSize());
}

/// Counts a frame that the device drops
void
CountDrop(uint32_t* drops, Ptr<const Packet> frame)
{
    (*drops)++;
}

/// A UDP socket on \p node that sends broadcasts with socket priority \p priority
Ptr<Socket>
BroadcastSocket(Ptr<Node> node, uint8_t priority)
{
    Ptr<Socket> socket = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    socket->Bind();
    socket->SetAllowBroadcast(true);
    socket->SetPriority(priority);
    return socket;
}

} // namespace

/// One host connected to a P4 switch through SwitchedEthernetHelper
class HostTrafficControlTestCase : public TestCase
{
  public:
    /// The three cases of this suite
    enum Case
    {
        SCHEDULE,     ///< PfifoFastQueueDisc lets a high-priority packet overtake
        DEFAULT_QDISC, ///< Ipv4AddressHelper installs FqCoDelQueueDisc
        NO_FLOW_CONTROL ///< DisableFlowControl(): no queue disc is installed
    };

    HostTrafficControlTestCase(Case c)
        : TestCase(c == SCHEDULE        ? "A queue disc on a host schedules its packets"
                   : c == DEFAULT_QDISC ? "A host gets FqCoDelQueueDisc by default"
                                        : "DisableFlowControl leaves a host without a queue disc"),
          m_case(c)
    {
    }

  private:
    void DoRun() override;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// The host sends N_LOW low-priority packets, then one high-priority packet
    void SendBurst();

    Case m_case;
    Ptr<Socket> m_low;
    Ptr<Socket> m_high;
};

void
HostTrafficControlTestCase::SendBurst()
{
    InetSocketAddress broadcast(Ipv4Address("10.1.1.255"), 9);
    for (uint32_t k = 0; k < N_LOW; k++)
    {
        m_low->SendTo(Create<Packet>(LOW_SIZE), 0, broadcast);
    }
    m_high->SendTo(Create<Packet>(HIGH_SIZE), 0, broadcast);
}

void
HostTrafficControlTestCase::DoRun()
{
    SetDataDir(NS_TEST_SOURCEDIR);
    Ptr<Node> switchNode = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("P4SwitchArch", UintegerValue(P4SWITCH_ARCH_V1MODEL));
    sw->SetAttribute(
        "JsonPath",
        StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_v1model.json")));
    sw->SetAttribute("FlowTablePath", StringValue(""));
    switchNode->AddDevice(sw);

    NodeContainer host(1);
    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
    if (m_case == SCHEDULE)
    {
        // A small device queue: the other packets wait in the queue disc
        eth.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue("2p"));
    }
    if (m_case == NO_FLOW_CONTROL)
    {
        eth.DisableFlowControl();
    }
    NetDeviceContainer devs = eth.Install(sw, host);
    Ptr<SwitchedEthernetHostDevice> dev = DynamicCast<SwitchedEthernetHostDevice>(devs.Get(0));
    sw->Initialize();

    InternetStackHelper internet;
    internet.Install(host);
    if (m_case == SCHEDULE)
    {
        TrafficControlHelper tch;
        tch.SetRootQueueDisc("ns3::PfifoFastQueueDisc");
        tch.Install(devs);
    }
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    ipv4.Assign(devs);

    Ptr<QueueDisc> qdisc =
        host.Get(0)->GetObject<TrafficControlLayer>()->GetRootQueueDiscOnDevice(dev);
    if (m_case == DEFAULT_QDISC)
    {
        NS_TEST_EXPECT_MSG_NE(DynamicCast<FqCoDelQueueDisc>(qdisc),
                              nullptr,
                              "The host has no FqCoDelQueueDisc");
        return;
    }
    if (m_case == NO_FLOW_CONTROL)
    {
        NS_TEST_EXPECT_MSG_EQ(dev->GetObject<NetDeviceQueueInterface>(),
                              nullptr,
                              "The host device has flow control");
        NS_TEST_EXPECT_MSG_EQ(qdisc, nullptr, "The host has a queue disc");
        return;
    }

    // SCHEDULE: 10 low-priority packets, then a high-priority one, at once.
    // The first low-priority packet goes on the link, the next two fill the
    // device queue, which then stops the queue disc. When the device queue
    // has room again, PfifoFastQueueDisc sends the high-priority packet first.
    NS_TEST_EXPECT_MSG_EQ(dev->GetQueue()->GetMaxSize(),
                          QueueSize("2p"),
                          "SetQueue() did not set the device queue");
    m_low = BroadcastSocket(host.Get(0), 0);  // band 1 of PfifoFastQueueDisc
    m_high = BroadcastSocket(host.Get(0), 6); // band 0, the first one served
    std::vector<uint32_t> frames;
    uint32_t drops = 0;
    dev->TraceConnectWithoutContext("Sniffer", MakeBoundCallback(&RecordFrame, &frames));
    dev->TraceConnectWithoutContext("MacTxDrop", MakeBoundCallback(&CountDrop, &drops));
    Simulator::Schedule(MilliSeconds(1), &HostTrafficControlTestCase::SendBurst, this);
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_EXPECT_MSG_EQ(frames.size(), N_LOW + 1, "Not every packet went on the link");
    NS_TEST_EXPECT_MSG_EQ(drops, 0, "The host device dropped packets");
    for (size_t k = 0; k < frames.size(); k++)
    {
        uint32_t expected = (k == 3) ? HIGH_SIZE + HEADERS : LOW_SIZE + HEADERS;
        NS_TEST_EXPECT_MSG_EQ(frames[k], expected, "Frame " << k << " on the link");
    }
}

static class SwitchedEthernetTrafficControlTestSuite : public TestSuite
{
  public:
    SwitchedEthernetTrafficControlTestSuite()
        : TestSuite("switched-ethernet-traffic-control", UNIT)
    {
        AddTestCase(new HostTrafficControlTestCase(HostTrafficControlTestCase::SCHEDULE),
                    TestCase::QUICK);
        AddTestCase(new HostTrafficControlTestCase(HostTrafficControlTestCase::DEFAULT_QDISC),
                    TestCase::QUICK);
        AddTestCase(new HostTrafficControlTestCase(HostTrafficControlTestCase::NO_FLOW_CONTROL),
                    TestCase::QUICK);
    }
} g_switchedEthernetTrafficControlTestSuite;
