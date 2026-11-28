// SPDX-License-Identifier: Apache-2.0
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
#include "ns3/p4sim-ns3-compat.h"
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
    /// The cases of this suite
    enum Case
    {
        SCHEDULE,          ///< PfifoFastQueueDisc lets a high-priority packet overtake
        DEFAULT_QDISC,     ///< Ipv4AddressHelper installs FqCoDelQueueDisc
        NO_FLOW_CONTROL,   ///< DisableFlowControl(): no queue disc is installed
        BIG_DEVICE_QUEUE,  ///< a large device queue takes the whole burst
        BYTE_QUEUE_LIMITS, ///< byte queue limits keep the backlog in the queue disc
    };

    HostTrafficControlTestCase(Case c)
        : TestCase(Name(c)),
          m_case(c)
    {
    }

  private:
    /// The name of case \p c
    static std::string Name(Case c)
    {
        switch (c)
        {
        case SCHEDULE:
            return "A queue disc on a host schedules its packets";
        case DEFAULT_QDISC:
            return "A host gets FqCoDelQueueDisc by default";
        case NO_FLOW_CONTROL:
            return "DisableFlowControl leaves a host without a queue disc";
        case BIG_DEVICE_QUEUE:
            return "Without queue limits, a large device queue takes the whole burst";
        case BYTE_QUEUE_LIMITS:
            return "Byte queue limits keep the backlog of a host in the queue disc";
        }
        return "";
    }

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
    if (m_case == BIG_DEVICE_QUEUE || m_case == BYTE_QUEUE_LIMITS)
    {
        // Room for the whole burst: only byte queue limits stop the queue disc
        eth.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue("100p"));
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
    if (m_case == SCHEDULE || m_case == BIG_DEVICE_QUEUE || m_case == BYTE_QUEUE_LIMITS)
    {
        TrafficControlHelper tch;
        tch.SetRootQueueDisc("ns3::PfifoFastQueueDisc");
        if (m_case == BYTE_QUEUE_LIMITS)
        {
            tch.SetQueueLimits("ns3::DynamicQueueLimits");
        }
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

    // 10 low-priority packets, then a high-priority one, at once.
    // SCHEDULE: the first low-priority packet goes on the link, the next two
    // fill the device queue, which then stops the queue disc. When the device
    // queue has room again, PfifoFastQueueDisc sends the high-priority packet
    // first: it is the fourth frame.
    // BIG_DEVICE_QUEUE: the device queue takes all packets in the order they
    // come, and the high-priority packet is the last frame.
    // BYTE_QUEUE_LIMITS: DynamicQueueLimits starts with a limit of 0 bytes, so
    // the first low-priority packet already stops the queue disc. The device
    // sends it at once; when it has reported its bytes as sent, the queue disc
    // goes on with the high-priority packet: it is the second frame.
    Ptr<NetDeviceQueueInterface> ndqi = dev->GetObject<NetDeviceQueueInterface>();
    NS_TEST_ASSERT_MSG_NE(ndqi, nullptr, "The host device has no flow control");
    Ptr<QueueLimits> limits = ndqi->GetTxQueue(0)->GetQueueLimits();
    NS_TEST_EXPECT_MSG_EQ((DynamicCast<DynamicQueueLimits>(limits) != nullptr),
                          (m_case == BYTE_QUEUE_LIMITS),
                          "SetQueueLimits() did not set the limits of the device queue");
    NS_TEST_EXPECT_MSG_EQ(dev->GetQueue()->GetMaxSize(),
                          QueueSize(m_case == SCHEDULE ? "2p" : "100p"),
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
    size_t high = (m_case == SCHEDULE) ? 3 : (m_case == BIG_DEVICE_QUEUE) ? N_LOW : 1;
    for (size_t k = 0; k < frames.size(); k++)
    {
        uint32_t expected = (k == high) ? HIGH_SIZE + HEADERS : LOW_SIZE + HEADERS;
        NS_TEST_EXPECT_MSG_EQ(frames[k], expected, "Frame " << k << " on the link");
    }
}

static class SwitchedEthernetTrafficControlTestSuite : public TestSuite
{
  public:
    SwitchedEthernetTrafficControlTestSuite()
        : TestSuite("switched-ethernet-traffic-control", TestSuite::Type::UNIT)
    {
        AddTestCase(new HostTrafficControlTestCase(HostTrafficControlTestCase::SCHEDULE),
                    P4SIM_TEST_QUICK);
        AddTestCase(new HostTrafficControlTestCase(HostTrafficControlTestCase::DEFAULT_QDISC),
                    P4SIM_TEST_QUICK);
        AddTestCase(new HostTrafficControlTestCase(HostTrafficControlTestCase::NO_FLOW_CONTROL),
                    P4SIM_TEST_QUICK);
        AddTestCase(new HostTrafficControlTestCase(HostTrafficControlTestCase::BIG_DEVICE_QUEUE),
                    P4SIM_TEST_QUICK);
        AddTestCase(new HostTrafficControlTestCase(HostTrafficControlTestCase::BYTE_QUEUE_LIMITS),
                    P4SIM_TEST_QUICK);
    }
} g_switchedEthernetTrafficControlTestSuite;
