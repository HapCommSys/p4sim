// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * Bridge ports: a P4 switch whose ports are ordinary ns-3 devices, mixed with a
 * switched-Ethernet port. Port 0 is a 10 Gbps switched-Ethernet link to host 0,
 * port 1 a 1 Gbps CSMA link to host 1, port 2 a 2.5 Gbps P4 point-to-point
 * link to host 2. Host 0 sends one frame per microsecond, alternately to hosts
 * 1 and 2, so that both bridge ports are congested: each must then send back
 * to back at its own line rate, i.e. every frame arrives one transmission time
 * after the previous one. Then host 1 sends a frame to host 2, through the
 * switch, which checks the reception on a bridge port.
 */

#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/eth-net-device.h"
#include "ns3/network-module.h"
#include "ns3/p4-p2p-helper.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/simple-channel.h"
#include "ns3/simple-net-device.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

using namespace ns3;

namespace
{

constexpr uint32_t N_FRAMES = 20;
constexpr uint32_t PAYLOAD = 1000; ///< bytes

/// A frame as a host's PHY received it
struct Arrival
{
    Time time;
    uint32_t size; ///< bytes on the wire, headers included
};

/// Records a frame received by a host's PHY
void
RecordPhy(std::vector<Arrival>* arrivals, Ptr<const Packet> frame)
{
    arrivals->push_back({Simulator::Now(), frame->GetSize()});
}

/// Records the size of a frame a host passes up
void
RecordMac(std::vector<uint32_t>* sizes, Ptr<const Packet> packet)
{
    sizes->push_back(packet->GetSize());
}

} // namespace

/// See the file comment
class BridgePortTestCase : public TestCase
{
  public:
    BridgePortTestCase(const std::string& archName, uint32_t arch)
        : TestCase(archName + ": congested CSMA and point-to-point bridge ports send back to back"),
          m_archName(archName),
          m_arch(arch)
    {
    }

  private:
    void DoRun() override;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// Host 0 sends one frame to \p dst
    void SendFromHost0(Mac48Address dst);

    /// Host 1 sends one frame to \p dst
    void SendFromHost1(Mac48Address dst);

    std::string m_archName;
    uint32_t m_arch;
    Ptr<SwitchedEthernetHostDevice> m_host0;
    Ptr<NetDevice> m_host1; ///< CSMA
    Ptr<NetDevice> m_host2; ///< P4 point-to-point
    std::vector<Arrival> m_phy1;
    std::vector<Arrival> m_phy2;
    std::vector<uint32_t> m_mac1; ///< sizes host 1 passes up
};

void
BridgePortTestCase::SendFromHost0(Mac48Address dst)
{
    m_host0->Send(Create<Packet>(PAYLOAD), dst, 0x88b5);
}

void
BridgePortTestCase::SendFromHost1(Mac48Address dst)
{
    m_host1->Send(Create<Packet>(PAYLOAD), dst, 0x88b5);
}

void
BridgePortTestCase::DoRun()
{
    SetDataDir(NS_TEST_SOURCEDIR);
    Ptr<Node> switchNode = CreateObject<Node>();
    Ptr<Node> node0 = CreateObject<Node>();
    Ptr<Node> node1 = CreateObject<Node>();
    Ptr<Node> node2 = CreateObject<Node>();

    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("P4SwitchArch", UintegerValue(m_arch));
    sw->SetAttribute("JsonPath",
                     StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_" +
                                                       m_archName + ".json")));
    sw->SetAttribute("FlowTablePath", StringValue(""));
    switchNode->AddDevice(sw);

    // Port 0: switched Ethernet, 10 Gbps
    Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
    channel->SetAttribute("DataRate", DataRateValue(DataRate("10Gbps")));
    sw->Attach(channel);
    m_host0 = CreateObject<SwitchedEthernetHostDevice>();
    m_host0->SetAddress(Mac48Address("00:00:00:00:00:10"));
    node0->AddDevice(m_host0);
    m_host0->Attach(channel);

    // Port 1: CSMA, 1 Gbps
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("1Gbps"));
    NetDeviceContainer csmaDevs = csma.Install(NodeContainer(switchNode, node1));
    sw->AddBridgePort(csmaDevs.Get(0));
    m_host1 = csmaDevs.Get(1);
    m_host1->SetAddress(Mac48Address("00:00:00:00:00:01"));

    // Port 2: P4 point-to-point, 2.5 Gbps
    P4PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("2.5Gbps"));
    NetDeviceContainer p2pDevs = p2p.Install(switchNode, node2);
    sw->AddBridgePort(p2pDevs.Get(0));
    m_host2 = p2pDevs.Get(1);
    m_host2->SetAddress(Mac48Address("00:00:00:00:00:02"));

    m_host1->TraceConnectWithoutContext("PhyRxEnd", MakeBoundCallback(&RecordPhy, &m_phy1));
    m_host2->TraceConnectWithoutContext("PhyRxEnd", MakeBoundCallback(&RecordPhy, &m_phy2));
    m_host1->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&RecordMac, &m_mac1));
    sw->Initialize();

    NS_TEST_EXPECT_MSG_EQ(sw->GetNPorts(), 3, "The switch does not have 3 ports");
    NS_TEST_EXPECT_MSG_EQ(sw->GetPortDataRate(0), DataRate("10Gbps"), "Rate of port 0");
    NS_TEST_EXPECT_MSG_EQ(sw->GetPortDataRate(1), DataRate("1Gbps"), "Rate of the CSMA port");
    NS_TEST_EXPECT_MSG_EQ(sw->GetPortDataRate(2), DataRate("2.5Gbps"), "Rate of the P2P port");

    // One frame per microsecond, alternately to host 1 and host 2: a frame takes
    // 8.1 us on port 1 and 3.2 us on port 2, so both ports are congested
    for (uint32_t k = 0; k < N_FRAMES; k++)
    {
        Mac48Address dst((k % 2 == 0) ? "00:00:00:00:00:01" : "00:00:00:00:00:02");
        Simulator::Schedule(MicroSeconds(1 + k), &BridgePortTestCase::SendFromHost0, this, dst);
    }
    // Then host 1 sends a frame to host 2: it enters the switch on bridge port 1
    Simulator::Schedule(MilliSeconds(1),
                        &BridgePortTestCase::SendFromHost1,
                        this,
                        Mac48Address("00:00:00:00:00:02"));
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    // A CSMA device waits 96 bit times between two frames (CsmaNetDevice::Attach())
    Time csmaGap = DataRate("1Gbps").CalculateBytesTxTime(96 / 8);
    struct
    {
        const char* name;
        const std::vector<Arrival>& arrivals;
        DataRate rate;
        Time gap;
        uint32_t expected;
    } ports[] = {{"CSMA port", m_phy1, DataRate("1Gbps"), csmaGap, N_FRAMES / 2},
                 {"P2P port", m_phy2, DataRate("2.5Gbps"), Time(0), N_FRAMES / 2 + 1}};
    for (const auto& port : ports)
    {
        NS_TEST_EXPECT_MSG_EQ(port.arrivals.size(), port.expected, port.name << ": frames lost");
        for (size_t k = 1; k < port.arrivals.size() && k < N_FRAMES / 2; k++)
        {
            Time expected = port.rate.CalculateBytesTxTime(port.arrivals[k - 1].size) + port.gap;
            NS_TEST_EXPECT_MSG_EQ(port.arrivals[k].time - port.arrivals[k - 1].time,
                                  expected,
                                  port.name << ": frame " << k << " not back to back");
        }
    }
    // Host 1 gets its frames as sent: the payload with one Ethernet header and
    // trailer (MacRx shows the frame before the CSMA device removes them)
    NS_TEST_EXPECT_MSG_EQ(m_mac1.size(), N_FRAMES / 2, "Host 1 passed up the wrong number of frames");
    for (uint32_t size : m_mac1)
    {
        NS_TEST_EXPECT_MSG_EQ(size, PAYLOAD + 14 + 4, "Host 1 got a frame of the wrong size");
    }
}

/**
 * A bridge port whose device does not report the end of a transmission
 * (SimpleNetDevice has no PhyTxEnd trace): the port is free again as soon as
 * the device has taken a frame, so all frames for it leave the switch.
 */
class BridgePortNoTxEndTestCase : public TestCase
{
  public:
    BridgePortNoTxEndTestCase()
        : TestCase("v1model: a bridge port without PhyTxEnd sends every frame")
    {
    }

  private:
    void DoRun() override;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// Counts a frame that host 1 receives
    bool Receive(Ptr<NetDevice>, Ptr<const Packet>, uint16_t, const Address&)
    {
        m_received++;
        return true;
    }

    /// Host 0 sends one frame to host 1
    void Send()
    {
        m_host0->Send(Create<Packet>(PAYLOAD), Mac48Address("00:00:00:00:00:01"), 0x88b5);
    }

    Ptr<SwitchedEthernetHostDevice> m_host0;
    uint32_t m_received{0};
};

void
BridgePortNoTxEndTestCase::DoRun()
{
    SetDataDir(NS_TEST_SOURCEDIR);
    Ptr<Node> switchNode = CreateObject<Node>();
    Ptr<Node> node0 = CreateObject<Node>();
    Ptr<Node> node1 = CreateObject<Node>();

    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("JsonPath",
                     StringValue(CreateDataDirFilename(
                         "p4src/egress_ports/egress_ports_v1model.json")));
    sw->SetAttribute("FlowTablePath", StringValue(""));
    switchNode->AddDevice(sw);

    // 10 Gbps: host 0 sends a frame in 0.81 us, before its next one is due
    Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
    channel->SetAttribute("DataRate", DataRateValue(DataRate("10Gbps")));
    sw->Attach(channel);
    m_host0 = CreateObject<SwitchedEthernetHostDevice>();
    m_host0->SetAddress(Mac48Address("00:00:00:00:00:10"));
    node0->AddDevice(m_host0);
    m_host0->Attach(channel);

    Ptr<SimpleChannel> simple = CreateObject<SimpleChannel>();
    Ptr<SimpleNetDevice> port = CreateObject<SimpleNetDevice>();
    Ptr<SimpleNetDevice> host1 = CreateObject<SimpleNetDevice>();
    port->SetAddress(Mac48Address("00:00:00:00:00:20"));
    host1->SetAddress(Mac48Address("00:00:00:00:00:01"));
    port->SetChannel(simple);
    host1->SetChannel(simple);
    switchNode->AddDevice(port);
    node1->AddDevice(host1);
    sw->AddBridgePort(port);
    host1->SetReceiveCallback(MakeCallback(&BridgePortNoTxEndTestCase::Receive, this));
    sw->Initialize();

    for (uint32_t k = 0; k < 5; k++)
    {
        Simulator::Schedule(MicroSeconds(1 + k), &BridgePortNoTxEndTestCase::Send, this);
    }
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_EXPECT_MSG_EQ(m_received, 5, "Frames for the SimpleNetDevice port were lost");
}

static class P4BridgePortTestSuite : public TestSuite
{
  public:
    P4BridgePortTestSuite()
        : TestSuite("p4-bridge-port", UNIT)
    {
        AddTestCase(new BridgePortTestCase("v1model", P4SWITCH_ARCH_V1MODEL), TestCase::QUICK);
        AddTestCase(new BridgePortTestCase("psa", P4SWITCH_ARCH_PSA), TestCase::QUICK);
        AddTestCase(new BridgePortNoTxEndTestCase(), TestCase::QUICK);
    }
} g_p4BridgePortTestSuite;
