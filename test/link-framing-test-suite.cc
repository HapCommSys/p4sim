// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * The Framing attribute of SwitchedEthernetChannel. With Ethernet framing
 * (IEEE 802.3), a frame occupies the wire for its bytes plus 8 bytes of
 * preamble and start-of-frame delimiter and a 4-byte FCS, padded up to the
 * 64-byte minimum frame; the next frame starts 12 bytes (the interframe gap)
 * later. The expected times below are computed from these numbers, not from
 * LinkFraming.
 * - Host to host: back-to-back frames of 1014 and 34 bytes at 1 Gbps, and
 *   minimum frames at 100 Gbps, which give the well-known 148.8 million frames
 *   per second. Without framing (the default) a frame takes its own bytes only.
 * - Through a switch: a congested 1 Gbps port keeps the same gaps.
 * - The P4 point-to-point device has the same Framing attribute, and a switch
 *   counts it when it estimates the time of a frame on such a bridge port.
 */

#include "ns3/core-module.h"
#include "ns3/custom-p2p-net-device.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/eth-net-device.h"
#include "ns3/link-framing.h"
#include "ns3/network-module.h"
#include "ns3/p4-p2p-channel.h"
#include "ns3/p4-p2p-helper.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

#include <algorithm>
#include <cmath>

using namespace ns3;

namespace
{

/// Records the arrival time of a frame
void
Record(std::vector<Time>* arrivals, Ptr<const Packet> frame)
{
    arrivals->push_back(Simulator::Now());
}

/// Host \p from sends a frame with \p payload bytes to \p to
void
Send(Ptr<SwitchedEthernetHostDevice> from, Address to, uint32_t payload)
{
    from->Send(Create<Packet>(payload), to, 0x88b5);
}

/// Records the arrival time of a frame at a P4 point-to-point device
bool
RecordRx(std::vector<Time>* arrivals,
         Ptr<NetDevice> device,
         Ptr<const Packet> packet,
         uint16_t protocol,
         const Address& from)
{
    arrivals->push_back(Simulator::Now());
    return true;
}

/// Device \p from sends a frame with \p payload bytes to \p to
void
SendP2p(Ptr<CustomP2PNetDevice> from, Address to, uint32_t payload)
{
    from->Send(Create<Packet>(payload), to, 0x88b5);
}

/// The bytes of an ns-3 frame with \p payload bytes on the wire, IEEE 802.3
uint32_t
EthernetWireBytes(uint32_t payload)
{
    return 8 + std::max(payload + 14, 60u) + 4;
}

/// The time \p bytes take at \p rate, in ns
double
Ns(uint32_t bytes, const std::string& rate)
{
    return bytes * 8.0 / static_cast<double>(DataRate(rate).GetBitRate()) * 1e9;
}

} // namespace

/// The bytes that LinkFraming adds, for both kinds of link
class LinkFramingBytesTestCase : public TestCase
{
  public:
    LinkFramingBytesTestCase()
        : TestCase("LinkFraming: the bytes on the wire and the gap")
    {
    }

  private:
    void DoRun() override
    {
        LinkFraming none;
        NS_TEST_EXPECT_MSG_EQ(none.GetWireBytes(34), 34, "None: the frame alone");
        NS_TEST_EXPECT_MSG_EQ(none.GetWireBytes(1514), 1514, "None: the frame alone");
        NS_TEST_EXPECT_MSG_EQ(none.GetGapBytes(), 0, "None: no gap");

        LinkFraming ethernet(LinkFraming::ETHERNET);
        NS_TEST_EXPECT_MSG_EQ(ethernet.GetWireBytes(34), 72, "A short frame is padded to 60");
        NS_TEST_EXPECT_MSG_EQ(ethernet.GetWireBytes(60), 72, "Preamble 8 + 60 + FCS 4");
        NS_TEST_EXPECT_MSG_EQ(ethernet.GetWireBytes(1514), 1526, "Preamble 8 + 1514 + FCS 4");
        NS_TEST_EXPECT_MSG_EQ(ethernet.GetGapBytes(), 12, "Interframe gap: 96 bit times");
    }
};

/// Host 0 sends back-to-back frames to host 1 over one channel
class HostFramingTestCase : public TestCase
{
  public:
    /**
     * Constructor
     * \param name the name of the case
     * \param framing the Framing attribute: "None" or "Ethernet"; empty = the default
     * \param rate the data rate of the channel
     * \param payload the payload of each frame, in bytes
     * \param frames the number of frames
     * \param framesPerSecond the expected rate of frames; 0 = not checked
     */
    HostFramingTestCase(const std::string& name,
                        const std::string& framing,
                        const std::string& rate,
                        uint32_t payload,
                        uint32_t frames,
                        double framesPerSecond)
        : TestCase(name),
          m_framing(framing),
          m_rate(rate),
          m_payload(payload),
          m_frames(frames),
          m_framesPerSecond(framesPerSecond)
    {
    }

  private:
    void DoRun() override
    {
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        channel->SetAttribute("DataRate", DataRateValue(DataRate(m_rate)));
        if (!m_framing.empty())
        {
            channel->SetAttribute("Framing", StringValue(m_framing));
        }
        Ptr<SwitchedEthernetHostDevice> hosts[2];
        for (auto& host : hosts)
        {
            Ptr<Node> node = CreateObject<Node>();
            host = CreateObject<SwitchedEthernetHostDevice>();
            host->SetAddress(Mac48Address::Allocate());
            node->AddDevice(host);
            host->Attach(channel);
        }
        std::vector<Time> arrivals;
        hosts[1]->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&Record, &arrivals));
        for (uint32_t k = 0; k < m_frames; k++)
        {
            Simulator::Schedule(MicroSeconds(1),
                                &Send,
                                hosts[0],
                                hosts[1]->GetAddress(),
                                m_payload);
        }
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(arrivals.size(), m_frames, "Frames were lost");
        bool ethernet = (m_framing == "Ethernet");
        uint32_t wire = ethernet ? EthernetWireBytes(m_payload) : m_payload + 14;
        uint32_t gap = ethernet ? 12 : 0;
        // Frame k ends one wire time after its start; it starts k (wire + gap)
        // times after the first one, which starts at 1 us
        for (size_t k = 0; k < arrivals.size(); k++)
        {
            double expected = 1000 + Ns(wire, m_rate) + k * Ns(wire + gap, m_rate);
            double error = arrivals[k].GetNanoSeconds() - expected;
            NS_TEST_EXPECT_MSG_LT_OR_EQ(std::abs(error),
                                        1.0,
                                        "Frame " << k << " arrives " << error
                                                 << " ns from its expected time");
        }
        if (m_framesPerSecond > 0)
        {
            double perSecond =
                (arrivals.size() - 1) / (arrivals.back() - arrivals.front()).GetSeconds();
            NS_TEST_EXPECT_MSG_EQ_TOL(perSecond,
                                      m_framesPerSecond,
                                      m_framesPerSecond * 0.005,
                                      "Wrong number of frames per second");
        }
    }

    std::string m_framing;    ///< the Framing attribute; empty = the default
    std::string m_rate;       ///< the data rate
    uint32_t m_payload;       ///< the payload of each frame
    uint32_t m_frames;        ///< the number of frames
    double m_framesPerSecond; ///< the expected rate of frames; 0 = not checked
};

/// A congested switch port keeps the Ethernet framing
class SwitchFramingTestCase : public TestCase
{
  public:
    SwitchFramingTestCase()
        : TestCase("v1model: a congested switch port keeps the interframe gaps")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        const uint32_t payload = 1000;
        const uint32_t frames = 20;
        Ptr<Node> switchNode = CreateObject<Node>();
        Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
        sw->SetAttribute(
            "JsonPath",
            StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_v1model.json")));
        sw->SetAttribute("FlowTablePath", StringValue(""));
        switchNode->AddDevice(sw);

        // Port 0: host 0 (00:..:10) at 10 Gbps; port 1: host 1 (00:..:01) at
        // 1 Gbps, where egress_ports_v1model.p4 sends frames for 00:..:01
        const char* macs[] = {"00:00:00:00:00:10", "00:00:00:00:00:01"};
        const std::string rates[] = {"10Gbps", "1Gbps"};
        Ptr<SwitchedEthernetHostDevice> hosts[2];
        for (uint32_t i = 0; i < 2; i++)
        {
            Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
            channel->SetAttribute("DataRate", DataRateValue(DataRate(rates[i])));
            channel->SetAttribute("Framing", StringValue("Ethernet"));
            sw->Attach(channel);
            Ptr<Node> node = CreateObject<Node>();
            hosts[i] = CreateObject<SwitchedEthernetHostDevice>();
            hosts[i]->SetAddress(Mac48Address(macs[i]));
            node->AddDevice(hosts[i]);
            hosts[i]->Attach(channel);
        }
        sw->Initialize();

        std::vector<Time> arrivals;
        hosts[1]->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&Record, &arrivals));
        // One frame per microsecond: port 1 needs 8.3 us per frame, so the
        // frames queue up in the switch and leave back to back
        for (uint32_t k = 0; k < frames; k++)
        {
            Simulator::Schedule(MicroSeconds(1 + k),
                                &Send,
                                hosts[0],
                                hosts[1]->GetAddress(),
                                payload);
        }
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(arrivals.size(), frames, "Frames were lost");
        uint32_t wire = EthernetWireBytes(payload);
        double first = 1000 + Ns(wire, "10Gbps") + Ns(wire, "1Gbps");
        for (size_t k = 0; k < arrivals.size(); k++)
        {
            double expected = first + k * Ns(wire + 12, "1Gbps");
            double error = arrivals[k].GetNanoSeconds() - expected;
            NS_TEST_EXPECT_MSG_LT_OR_EQ(std::abs(error),
                                        1.0,
                                        "Frame " << k << " arrives " << error
                                                 << " ns from its expected time");
        }
    }
};

/// Device 0 sends back-to-back frames to device 1 over a P4 point-to-point link
class P2pFramingTestCase : public TestCase
{
  public:
    /**
     * Constructor
     * \param name the name of the case
     * \param framing the Framing attribute: "None" or "Ethernet"; empty = the default
     * \param payload the payload of each frame, in bytes
     */
    P2pFramingTestCase(const std::string& name, const std::string& framing, uint32_t payload)
        : TestCase(name),
          m_framing(framing),
          m_payload(payload)
    {
    }

  private:
    void DoRun() override
    {
        const uint32_t frames = 10;
        Ptr<P4P2PChannel> channel = CreateObject<P4P2PChannel>();
        Ptr<CustomP2PNetDevice> devices[2];
        for (auto& device : devices)
        {
            Ptr<Node> node = CreateObject<Node>();
            device = CreateObject<CustomP2PNetDevice>();
            device->SetAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
            if (!m_framing.empty())
            {
                device->SetAttribute("Framing", StringValue(m_framing));
            }
            device->SetAddress(Mac48Address::Allocate());
            device->SetQueue(CreateObject<DropTailQueue<Packet>>());
            device->Attach(channel);
            node->AddDevice(device);
        }
        std::vector<Time> arrivals;
        devices[1]->SetReceiveCallback(MakeBoundCallback(&RecordRx, &arrivals));
        for (uint32_t k = 0; k < frames; k++)
        {
            Simulator::Schedule(MicroSeconds(1),
                                &SendP2p,
                                devices[0],
                                devices[1]->GetAddress(),
                                m_payload);
        }
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(arrivals.size(), frames, "Frames were lost");
        bool ethernet = (m_framing == "Ethernet");
        uint32_t wire = ethernet ? EthernetWireBytes(m_payload) : m_payload + 14;
        uint32_t gap = ethernet ? 12 : 0;
        for (size_t k = 0; k < arrivals.size(); k++)
        {
            double expected = 1000 + Ns(wire, "1Gbps") + k * Ns(wire + gap, "1Gbps");
            double error = arrivals[k].GetNanoSeconds() - expected;
            NS_TEST_EXPECT_MSG_LT_OR_EQ(std::abs(error),
                                        1.0,
                                        "Frame " << k << " arrives " << error
                                                 << " ns from its expected time");
        }
    }

    std::string m_framing; ///< the Framing attribute; empty = the default
    uint32_t m_payload;    ///< the payload of each frame
};

/// The switch's estimate of the time of a frame on a P4 point-to-point bridge port
class BridgePortEstimateTestCase : public TestCase
{
  public:
    /// \param framing the Framing attribute of the port's devices
    explicit BridgePortEstimateTestCase(const std::string& framing)
        : TestCase("v1model: the time of a frame on a P4 point-to-point bridge port, " + framing),
          m_framing(framing)
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        const uint32_t payload = 1000;
        Ptr<Node> switchNode = CreateObject<Node>();
        Ptr<Node> hostNode = CreateObject<Node>();
        Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
        sw->SetAttribute(
            "JsonPath",
            StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_v1model.json")));
        sw->SetAttribute("FlowTablePath", StringValue(""));
        switchNode->AddDevice(sw);
        P4PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("1Gbps"));
        p2p.SetDeviceAttribute("Framing", StringValue(m_framing));
        NetDeviceContainer devices = p2p.Install(switchNode, hostNode);
        sw->AddBridgePort(devices.Get(0));
        sw->Initialize();

        Ptr<Packet> frame = Create<Packet>(payload);
        EthernetHeader eth;
        eth.SetSource(Mac48Address("00:00:00:00:00:10"));
        eth.SetDestination(Mac48Address("00:00:00:00:00:02"));
        eth.SetLengthType(0x88b5);
        frame->AddHeader(eth);
        Time txTime;
        bool sent = sw->SendNs3Packet(frame, 0, 0x88b5, Mac48Address("00:00:00:00:00:02"), &txTime);
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(sent, true, "The port did not take the frame");
        uint32_t wire = (m_framing == "Ethernet") ? EthernetWireBytes(payload) : payload + 14;
        NS_TEST_EXPECT_MSG_EQ(txTime,
                              NanoSeconds(wire * 8),
                              "Wrong time for a frame of " << wire << " bytes at 1 Gbps");
    }

    std::string m_framing; ///< the Framing attribute of the port's devices
};

static class LinkFramingTestSuite : public TestSuite
{
  public:
    LinkFramingTestSuite()
        : TestSuite("link-framing", UNIT)
    {
        AddTestCase(new LinkFramingBytesTestCase, TestCase::QUICK);
        AddTestCase(
            new HostFramingTestCase("No framing (the default): a frame takes its bytes only",
                                    "",
                                    "1Gbps",
                                    1000,
                                    10,
                                    0),
            TestCase::QUICK);
        AddTestCase(new HostFramingTestCase("Ethernet, 1 Gbps: 1026 bytes per frame, 12 between",
                                            "Ethernet",
                                            "1Gbps",
                                            1000,
                                            10,
                                            0),
                    TestCase::QUICK);
        AddTestCase(new HostFramingTestCase("Ethernet, 1 Gbps: a short frame is padded to 64 bytes",
                                            "Ethernet",
                                            "1Gbps",
                                            20,
                                            10,
                                            0),
                    TestCase::QUICK);
        AddTestCase(
            new HostFramingTestCase("Ethernet, 100 Gbps: 148.8 million minimum frames per second",
                                    "Ethernet",
                                    "100Gbps",
                                    46,
                                    100,
                                    100e9 / (84 * 8)),
            TestCase::QUICK);
        AddTestCase(new SwitchFramingTestCase, TestCase::QUICK);
        AddTestCase(new P2pFramingTestCase("P4 point-to-point, no framing (the default)", "", 1000),
                    TestCase::QUICK);
        AddTestCase(new P2pFramingTestCase("P4 point-to-point, Ethernet: 1026 bytes per frame",
                                           "Ethernet",
                                           1000),
                    TestCase::QUICK);
        AddTestCase(new P2pFramingTestCase("P4 point-to-point, Ethernet: a short frame is padded",
                                           "Ethernet",
                                           20),
                    TestCase::QUICK);
        AddTestCase(new BridgePortEstimateTestCase("None"), TestCase::QUICK);
        AddTestCase(new BridgePortEstimateTestCase("Ethernet"), TestCase::QUICK);
    }
} g_linkFramingTestSuite;
