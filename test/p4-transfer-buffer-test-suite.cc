// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * TransferBufferSize: the frames a port holds after the egress pipeline (the
 * hardware port queue). Host 0 sends into port 0, port 1 has a 1 Gbps link, so
 * the frames queue up in the switch.
 * - A congested port takes packets from the output queues while its transfer
 *   buffer has room, so the buffer holds TransferBufferSize frames; the frames
 *   still leave back to back at the line rate, and the buffer is empty at the
 *   end. v1model and PSA; with the default, 0, the buffer stays empty.
 * - Strict priority (p4src/priority): a high-priority frame overtakes the
 *   low-priority frames in the output queue, but not those in the transfer
 *   buffer, so with a buffer of n frames it leaves n frames later.
 * - The egress drops every second frame (p4src/drop), on a bridge port: a
 *   dropped packet does not free the port while it sends, so the frames wait in
 *   the transfer buffer and not in the port's device.
 */

#include "ns3/core-module.h"
#include "ns3/eth-net-device.h"
#include "ns3/network-module.h"
#include "ns3/p4-switch-core.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4sim-ns3-compat.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

#include <algorithm>
#include <cmath>
#include <sstream>

using namespace ns3;

namespace
{

constexpr uint32_t PAYLOAD = 1000; ///< bytes; with the Ethernet header a frame has 1014

/// A frame that reached the receiver
struct Arrival
{
    Time time;         ///< when it arrived
    uint16_t protocol; ///< its EtherType
    uint32_t size;     ///< its size with the Ethernet header
};

/// Records a frame, with its Ethernet header, that reached the receiver
void
Record(std::vector<Arrival>* arrivals, Ptr<const Packet> frame)
{
    EthernetHeader eth;
    frame->PeekHeader(eth);
    arrivals->push_back({Simulator::Now(), eth.GetLengthType(), frame->GetSize()});
}

/// Notes the largest length of port 1's transfer buffer
void
Sample(P4SwitchCore* core, uint32_t* maxLength)
{
    *maxLength = std::max(*maxLength, core->GetTransferBufferLength(1));
}

/// Samples port 1's transfer buffer every 100 ns from 0 to \p until
void
SampleUntil(Ptr<P4SwitchNetDevice> sw, uint32_t* maxLength, Time until)
{
    for (Time t = NanoSeconds(100); t < until; t += NanoSeconds(100))
    {
        Simulator::Schedule(t, &Sample, sw->GetCore(), maxLength);
    }
}

/// Counts the frames that the switch dropped
void
CountDrop(uint32_t* drops, Ptr<const Packet> frame)
{
    (*drops)++;
}

/// A switch whose port 0 links to a host at 10 Gbps and port 1 to a host at 1 Gbps
struct Network
{
    Ptr<P4SwitchNetDevice> sw;                ///< the switch
    Ptr<SwitchedEthernetHostDevice> sender;   ///< the host on port 0, 00:00:00:00:00:10
    Ptr<SwitchedEthernetHostDevice> receiver; ///< the host on port 1, 00:00:00:00:00:01
};

/**
 * Builds the network with switched-Ethernet ports
 * \param arch P4SwitchArch
 * \param json the P4 program
 * \param bufferSize TransferBufferSize; 0 leaves the attribute at its default
 * \param arrivals where the receiver records its frames
 */
Network
BuildNetwork(uint32_t arch,
             const std::string& json,
             uint32_t bufferSize,
             std::vector<Arrival>* arrivals)
{
    Network net;
    Ptr<Node> switchNode = CreateObject<Node>();
    net.sw = CreateObject<P4SwitchNetDevice>();
    net.sw->SetAttribute("P4SwitchArch", UintegerValue(arch));
    net.sw->SetAttribute("JsonPath", StringValue(json));
    net.sw->SetAttribute("FlowTablePath", StringValue(""));
    if (bufferSize > 0)
    {
        net.sw->SetAttribute("TransferBufferSize", UintegerValue(bufferSize));
    }
    switchNode->AddDevice(net.sw);

    const char* macs[] = {"00:00:00:00:00:10", "00:00:00:00:00:01"};
    const char* rates[] = {"10Gbps", "1Gbps"};
    for (uint32_t i = 0; i < 2; i++)
    {
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        channel->SetAttribute("DataRate", DataRateValue(DataRate(rates[i])));
        net.sw->Attach(channel);
        Ptr<Node> node = CreateObject<Node>();
        Ptr<SwitchedEthernetHostDevice> host = CreateObject<SwitchedEthernetHostDevice>();
        host->SetAddress(Mac48Address(macs[i]));
        node->AddDevice(host);
        host->Attach(channel);
        (i == 0 ? net.sender : net.receiver) = host;
    }
    net.receiver->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&Record, arrivals));
    net.sw->Initialize();
    return net;
}

/// Host \p from sends a frame of \p payload bytes with EtherType \p protocol to \p to
void
SendFrame(Ptr<SwitchedEthernetHostDevice> from, Address to, uint32_t payload, uint16_t protocol)
{
    from->Send(Create<Packet>(payload), to, protocol);
}

/// Whether the frames arrived back to back at 1 Gbps (8 ns per byte), each within 1 ns
bool
BackToBack(const std::vector<Arrival>& arrivals)
{
    for (size_t k = 1; k < arrivals.size(); k++)
    {
        double gap = (arrivals[k].time - arrivals[k - 1].time).GetNanoSeconds();
        if (std::abs(gap - 8.0 * arrivals[k].size) > 1.0)
        {
            return false;
        }
    }
    return true;
}

} // namespace

/**
 * \ingroup p4sim-tests
 * Host 0 sends 20 frames, one per microsecond, to port 1, which needs 8.1 us
 * per frame: the transfer buffer of port 1 fills up to TransferBufferSize and
 * is empty at the end, and the frames leave back to back at the line rate.
 */
class TransferBufferOccupancyTestCase : public TestCase
{
  public:
    /**
     * \param archName "v1model" or "psa"
     * \param arch P4SwitchArch
     * \param size TransferBufferSize; 0 leaves the attribute at its default
     */
    TransferBufferOccupancyTestCase(const std::string& archName, uint32_t arch, uint32_t size)
        : TestCase(archName + ": a congested port holds " + std::to_string(size) +
                   " frames in its transfer buffer" + (size == 0 ? " (default)" : "")),
          m_archName(archName),
          m_arch(arch),
          m_size(size)
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        std::vector<Arrival> arrivals;
        Network net = BuildNetwork(
            m_arch,
            CreateDataDirFilename("p4src/egress_ports/egress_ports_" + m_archName + ".json"),
            m_size,
            &arrivals);
        NS_TEST_EXPECT_MSG_EQ(net.sw->GetCore()->GetTransferBufferSize(),
                              m_size,
                              "The core has the wrong TransferBufferSize");

        const uint32_t nFrames = 20;
        for (uint32_t k = 0; k < nFrames; k++)
        {
            Simulator::Schedule(MicroSeconds(1 + k),
                                &SendFrame,
                                net.sender,
                                net.receiver->GetAddress(),
                                PAYLOAD,
                                0x88b5);
        }
        uint32_t maxLength = 0;
        SampleUntil(net.sw, &maxLength, MicroSeconds(200));
        Simulator::Stop(MilliSeconds(1));
        Simulator::Run();

        NS_TEST_EXPECT_MSG_EQ(arrivals.size(), nFrames, "Frames were lost");
        NS_TEST_EXPECT_MSG_EQ(BackToBack(arrivals),
                              true,
                              "Frames not back to back at the line rate");
        NS_TEST_EXPECT_MSG_EQ(maxLength, m_size, "Wrong number of frames in the transfer buffer");
        NS_TEST_EXPECT_MSG_EQ(net.sw->GetCore()->GetTransferBufferLength(1),
                              0,
                              "Frames left in the transfer buffer");
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    std::string m_archName; ///< "v1model" or "psa"
    uint32_t m_arch;        ///< P4SwitchArch
    uint32_t m_size;        ///< TransferBufferSize
};

/**
 * \ingroup p4sim-tests
 * Strict priority with a transfer buffer (p4src/priority, v1model). Host 0 sends
 * the low-priority frames L1 to L6 at 1 to 6 us, which queue up at port 1 (8.1 us
 * per frame), and at 20 us the high-priority frame H, while L3 is on the wire.
 * Without a transfer buffer, H leaves right after L3; with a buffer of n frames,
 * the n low-priority frames already in it leave before H.
 */
class TransferBufferPriorityTestCase : public TestCase
{
  public:
    /// \param size TransferBufferSize
    explicit TransferBufferPriorityTestCase(uint32_t size)
        : TestCase("v1model: with a transfer buffer of " + std::to_string(size) +
                   " frames, a high-priority frame leaves " + std::to_string(size) +
                   " frames later"),
          m_size(size)
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        std::vector<Arrival> arrivals;
        Network net = BuildNetwork(P4SWITCH_ARCH_V1MODEL,
                                   CreateDataDirFilename("p4src/priority/priority_v1model.json"),
                                   m_size,
                                   &arrivals);
        // Lk has k bytes more than PAYLOAD, priority 0 (EtherType 0x9000); H has
        // priority 7 (0x9007)
        for (uint32_t k = 1; k <= 6; k++)
        {
            Simulator::Schedule(MicroSeconds(k),
                                &SendFrame,
                                net.sender,
                                net.receiver->GetAddress(),
                                PAYLOAD + k,
                                0x9000);
        }
        Simulator::Schedule(MicroSeconds(20),
                            &SendFrame,
                            net.sender,
                            net.receiver->GetAddress(),
                            PAYLOAD,
                            0x9007);
        Simulator::Stop(MilliSeconds(1));
        Simulator::Run();

        std::ostringstream order;
        for (const Arrival& a : arrivals)
        {
            order << (order.tellp() > 0 ? " " : "")
                  << (a.protocol == 0x9007 ? std::string("H")
                                           : "L" + std::to_string(a.size - 14 - PAYLOAD));
        }
        std::vector<std::string> expected = {"L1", "L2", "L3", "L4", "L5", "L6"};
        expected.insert(expected.begin() + 3 + m_size, "H");
        std::ostringstream want;
        for (const std::string& label : expected)
        {
            want << (want.tellp() > 0 ? " " : "") << label;
        }
        NS_TEST_EXPECT_MSG_EQ(order.str(), want.str(), "Wrong order at the receiver");
        NS_TEST_EXPECT_MSG_EQ(BackToBack(arrivals),
                              true,
                              "Frames not back to back at the line rate");
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    uint32_t m_size; ///< TransferBufferSize
};

/**
 * \ingroup p4sim-tests
 * The egress drops packets while the port sends (p4src/drop, v1model), on a
 * bridge port at 1 Gbps (a SimpleNetDevice, whose end of transmission the switch
 * times itself). Host 0 sends 10 frames, one per microsecond, every second one to
 * 00:00:00:00:00:ee, which the egress drops. A dropped packet must not free the
 * port: the 5 other frames then wait in the transfer buffer (2 frames), not in
 * the port's device, and all of them arrive.
 */
class TransferBufferEgressDropTestCase : public TestCase
{
  public:
    TransferBufferEgressDropTestCase()
        : TestCase("v1model: a packet dropped by the egress does not free a sending port")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        Ptr<Node> switchNode = CreateObject<Node>();
        Ptr<Node> hostNode = CreateObject<Node>();
        Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
        sw->SetAttribute("P4SwitchArch", UintegerValue(P4SWITCH_ARCH_V1MODEL));
        sw->SetAttribute("JsonPath",
                         StringValue(CreateDataDirFilename("p4src/drop/drop_v1model.json")));
        sw->SetAttribute("FlowTablePath", StringValue(""));
        sw->SetAttribute("TransferBufferSize", UintegerValue(2));
        switchNode->AddDevice(sw);
        std::vector<Ptr<SimpleNetDevice>> hosts;
        for (uint32_t i = 0; i < 2; i++)
        {
            Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
            Ptr<SimpleNetDevice> port = CreateObject<SimpleNetDevice>();
            Ptr<SimpleNetDevice> host = CreateObject<SimpleNetDevice>();
            port->SetAddress(Mac48Address::Allocate());
            port->SetAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
            host->SetAddress(Mac48Address::Allocate());
            port->SetChannel(channel);
            host->SetChannel(channel);
            switchNode->AddDevice(port);
            hostNode->AddDevice(host);
            sw->AddBridgePort(port);
            hosts.push_back(host);
        }
        uint32_t received = 0;
        hosts[1]->SetPromiscReceiveCallback(MakeBoundCallback(&CountReceived, &received));
        uint32_t drops = 0;
        sw->TraceConnectWithoutContext("MacTxDrop", MakeBoundCallback(&CountDrop, &drops));
        sw->Initialize();

        const uint32_t nFrames = 10;
        for (uint32_t k = 0; k < nFrames; k++)
        {
            Mac48Address to(k % 2 == 0 ? "00:00:00:00:00:01" : "00:00:00:00:00:ee");
            Simulator::Schedule(MicroSeconds(1 + k),
                                &SendFrom,
                                hosts[0],
                                to,
                                Mac48Address("00:00:00:00:00:10"));
        }
        uint32_t maxLength = 0;
        SampleUntil(sw, &maxLength, MicroSeconds(100));
        Simulator::Stop(MilliSeconds(1));
        Simulator::Run();

        NS_TEST_EXPECT_MSG_EQ(received, nFrames / 2, "Frames were lost");
        NS_TEST_EXPECT_MSG_EQ(drops, 0, "The port refused frames");
        NS_TEST_EXPECT_MSG_EQ(maxLength, 2, "The frames did not wait in the transfer buffer");
        bm::Data value;
        NS_TEST_EXPECT_MSG_EQ(
            (sw->GetCore()->register_read(0, "MyEgress.egress_frames", 0, &value) ==
             bm::Register::RegisterErrorCode::SUCCESS),
            true,
            "Cannot read MyEgress.egress_frames");
        NS_TEST_EXPECT_MSG_EQ(value.get<uint32_t>(), nFrames, "The egress did not see every frame");
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// Host \p host sends a frame from \p from to \p to
    static void SendFrom(Ptr<SimpleNetDevice> host, Mac48Address to, Mac48Address from)
    {
        host->SendFrom(Create<Packet>(PAYLOAD), from, to, 0x88b5);
    }

    /// The receiver got a frame
    static bool CountReceived(uint32_t* received,
                              Ptr<NetDevice> device,
                              Ptr<const Packet> packet,
                              uint16_t protocol,
                              const Address& from,
                              const Address& to,
                              NetDevice::PacketType type)
    {
        (*received)++;
        return true;
    }
};

/**
 * \ingroup p4sim-tests
 * Transfer buffer tests.
 */
static class P4TransferBufferTestSuite : public TestSuite
{
  public:
    P4TransferBufferTestSuite()
        : TestSuite("p4-transfer-buffer", TestSuite::Type::UNIT)
    {
        for (uint32_t size : {0, 2})
        {
            AddTestCase(new TransferBufferOccupancyTestCase("v1model", P4SWITCH_ARCH_V1MODEL, size),
                        P4SIM_TEST_QUICK);
            AddTestCase(new TransferBufferOccupancyTestCase("psa", P4SWITCH_ARCH_PSA, size),
                        P4SIM_TEST_QUICK);
        }
        for (uint32_t size : {0, 1, 2})
        {
            AddTestCase(new TransferBufferPriorityTestCase(size), P4SIM_TEST_QUICK);
        }
        AddTestCase(new TransferBufferEgressDropTestCase(), P4SIM_TEST_QUICK);
    }
} g_p4TransferBufferTestSuite;
