// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * Egress timing on switched-Ethernet ports. Host 0 sends on a 10 Gbps link,
 * ports 1 and 2 have 1 and 2.5 Gbps links, so the frames queue up in the
 * switch. A congested port must then send back to back at its own line rate:
 * every frame arrives, one serialisation time after the previous one. This
 * also holds when two ports with different rates are congested at the same time,
 * for v1model, PSA and PNA. A frame takes 3244.8 ns on the 2.5 Gbps link:
 * each arrival is rounded to the simulator's resolution (1 ns), so it may lie up
 * to 1 ns from its exact time, but the rounding must not add up.
 */

#include "ns3/core-module.h"
#include "ns3/eth-net-device.h"
#include "ns3/network-module.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4sim-ns3-compat.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

#include <cmath>

using namespace ns3;

namespace
{

constexpr uint32_t N_FRAMES = 20;
constexpr uint32_t PAYLOAD = 1000; ///< bytes; with the Ethernet header a frame has 1014

/// Records the arrival time of a frame
void
Record(std::vector<Time>* arrivals, Ptr<const Packet> frame)
{
    arrivals->push_back(Simulator::Now());
}

/// A switch, and how many frames it dropped
struct DropState
{
    Ptr<P4SwitchNetDevice> sw; ///< the switch, disposed at its first drop
    uint32_t drops{0};         ///< frames the switch dropped
};

/// The switch dropped a frame: dispose it in the same instant. The event runs
/// before the ones that the switch schedules after the drop.
void
DisposeOnDrop(DropState* state, Ptr<const Packet> frame)
{
    if (state->drops++ == 0)
    {
        Simulator::ScheduleNow(&Object::Dispose, state->sw);
    }
}

/// Host \p host sends one frame to \p to
void
SendFrame(Ptr<SwitchedEthernetHostDevice> host, Mac48Address to)
{
    host->Send(Create<Packet>(PAYLOAD), to, 0x88b5);
}

} // namespace

/// Host 0 sends N_FRAMES frames to one port, or alternately to two ports
class EgressRateTestCase : public TestCase
{
  public:
    EgressRateTestCase(const std::string& archName, uint32_t arch, uint32_t nPorts)
        : TestCase(archName + (nPorts == 1 ? ": a congested port sends back to back"
                                           : ": two congested ports send back to back")),
          m_archName(archName),
          m_arch(arch),
          m_nPorts(nPorts)
    {
    }

  private:
    void DoRun() override;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// Host 0 sends one frame to the host on \p port
    void Send(uint32_t port);

    std::string m_archName;
    uint32_t m_arch;
    uint32_t m_nPorts;
    std::vector<Ptr<SwitchedEthernetHostDevice>> m_hosts; ///< the host on each port
    std::vector<Time> m_arrivals[3];                      ///< arrival times per host
};

void
EgressRateTestCase::Send(uint32_t port)
{
    m_hosts[0]->Send(Create<Packet>(PAYLOAD), m_hosts[port]->GetAddress(), 0x88b5);
}

void
EgressRateTestCase::DoRun()
{
    SetDataDir(NS_TEST_SOURCEDIR);
    Ptr<Node> switchNode = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("P4SwitchArch", UintegerValue(m_arch));
    sw->SetAttribute("JsonPath",
                     StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_" +
                                                       m_archName + ".json")));
    sw->SetAttribute("FlowTablePath", StringValue(""));
    // 10 ns per packet: the queue rate does not limit, the links set the pace
    sw->SetAttribute("SwitchRate", UintegerValue(100000000));
    switchNode->AddDevice(sw);

    const char* macs[] = {"00:00:00:00:00:10", "00:00:00:00:00:01", "00:00:00:00:00:02"};
    const char* rates[] = {"10Gbps", "1Gbps", "2.5Gbps"};
    for (uint32_t i = 0; i < 3; i++)
    {
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        channel->SetAttribute("DataRate", DataRateValue(DataRate(rates[i])));
        sw->Attach(channel);
        Ptr<Node> node = CreateObject<Node>();
        Ptr<SwitchedEthernetHostDevice> host = CreateObject<SwitchedEthernetHostDevice>();
        host->SetAddress(Mac48Address(macs[i]));
        node->AddDevice(host);
        host->Attach(channel);
        host->TraceConnectWithoutContext("MacRx", MakeBoundCallback(&Record, &m_arrivals[i]));
        m_hosts.push_back(host);
    }
    sw->Initialize();

    // One frame per microsecond, to one port or alternately to two: the 10 Gbps
    // link takes 0.81 us per frame, port 1 8.11 us and port 2 3.24 us
    for (uint32_t k = 0; k < N_FRAMES; k++)
    {
        uint32_t port = (m_nPorts == 1) ? 1 : 1 + k % 2;
        Simulator::Schedule(MicroSeconds(1 + k), &EgressRateTestCase::Send, this, port);
    }
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    for (uint32_t port = 1; port <= m_nPorts; port++)
    {
        // Exact serialisation time of a frame, in ns
        const double txNs =
            (PAYLOAD + 14) * 8.0 / static_cast<double>(DataRate(rates[port]).GetBitRate()) * 1e9;
        const std::vector<Time>& arrivals = m_arrivals[port];
        NS_TEST_EXPECT_MSG_EQ(arrivals.size(), N_FRAMES / m_nPorts, "Port " << port << " lost frames");
        for (size_t k = 1; k < arrivals.size(); k++)
        {
            // Frame k arrives k serialisation times after the first one
            double error = (arrivals[k] - arrivals[0]).GetNanoSeconds() - k * txNs;
            NS_TEST_EXPECT_MSG_LT_OR_EQ(std::abs(error),
                                        1.0,
                                        "Port " << port << ": frame " << k
                                                << " not back to back at the line rate");
        }
    }
}

/**
 * BMv2 stops the worker threads of a switch by pushing a sentinel into each
 * queue. ns-3 has no such threads, but the v1model destructor still pushed one
 * into an egress queue, and retried for as long as that queue was full: then
 * destroying the switch never returned.
 */
class EgressTeardownTestCase : public TestCase
{
  public:
    EgressTeardownTestCase()
        : TestCase("v1model: a switch with a full egress queue can be destroyed")
    {
    }

  private:
    void DoRun() override
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
        sw->Attach(CreateObject<SwitchedEthernetChannel>());
        sw->Initialize();

        // The queues of port 0 can hold no packet, so they are always full
        sw->GetV1ModelCore()->SetEgressQueueDepth(0, 0);

        Simulator::Run();
        // Disposes the switch, which deletes its P4 core
        Simulator::Destroy();
        NS_TEST_EXPECT_MSG_EQ((sw->GetV1ModelCore() == nullptr),
                              true,
                              "The switch was not disposed, so its destructor did not run");
    }
};

/**
 * A port that refuses a frame is freed by a PortTxComplete() in the same
 * instant. A switch destroyed in that instant must cancel this event, which
 * points to its P4 core. The switch has one port; the program sends a frame for
 * 00:00:00:00:00:01 to port 1, which does not exist, so the switch refuses it
 * and drops it, and the test disposes the switch then. Without the
 * cancellation the event runs on the deleted core: valgrind reports invalid
 * reads; a plain run may not notice.
 */
class EgressRefusedTeardownTestCase : public TestCase
{
  public:
    /**
     * Constructor
     * \param archName "v1model" or "psa"
     * \param arch P4SWITCH_ARCH_*
     */
    EgressRefusedTeardownTestCase(const std::string& archName, uint32_t arch)
        : TestCase(archName + ": a switch can be destroyed when a port refuses a frame"),
          m_archName(archName),
          m_arch(arch)
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        Ptr<Node> switchNode = CreateObject<Node>();
        Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
        sw->SetAttribute("P4SwitchArch", UintegerValue(m_arch));
        sw->SetAttribute("JsonPath",
                         StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_" +
                                                           m_archName + ".json")));
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

        DropState state{sw};
        sw->TraceConnectWithoutContext("MacTxDrop", MakeBoundCallback(&DisposeOnDrop, &state));
        Simulator::Schedule(MicroSeconds(1), &SendFrame, host, Mac48Address("00:00:00:00:00:01"));
        Simulator::Run();
        Simulator::Destroy();
        NS_TEST_EXPECT_MSG_EQ(state.drops, 1, "The switch did not refuse the frame");
    }

    std::string m_archName; ///< "v1model" or "psa"
    uint32_t m_arch;        ///< P4SWITCH_ARCH_*
};

static class P4EgressTestSuite : public TestSuite
{
  public:
    P4EgressTestSuite()
        : TestSuite("p4-egress", TestSuite::Type::UNIT)
    {
        for (uint32_t nPorts : {1, 2})
        {
            AddTestCase(new EgressRateTestCase("v1model", P4SWITCH_ARCH_V1MODEL, nPorts),
                        P4SIM_TEST_QUICK);
            AddTestCase(new EgressRateTestCase("psa", P4SWITCH_ARCH_PSA, nPorts), P4SIM_TEST_QUICK);
            AddTestCase(new EgressRateTestCase("pna", P4NIC_ARCH_PNA, nPorts), P4SIM_TEST_QUICK);
        }
        AddTestCase(new EgressTeardownTestCase(), P4SIM_TEST_QUICK);
        AddTestCase(new EgressRefusedTeardownTestCase("v1model", P4SWITCH_ARCH_V1MODEL),
                    P4SIM_TEST_QUICK);
        AddTestCase(new EgressRefusedTeardownTestCase("psa", P4SWITCH_ARCH_PSA), P4SIM_TEST_QUICK);
    }
} g_p4EgressTestSuite;
