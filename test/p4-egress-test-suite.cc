// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * Egress timing on switched-Ethernet ports. Host 0 sends on a 10 Gbps link,
 * ports 1 and 2 have 1 and 2.5 Gbps links, so the frames queue up in the
 * switch. A congested port must then send back to back at its own line rate:
 * every frame arrives, one serialisation time after the previous one. This
 * also holds when two ports with different rates are congested at the same time.
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

constexpr uint32_t N_FRAMES = 20;
constexpr uint32_t PAYLOAD = 1000; ///< bytes; with the Ethernet header a frame has 1014

/// Records the arrival time of a frame
void
Record(std::vector<Time>* arrivals, Ptr<const Packet> frame)
{
    arrivals->push_back(Simulator::Now());
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
        Time txTime = DataRate(rates[port]).CalculateBytesTxTime(PAYLOAD + 14);
        const std::vector<Time>& arrivals = m_arrivals[port];
        NS_TEST_EXPECT_MSG_EQ(arrivals.size(), N_FRAMES / m_nPorts, "Port " << port << " lost frames");
        for (size_t k = 1; k < arrivals.size(); k++)
        {
            NS_TEST_EXPECT_MSG_EQ(arrivals[k] - arrivals[k - 1],
                                  txTime,
                                  "Port " << port << ": frame " << k << " not back to back");
        }
    }
}

static class P4EgressTestSuite : public TestSuite
{
  public:
    P4EgressTestSuite()
        : TestSuite("p4-egress", UNIT)
    {
        for (uint32_t nPorts : {1, 2})
        {
            AddTestCase(new EgressRateTestCase("v1model", P4SWITCH_ARCH_V1MODEL, nPorts),
                        TestCase::QUICK);
            AddTestCase(new EgressRateTestCase("psa", P4SWITCH_ARCH_PSA, nPorts),
                        TestCase::QUICK);
        }
    }
} g_p4EgressTestSuite;
