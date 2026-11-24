// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * Digests: digest() in a P4 program gives a record to the Digest trace of the
 * switch, and P4Controller passes it to its digest callback. The program is
 * p4src/l2_learning, the program of the example p4-l2-learning: a frame from an
 * unknown source address sends a digest (source MAC, ingress port), and a frame
 * to an unknown address is flooded. Three hosts are on switched-Ethernet ports
 * 0 to 2.
 */

#include "ns3/core-module.h"
#include "ns3/eth-net-device.h"
#include "ns3/network-module.h"
#include "ns3/p4-controller.h"
#include "ns3/p4-runtime-api.h"
#include "ns3/p4-switch-core.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4sim-ns3-compat.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

#include <fstream>
#include <set>
#include <sstream>

using namespace ns3;

namespace
{

constexpr uint32_t N_HOSTS = 3;

/// The MAC address of host \p i, which is on port i
Mac48Address
HostMac(uint32_t i)
{
    return Mac48Address(("00:00:00:00:00:0" + std::to_string(i + 1)).c_str());
}

/// The 6 bytes of \p mac
std::string
MacBytes(Mac48Address mac)
{
    uint8_t bytes[6];
    mac.CopyTo(bytes);
    return std::string(reinterpret_cast<const char*>(bytes), 6);
}

/// A digest record and when it came
struct Record
{
    Time time;
    P4Digest digest;
};

/// A switch with a host on each of its three switched-Ethernet ports; it records
/// the digests of the switch, when the switch received each frame, and the
/// frames each host received
class DigestTestCase : public TestCase
{
  protected:
    using TestCase::TestCase;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// Creates the switch with p4src/<program>/<program>_v1model.json
    void CreateSwitch(const std::string& program, uint32_t arch, bool enableSwap = false)
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        Ptr<Node> switchNode = CreateObject<Node>();
        Ptr<Node> hostNode = CreateObject<Node>();
        m_sw = CreateObject<P4SwitchNetDevice>();
        m_sw->SetAttribute("P4SwitchArch", UintegerValue(arch));
        m_sw->SetAttribute("JsonPath", StringValue(Json(program)));
        m_sw->SetAttribute("FlowTablePath", StringValue(""));
        m_sw->SetAttribute("EnableSwap", BooleanValue(enableSwap));
        switchNode->AddDevice(m_sw);
        for (uint32_t i = 0; i < N_HOSTS; i++)
        {
            Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
            m_sw->Attach(channel);
            Ptr<SwitchedEthernetHostDevice> host = CreateObject<SwitchedEthernetHostDevice>();
            host->SetAddress(HostMac(i));
            hostNode->AddDevice(host);
            host->Attach(channel);
            host->SetReceiveCallback(MakeCallback(&DigestTestCase::Receive, this).Bind(i));
            m_hosts.push_back(host);
        }
        m_sw->TraceConnectWithoutContext("Digest",
                                         MakeCallback(&DigestTestCase::RecordDigest, this));
        m_sw->TraceConnectWithoutContext("MacRx",
                                         MakeCallback(&DigestTestCase::RecordArrival, this));
        m_sw->Initialize();
    }

    /// The path of p4src/<program>/<program>_v1model.json
    std::string Json(const std::string& program)
    {
        return CreateDataDirFilename("p4src/" + program + "/" + program + "_v1model.json");
    }

    /// Multicast group 1 has every port (the flood of p4src/l2_learning)
    void CreateFloodGroup()
    {
        auto pre = m_sw->GetCore()->get_component<bm::McSimplePreLAG>();
        bm::McSimplePre::PortMap ports;
        for (uint32_t i = 0; i < N_HOSTS; i++)
        {
            ports[i] = true;
        }
        bm::McSimplePre::mgrp_hdl_t group = 0;
        bm::McSimplePre::l1_hdl_t node = 0;
        bool ok = pre->mc_mgrp_create(1, &group) == bm::McSimplePre::SUCCESS &&
                  pre->mc_node_create(0, ports, {}, &node) == bm::McSimplePre::SUCCESS &&
                  pre->mc_node_associate(group, node) == bm::McSimplePre::SUCCESS;
        NS_TEST_ASSERT_MSG_EQ(ok, true, "Cannot create the flood group");
    }

    /// Host \p from sends a frame to \p to at \p when
    void Send(Time when, uint32_t from, Mac48Address to, uint16_t etherType = 0x88b5)
    {
        Simulator::Schedule(when, [host = m_hosts[from], to, etherType]() {
            host->Send(Create<Packet>(46), to, etherType);
        });
    }

    Ptr<P4SwitchNetDevice> m_sw;
    std::vector<Ptr<SwitchedEthernetHostDevice>> m_hosts;
    std::vector<Record> m_digests;                 ///< the digests of the switch
    std::vector<Time> m_arrivals;                  ///< when the switch received each frame
    std::vector<Mac48Address> m_received[N_HOSTS]; ///< the sources of each host's frames

  private:
    void RecordDigest(const P4Digest& digest)
    {
        m_digests.push_back({Simulator::Now(), digest});
    }

    void RecordArrival(Ptr<const Packet>)
    {
        m_arrivals.push_back(Simulator::Now());
    }

    bool Receive(uint32_t host, Ptr<NetDevice>, Ptr<const Packet>, uint16_t, const Address& from)
    {
        m_received[host].push_back(Mac48Address::ConvertFrom(from));
        return true;
    }
};

/**
 * \ingroup p4sim-tests
 * Without a controller nothing is learned, so each frame sends a digest: one
 * record per digest(), at the time the switch received the frame, with the
 * fields of the learn list (p4c copies them into temporaries).
 */
class DigestRecordTestCase : public DigestTestCase
{
  public:
    DigestRecordTestCase(const std::string& archName, uint32_t arch)
        : DigestTestCase(archName + ": each digest() gives a record with its fields, at once"),
          m_arch(arch)
    {
    }

  private:
    void DoRun() override
    {
        CreateSwitch("l2_learning", m_arch);
        Send(MilliSeconds(1), 1, HostMac(0));
        Send(MilliSeconds(2), 1, HostMac(0)); // the same frame again: a second record
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();

        NS_TEST_EXPECT_MSG_EQ(m_digests.size(), 2u, "Each frame should give one digest");
        NS_TEST_EXPECT_MSG_EQ(m_arrivals.size(), 2u, "The switch should receive two frames");
        for (size_t k = 0; k < std::min(m_digests.size(), m_arrivals.size()); k++)
        {
            const P4Digest& d = m_digests[k].digest;
            NS_TEST_EXPECT_MSG_EQ(m_digests[k].time, m_arrivals[k], "Digest " << k << ": time");
            NS_TEST_EXPECT_MSG_EQ(d.listId, 1u, "Digest " << k << ": list ID");
            NS_TEST_EXPECT_MSG_EQ(d.listName, "learn_t", "Digest " << k << ": list name");
            NS_TEST_EXPECT_MSG_EQ(d.fields.size(), 2u, "Digest " << k << ": two fields");
            if (d.fields.size() != 2) // the test goes on after a failed check
            {
                continue;
            }
            NS_TEST_EXPECT_MSG_EQ(d.fields[0].name, "scalars.tmp", "Digest " << k);
            NS_TEST_EXPECT_MSG_EQ(d.fields[0].bitwidth, 48u, "Digest " << k);
            NS_TEST_EXPECT_MSG_EQ((d.fields[0].value == MacBytes(HostMac(1))),
                                  true,
                                  "Digest " << k << ": the source MAC of host 1");
            NS_TEST_EXPECT_MSG_EQ(d.fields[1].name, "scalars.tmp_0", "Digest " << k);
            NS_TEST_EXPECT_MSG_EQ(d.fields[1].bitwidth, 9u, "Digest " << k);
            NS_TEST_EXPECT_MSG_EQ(d.fields[1].GetUint64(), 1u, "Digest " << k << ": port 1");
        }
    }

    uint32_t m_arch;
};

/**
 * \ingroup p4sim-tests
 * L2 learning with P4Controller: host 0 sends a broadcast, host 1 answers host
 * 0, and host 0 sends to host 1. The controller learns hosts 0 and 1 from their
 * first frames, so only the broadcast is flooded, and host 2 gets nothing else.
 */
class DigestLearningTestCase : public DigestTestCase
{
  public:
    DigestLearningTestCase()
        : DigestTestCase("P4Controller learns from the digests: learned hosts are not flooded")
    {
    }

  private:
    /// The digest callback: learn_t {source MAC, ingress port}
    void Learn(uint32_t sw, const P4Digest& digest)
    {
        m_callbacks++;
        if (digest.fields.size() != 2 || !m_known.insert(digest.fields[0].value).second)
        {
            return;
        }
        std::vector<bm::MatchKeyParam> key = {
            bm::MatchKeyParam(bm::MatchKeyParam::Type::EXACT, digest.fields[0].value)};
        bm::entry_handle_t handle = 0;
        m_controller->AddFlowEntry(sw, "MyIngress.smac", key, "MyIngress.known", {}, handle);
        bm::ActionData toPort;
        toPort.push_back_action_data(bm::Data(digest.fields[1].GetUint64()));
        m_controller->AddFlowEntry(sw,
                                   "MyIngress.dmac",
                                   key,
                                   "MyIngress.forward",
                                   std::move(toPort),
                                   handle);
    }

    void DoRun() override
    {
        CreateSwitch("l2_learning", P4SWITCH_ARCH_V1MODEL);
        CreateFloodGroup();
        m_controller = CreateObject<P4Controller>();
        m_controller->RegisterSwitch(m_sw);
        m_controller->SetDigestCallback(MakeCallback(&DigestLearningTestCase::Learn, this));

        Send(MilliSeconds(1), 0, Mac48Address::GetBroadcast());
        Send(MilliSeconds(2), 1, HostMac(0));
        Send(MilliSeconds(3), 0, HostMac(1));
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();

        NS_TEST_EXPECT_MSG_EQ(m_callbacks, 2u, "Hosts 0 and 1 should send one digest each");
        NS_TEST_EXPECT_MSG_EQ(m_digests.size(), 2u, "The trace should see the same digests");
        NS_TEST_EXPECT_MSG_EQ(m_received[0].size(), 1u, "Host 0 should get the frame of host 1");
        NS_TEST_EXPECT_MSG_EQ(m_received[1].size(), 2u, "Host 1 should get two frames");
        NS_TEST_EXPECT_MSG_EQ(m_received[2].size(), 1u, "Host 2 should get the broadcast only");
        bm::MatchTableAbstract::counter_value_t bytes = 0;
        bm::MatchTableAbstract::counter_value_t flooded = 0;
        P4RuntimeApi(*m_sw->GetCore()).ReadCounter("MyIngress.flooded", 0, &bytes, &flooded);
        NS_TEST_EXPECT_MSG_EQ(flooded, 1u, "Only the broadcast should be flooded");
        m_controller = nullptr;
    }

    Ptr<P4Controller> m_controller;
    uint32_t m_callbacks{0};       ///< digests the callback got
    std::set<std::string> m_known; ///< the learned addresses
};

/**
 * \ingroup p4sim-tests
 * After a swap, the records follow the learn lists of the new program: first
 * p4src/l2_learning (learn_t with two fields), then p4src/primitives (learn_t
 * with one field, for an EtherType whose low 4 bits are 1).
 */
class DigestSwapTestCase : public DigestTestCase
{
  public:
    DigestSwapTestCase()
        : DigestTestCase("After a program swap, the records follow the new program")
    {
    }

  private:
    void DoRun() override
    {
        CreateSwitch("l2_learning", P4SWITCH_ARCH_V1MODEL, true);
        std::ifstream in(Json("primitives"));
        std::stringstream json;
        json << in.rdbuf();
        Send(MilliSeconds(1), 1, HostMac(0));
        Simulator::Schedule(MilliSeconds(2), [this, program = json.str()]() {
            P4RuntimeApi api(*m_sw->GetCore());
            NS_TEST_EXPECT_MSG_EQ(api.LoadNewConfig(program), 0, "Cannot load the new program");
            NS_TEST_EXPECT_MSG_EQ(api.SwapConfigs(), 0, "Cannot swap");
        });
        Send(MilliSeconds(3), 1, HostMac(0), 0x88b1);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();

        NS_TEST_EXPECT_MSG_EQ(m_digests.size(), 2u, "One digest per program");
        if (m_digests.size() != 2) // the test goes on after a failed check
        {
            return;
        }
        NS_TEST_EXPECT_MSG_EQ(m_digests[0].digest.fields.size(), 2u, "l2_learning: two fields");
        NS_TEST_EXPECT_MSG_EQ(m_digests[1].digest.fields.size(), 1u, "primitives: one field");
        if (m_digests[1].digest.fields.size() == 1)
        {
            NS_TEST_EXPECT_MSG_EQ((m_digests[1].digest.fields[0].value == MacBytes(HostMac(1))),
                                  true,
                                  "primitives: the source MAC of host 1");
        }
    }
};

} // namespace

/**
 * \ingroup p4sim-tests
 * Digests: the Digest trace of the switch and the digest callback of P4Controller.
 */
static class P4DigestTestSuite : public TestSuite
{
  public:
    P4DigestTestSuite()
        : TestSuite("p4-digest", TestSuite::Type::UNIT)
    {
        AddTestCase(new DigestRecordTestCase("v1model", P4SWITCH_ARCH_V1MODEL), P4SIM_TEST_QUICK);
        AddTestCase(new DigestRecordTestCase("pipeline", P4SWITCH_ARCH_PIPELINE), P4SIM_TEST_QUICK);
        AddTestCase(new DigestLearningTestCase, P4SIM_TEST_QUICK);
        AddTestCase(new DigestSwapTestCase, P4SIM_TEST_QUICK);
    }
} g_p4DigestTestSuite; //!< Static variable for test initialization
