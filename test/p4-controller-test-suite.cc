// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * P4Controller on a v1model switch: flow entries, action profiles and mirroring
 * sessions. Every change is read back from the switch through the BMv2 runtime
 * API or, for mirroring sessions, the API of the P4 core. Also the commands that
 * simple_switch_CLI adds to the runtime CLI, through the "simple_switch" Thrift
 * service.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-controller.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/test.h"

#include <algorithm>
#include <cstdio>

using namespace ns3;

namespace
{

/// Test case that destroys the simulator in DoTeardown(), also after a failed assertion
class P4TestCase : public TestCase
{
  protected:
    using TestCase::TestCase;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }
};

/// An initialized v1model switch without ports. An empty \p flowTable loads none.
Ptr<P4SwitchNetDevice>
CreateV1modelSwitch(const std::string& json, const std::string& flowTable)
{
    Ptr<Node> node = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("P4SwitchArch", UintegerValue(0));
    sw->SetAttribute("JsonPath", StringValue(json));
    sw->SetAttribute("FlowTablePath", StringValue(flowTable));
    sw->SetAttribute("BmLogLevel", StringValue("off"));
    node->AddDevice(sw);
    sw->Initialize();
    return sw;
}

/// Runs simple_switch_CLI with \p commands on \p thriftPort; returns what it prints
std::string
RunSimpleSwitchCli(int thriftPort, const std::vector<std::string>& commands)
{
    std::string cmd = "printf '%s\\n'";
    for (const std::string& command : commands)
    {
        cmd += " '" + command + "'";
    }
    cmd += " | simple_switch_CLI --thrift-port " + std::to_string(thriftPort) + " 2>&1";
    std::string out;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe == nullptr)
    {
        return out;
    }
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        out += buffer;
    }
    pclose(pipe);
    return out;
}

/// Action data with a single value
bm::ActionData
OneValue(uint32_t value)
{
    bm::ActionData data;
    data.push_back_action_data(bm::Data(value));
    return data;
}

} // namespace

/**
 * \ingroup p4sim-tests
 * Flow entries: the flow table file is loaded (Thrift and simple_switch_CLI),
 * then an entry is added, modified and deleted.
 */
class P4ControllerFlowEntryTestCase : public P4TestCase
{
  public:
    P4ControllerFlowEntryTestCase()
        : P4TestCase("Flow entries: load, add, modify, delete")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        Ptr<P4SwitchNetDevice> sw =
            CreateV1modelSwitch(CreateDataDirFilename("p4src/simple_v1model/simple_v1model.json"),
                                CreateDataDirFilename("p4src/simple_v1model/flowtable_0.txt"));
        P4Controller controller;
        controller.RegisterSwitch(sw);
        const std::string table = "MyIngress.ipv4_nhop";
        NS_TEST_ASSERT_MSG_EQ(controller.GetTableEntryCount(0, table), 2, "Flow table not loaded");
        NS_TEST_ASSERT_MSG_EQ(controller.GetTableEntryCount(0, "MyIngress.arp_simple"),
                              2,
                              "Flow table not loaded");

        // Add 10.1.1.5 -> drop
        std::vector<bm::MatchKeyParam> key = {
            bm::MatchKeyParam(bm::MatchKeyParam::Type::EXACT, std::string("\x0a\x01\x01\x05", 4))};
        bm::entry_handle_t handle = 0;
        controller.AddFlowEntry(0, table, key, "MyIngress.drop", bm::ActionData(), handle);
        NS_TEST_ASSERT_MSG_EQ(controller.GetTableEntryCount(0, table), 3, "Entry not added");

        // Modify it to ipv4_forward(00:00:00:00:00:09, port 2) and read it back
        bm::ActionData forward;
        forward.push_back_action_data(bm::Data(0x9));
        forward.push_back_action_data(bm::Data(2));
        controller.ModifyFlowEntry(0, table, handle, "MyIngress.ipv4_forward", std::move(forward));
        bm::MatchTable::Entry e;
        bool found = sw->GetV1ModelCore()->mt_get_entry(0, table, handle, &e) ==
                     bm::MatchErrorCode::SUCCESS;
        NS_TEST_EXPECT_MSG_EQ(found && e.action_fn &&
                                  e.action_fn->get_name() == "MyIngress.ipv4_forward",
                              true,
                              "Action not modified");
        NS_TEST_EXPECT_MSG_EQ(found && e.action_data.size() == 2 &&
                                  e.action_data.get(1).get<uint32_t>() == 2,
                              true,
                              "Port not modified");

        controller.DeleteFlowEntry(0, table, handle);
        NS_TEST_EXPECT_MSG_EQ(controller.GetTableEntryCount(0, table), 2, "Entry not deleted");
    }
};

/**
 * \ingroup p4sim-tests
 * Action profile with a selector: members are added, modified, grouped and
 * deleted.
 */
class P4ControllerActionProfileTestCase : public P4TestCase
{
  public:
    P4ControllerActionProfileTestCase()
        : P4TestCase("Action profile: add, modify, group, delete members")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        Ptr<P4SwitchNetDevice> sw = CreateV1modelSwitch(
            CreateDataDirFilename("p4src/action_profile_v1model/action-profile.json"),
            "");
        P4Controller controller;
        controller.RegisterSwitch(sw);
        P4CoreV1model* core = sw->GetV1ModelCore();
        const std::string profile = "action_profile_1"; // has a selector, so it has groups

        bm::ActionProfile::mbr_hdl_t m1 = 0;
        bm::ActionProfile::mbr_hdl_t m2 = 0;
        controller.AddActionProfileMember(0, profile, "cIngress.foo1", OneValue(0x0a0a0a01), m1);
        controller.AddActionProfileMember(0, profile, "cIngress.foo1", OneValue(0x0a0a0a02), m2);
        NS_TEST_ASSERT_MSG_EQ(controller.GetActionProfileMembers(0, profile).size(),
                              2u,
                              "Members not added");
        NS_TEST_ASSERT_MSG_NE(m1, m2, "Both members got the same handle");

        // Modify m2 to foo2(10.10.10.3) and read it back
        controller.ModifyActionProfileMember(0, profile, m2, "cIngress.foo2", OneValue(0x0a0a0a03));
        bm::ActionProfile::Member m;
        bool found =
            core->mt_act_prof_get_member(0, profile, m2, &m) == bm::MatchErrorCode::SUCCESS;
        NS_TEST_EXPECT_MSG_EQ(found && m.action_fn && m.action_fn->get_name() == "cIngress.foo2",
                              true,
                              "Action not modified");
        NS_TEST_EXPECT_MSG_EQ(found && m.action_data.size() == 1 &&
                                  m.action_data.get(0).get<uint32_t>() == 0x0a0a0a03u,
                              true,
                              "Action data not modified");

        // Put m1 into a new group and read the group back
        bm::ActionProfile::grp_hdl_t grp = 0;
        controller.CreateActionProfileGroup(0, profile, &grp);
        controller.AddMemberToGroup(0, profile, m1, grp);
        bm::ActionProfile::Group g;
        found = core->mt_act_prof_get_group(0, profile, grp, &g) == bm::MatchErrorCode::SUCCESS;
        NS_TEST_EXPECT_MSG_EQ(found && g.mbr_handles.size() == 1 && g.mbr_handles[0] == m1,
                              true,
                              "The group should hold exactly m1");

        controller.DeleteActionProfileMember(0, profile, m2);
        NS_TEST_EXPECT_MSG_EQ(controller.GetActionProfileMembers(0, profile).size(),
                              1u,
                              "Member not deleted");
    }
};

/**
 * \ingroup p4sim-tests
 * Mirroring sessions: added to a port and to a multicast group, read, and
 * deleted, like mirroring_add, mirroring_add_mc, mirroring_get and
 * mirroring_delete of simple_switch_CLI.
 */
class P4ControllerMirroringTestCase : public P4TestCase
{
  public:
    P4ControllerMirroringTestCase()
        : P4TestCase("Mirroring sessions: add, get, delete")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        Ptr<P4SwitchNetDevice> sw =
            CreateV1modelSwitch(CreateDataDirFilename("p4src/clone/clone_v1model.json"), "");
        P4Controller controller;
        controller.RegisterSwitch(sw);
        P4CoreV1model* core = sw->GetV1ModelCore();

        // Session 5 to port 2, read back from the core
        NS_TEST_ASSERT_MSG_EQ(controller.MirroringAdd(0, 5, 2), true, "Session 5 not added");
        P4SwitchCore::MirroringSessionConfig config{};
        NS_TEST_ASSERT_MSG_EQ(core->GetMirroringSession(5, &config), true, "No session 5");
        NS_TEST_EXPECT_MSG_EQ(config.egress_port_valid && config.egress_port == 2,
                              true,
                              "Session 5 should send its clones to port 2");
        NS_TEST_EXPECT_MSG_EQ(config.mgid_valid, false, "Session 5 has no multicast group");

        // Session 6 to multicast group 3, read back with MirroringGet()
        NS_TEST_ASSERT_MSG_EQ(controller.MirroringAddMc(0, 6, 3), true, "Session 6 not added");
        config = {};
        NS_TEST_ASSERT_MSG_EQ(controller.MirroringGet(0, 6, &config), true, "No session 6");
        NS_TEST_EXPECT_MSG_EQ(config.mgid_valid && config.mgid == 3,
                              true,
                              "Session 6 should send its clones to multicast group 3");
        NS_TEST_EXPECT_MSG_EQ(config.egress_port_valid, false, "Session 6 has no port");

        // Session IDs are 0 to 32767, as in simple_switch
        NS_TEST_EXPECT_MSG_EQ(controller.MirroringAdd(0, 32768, 1), false, "Session ID too big");
        NS_TEST_EXPECT_MSG_EQ(controller.MirroringGet(0, 32768), false, "Session 32768 added");
        NS_TEST_EXPECT_MSG_EQ(controller.MirroringAdd(1, 5, 2), false, "There is no switch 1");

        // Delete session 5: session 6 stays
        NS_TEST_EXPECT_MSG_EQ(controller.MirroringDelete(0, 5), true, "Session 5 not deleted");
        NS_TEST_EXPECT_MSG_EQ(core->GetMirroringSession(5, &config), false, "Session 5 left");
        NS_TEST_EXPECT_MSG_EQ(controller.MirroringGet(0, 5), false, "Session 5 left");
        NS_TEST_EXPECT_MSG_EQ(controller.MirroringDelete(0, 5), false, "Session 5 deleted twice");
        NS_TEST_EXPECT_MSG_EQ(controller.MirroringGet(0, 6), true, "Session 6 deleted too");
    }
};

/**
 * \ingroup p4sim-tests
 * The commands that simple_switch_CLI adds to the runtime CLI, which use the
 * "simple_switch" Thrift service. The flow table file adds mirroring session 5
 * (port 2), 6 (multicast group 1) and 7, deletes 7 again, gives egress port 1
 * room for one frame and lets port 2 send 100 frames per second. Two frames that
 * the P4 program clones to session 5 show that the clones use the session and
 * that the queues follow these settings. Then simple_switch_CLI reads the
 * sessions and the time of the switch.
 */
class P4SimpleSwitchCliTestCase : public P4TestCase
{
  public:
    P4SimpleSwitchCliTestCase()
        : P4TestCase("simple_switch_CLI: mirroring sessions, queue depth and rate, time")
    {
    }

  private:
    /// Host 0 sends a frame with this EtherType into port 0 (see clone_v1model.p4)
    void Send(uint16_t etherType)
    {
        m_hosts[0]->Send(Create<Packet>(4), Mac48Address("00:00:00:00:00:01"), etherType);
    }

    /// A host received a frame from the switch: note its EtherType and the time
    bool Receive(Ptr<NetDevice> host,
                 Ptr<const Packet> packet,
                 uint16_t protocol,
                 const Address& from,
                 const Address& to,
                 NetDevice::PacketType type)
    {
        auto port = std::find(m_hosts.begin(), m_hosts.end(), host) - m_hosts.begin();
        m_received[port].emplace_back(protocol, Simulator::Now());
        return true;
    }

    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        Ptr<Node> switchNode = CreateObject<Node>();
        Ptr<Node> hostNode = CreateObject<Node>();
        Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
        sw->SetAttribute("JsonPath",
                         StringValue(CreateDataDirFilename("p4src/clone/clone_v1model.json")));
        sw->SetAttribute("FlowTablePath",
                         StringValue(CreateDataDirFilename("p4src/clone/flowtable_cli.txt")));
        sw->SetAttribute("BmLogLevel", StringValue("off"));
        switchNode->AddDevice(sw);
        for (uint32_t i = 0; i < 3; i++)
        {
            Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
            Ptr<SimpleNetDevice> port = CreateObject<SimpleNetDevice>();
            Ptr<SimpleNetDevice> host = CreateObject<SimpleNetDevice>();
            port->SetAddress(Mac48Address::Allocate());
            host->SetAddress(Mac48Address::Allocate());
            port->SetChannel(channel);
            host->SetChannel(channel);
            switchNode->AddDevice(port);
            hostNode->AddDevice(host);
            sw->AddBridgePort(port);
            host->SetPromiscReceiveCallback(
                MakeCallback(&P4SimpleSwitchCliTestCase::Receive, this));
            m_hosts.push_back(host);
        }
        sw->Initialize(); // runs simple_switch_CLI with the flow table file

        P4CoreV1model* core = sw->GetV1ModelCore();
        P4SwitchCore::MirroringSessionConfig config{};
        NS_TEST_ASSERT_MSG_EQ(core->GetMirroringSession(5, &config),
                              true,
                              "mirroring_add did not add session 5");
        NS_TEST_EXPECT_MSG_EQ(config.egress_port_valid && config.egress_port == 2 &&
                                  !config.mgid_valid,
                              true,
                              "Session 5 should send its clones to port 2");
        config = {};
        NS_TEST_ASSERT_MSG_EQ(core->GetMirroringSession(6, &config),
                              true,
                              "mirroring_add_mc did not add session 6");
        NS_TEST_EXPECT_MSG_EQ(config.mgid_valid && config.mgid == 1 && !config.egress_port_valid,
                              true,
                              "Session 6 should send its clones to multicast group 1");
        NS_TEST_EXPECT_MSG_EQ(core->GetMirroringSession(7, &config),
                              false,
                              "mirroring_delete did not delete session 7");

        // Two frames that are cloned to session 5: the originals go to port 1, the
        // clones to port 2
        Simulator::Schedule(MilliSeconds(1), &P4SimpleSwitchCliTestCase::Send, this, 0x9001);
        Simulator::Schedule(MilliSeconds(1), &P4SimpleSwitchCliTestCase::Send, this, 0x9004);
        Simulator::Stop(Seconds(1));
        Simulator::Run();

        // set_queue_depth 1 1: port 1 holds one frame, so the second original is dropped
        NS_TEST_EXPECT_MSG_EQ(m_received[1].size(), 1u, "Port 1 should send only one original");
        // set_queue_rate 100 2: port 2 sends one frame per 10 ms
        NS_TEST_EXPECT_MSG_EQ(m_received[2].size(), 2u, "Port 2 should send both clones");
        if (m_received[2].size() == 2)
        {
            NS_TEST_EXPECT_MSG_EQ(m_received[2][0].first, 0x9001, "Wrong first clone");
            NS_TEST_EXPECT_MSG_GT_OR_EQ(m_received[2][1].second - m_received[2][0].second,
                                        MilliSeconds(10),
                                        "Port 2 should send the clones 10 ms apart");
        }

        // The clock of the switch is the simulation clock: 1 s since the start
        std::string out = RunSimpleSwitchCli(sw->GetThriftPort(),
                                             {"mirroring_get 5",
                                              "mirroring_get 6",
                                              "mirroring_get 7",
                                              "get_time_elapsed",
                                              "get_time_since_epoch"});
        const std::vector<std::string> expected = {
            "RuntimeCmd: MirroringSessionConfig(port=2, mgid=None)\n",
            "RuntimeCmd: MirroringSessionConfig(port=None, mgid=1)\n",
            "RuntimeCmd: Invalid mirroring operation (SESSION_NOT_FOUND)\n",
            "RuntimeCmd: 1000000\nRuntimeCmd: 1000000\n", // the two times
        };
        for (const std::string& line : expected)
        {
            NS_TEST_EXPECT_MSG_NE(out.find(line),
                                  std::string::npos,
                                  "simple_switch_CLI should print '" << line << "':\n"
                                                                      << out);
        }
    }

    std::vector<Ptr<SimpleNetDevice>> m_hosts;           ///< one per switch port
    std::vector<std::pair<uint16_t, Time>> m_received[3]; ///< (EtherType, time) per port
};

/**
 * \ingroup p4sim-tests
 * P4Controller tests.
 */
class P4ControllerTestSuite : public TestSuite
{
  public:
    P4ControllerTestSuite()
        : TestSuite("p4-controller", UNIT)
    {
        AddTestCase(new P4ControllerFlowEntryTestCase, TestCase::QUICK);
        AddTestCase(new P4ControllerActionProfileTestCase, TestCase::QUICK);
        AddTestCase(new P4ControllerMirroringTestCase, TestCase::QUICK);
        AddTestCase(new P4SimpleSwitchCliTestCase, TestCase::QUICK);
    }
};

static P4ControllerTestSuite g_p4ControllerTestSuite; //!< Static variable for test initialization
