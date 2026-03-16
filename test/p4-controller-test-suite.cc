/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-controller.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-topology-reader-helper.h"
#include "ns3/format-utils.h"
#include "ns3/test.h"

using namespace ns3;

class P4ControllerCheckFlowEntryTestCase : public TestCase {
public:
  P4ControllerCheckFlowEntryTestCase();

  virtual ~P4ControllerCheckFlowEntryTestCase();

private:
  void DoRun() override;
};
class P4ControllerActionProfileTestCase : public TestCase {
public:
  P4ControllerActionProfileTestCase();
  virtual ~P4ControllerActionProfileTestCase();

private:
  void DoRun() override;
};

P4ControllerCheckFlowEntryTestCase::P4ControllerCheckFlowEntryTestCase()
    : TestCase("P4 controller add flow entry test case (does nothing)") {}
P4ControllerActionProfileTestCase::P4ControllerActionProfileTestCase()
    : TestCase("P4 controller action profile test case") {}

P4ControllerCheckFlowEntryTestCase::~P4ControllerCheckFlowEntryTestCase() {}
P4ControllerActionProfileTestCase::~P4ControllerActionProfileTestCase() {}

void P4ControllerCheckFlowEntryTestCase::DoRun() {
  // std::string appDataRate = "3Mbps"; // Default application data rate
  // std::string ns3_link_rate = "1000Mbps";

  std::string p4SrcDir = GetP4ExamplePath() + "/simple_v1model";
  std::string p4JsonPath = p4SrcDir + "/simple_v1model.json";
  std::string flowTablePath = p4SrcDir + "/flowtable_0.txt";
  std::string topoInput = p4SrcDir + "/topo.txt";

  P4TopologyReaderHelper p4TopoHelper;
  p4TopoHelper.SetFileName(topoInput);
  p4TopoHelper.SetFileType("CsmaTopo");

  // Get the topology reader, and read the file, load in the m_linksList.
  Ptr<P4TopologyReader> topoReader = p4TopoHelper.GetTopologyReader();

  NS_TEST_ASSERT_MSG_NE(topoReader->LinksSize(), 0,
                        "Verify that we reading the topology file correctly");

  // get switch and host node
  NodeContainer terminals = topoReader->GetHostNodeContainer();
  NodeContainer switchNode = topoReader->GetSwitchNodeContainer();

  // Install the network stack on the nodes
  InternetStackHelper internet;
  internet.Install(terminals);
  internet.Install(switchNode);
  const unsigned int hostNum = terminals.GetN();

  // Assign IP addresses to the hosts
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.1.0", "255.255.255.0");
  std::vector<Ipv4InterfaceContainer> terminalInterfaces(hostNum);

  for (unsigned int i = 0; i < hostNum; i++) {
    terminalInterfaces[i] = ipv4.Assign(terminals.Get(i)->GetDevice(0));
  }

  // Set up the P4 switch helper
  P4Helper p4Helper;
  p4Helper.SetDeviceAttribute(
      "JsonPath", StringValue(p4JsonPath));
  p4Helper.SetDeviceAttribute(
      "FlowTablePath", StringValue(flowTablePath));
  p4Helper.SetDeviceAttribute("ChannelType", UintegerValue(0));
  p4Helper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0)); // v1model

  // Setting up the controller
  P4Controller controller;

  for (uint32_t i = 0; i < switchNode.GetN(); ++i) {
    NetDeviceContainer devs;
    for (uint32_t j = 0; j < switchNode.Get(i)->GetNDevices(); ++j) {
      Ptr<NetDevice> dev = switchNode.Get(i)->GetDevice(j);
      devs.Add(dev);
    }

    NetDeviceContainer p4Devices = p4Helper.Install(switchNode.Get(i), devs);

    for (uint32_t k = 0; k < p4Devices.GetN(); ++k) {
      Ptr<P4SwitchNetDevice> p4dev =
          DynamicCast<P4SwitchNetDevice>(p4Devices.Get(k));
      if (p4dev) {
        controller.RegisterSwitch(p4dev);
      }
    }
  }

  // In running time, we can check the table entries from the P4 switches
  Simulator::Schedule(Seconds(2.0), [this, &controller]() {
    NS_TEST_ASSERT_MSG_EQ(controller.GetN(), 1,
                          "There should be only one p4switch in there");

    NS_TEST_ASSERT_MSG_EQ(
        controller.GetTableEntryCount(0, "MyIngress.ipv4_nhop"), 2,
        "Verify that we could get the right count of table entries in the "
        "controller");

    NS_TEST_ASSERT_MSG_EQ(
        controller.GetTableEntryCount(0, "MyIngress.arp_simple"), 2,
        "Verify that we could get the right count of table entries in the "
        "controller");

    uint32_t index = 0;
    std::string table = "MyIngress.ipv4_nhop";
    std::string originalAction = "MyIngress.drop";
    std::string newAction = "MyIngress.ipv4_forward";

    std::vector<bm::MatchKeyParam> match = {bm::MatchKeyParam(
        bm::MatchKeyParam::Type::EXACT, std::string("\x0a\x01\x01\x05", 4))};

    bm::ActionData originalActionData;

    bm::entry_handle_t handle;
    controller.AddFlowEntry(index, table, match, originalAction,
                            std::move(originalActionData), handle, -1);
    NS_TEST_ASSERT_MSG_EQ(controller.GetTableEntryCount(index, table), 3,
                          "Flow entry should have been added");
    controller.PrintFlowEntries(0, table);
    bm::ActionData newActionData;

    bm::Data dstMacData;
    dstMacData.set(std::string("\x00\x00\x00\x00\x00\x09", 6));
    newActionData.push_back_action_data(dstMacData);

    bm::Data portData;
    portData.set(std::string("\x00\x02", 2));
    newActionData.push_back_action_data(portData);

    controller.ModifyFlowEntry(index, table, handle, newAction,
                               std::move(newActionData));
    controller.PrintFlowEntries(0, table);

    controller.DeleteFlowEntry(0, table, handle);
    NS_TEST_ASSERT_MSG_EQ(controller.GetTableEntryCount(index, table), 2,

                          "Flow entry should have been added");
    // TODO: Add support_timeout=true in p4 programs and compile them again
    uint32_t ttlMs = 3000;
    controller.SetEntryTtl(index, table, handle, ttlMs);
  });
  Simulator::Stop(Seconds(4.0));
  Simulator::Run();
  Simulator::Destroy();
}

void P4ControllerActionProfileTestCase::DoRun() {
  // std::string appDataRate = "3Mbps"; // Default application data rate
  // std::string ns3_link_rate = "1000Mbps";
  
  std::string p4SrcDir = GetP4TestPath() + "/action_profile_v1model";
  std::string p4JsonPath = p4SrcDir + "/action-profile.json";
  
  std::string flowTablePath = p4SrcDir + "/flowtable_0.txt";
  std::string topoInput = p4SrcDir + "/topo.txt";

  P4TopologyReaderHelper p4TopoHelper;
  p4TopoHelper.SetFileName(topoInput);
  p4TopoHelper.SetFileType("CsmaTopo");

  // Get the topology reader, and read the file, load in the m_linksList.
  Ptr<P4TopologyReader> topoReader = p4TopoHelper.GetTopologyReader();

  NS_TEST_ASSERT_MSG_NE(topoReader->LinksSize(), 0,
                        "Verify that we reading the topology file correctly");

  // get switch and host node
  NodeContainer terminals = topoReader->GetHostNodeContainer();
  NodeContainer switchNode = topoReader->GetSwitchNodeContainer();

  // Install the network stack on the nodes
  InternetStackHelper internet;
  internet.Install(terminals);
  internet.Install(switchNode);
  const unsigned int hostNum = terminals.GetN();

  // Assign IP addresses to the hosts
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.1.0", "255.255.255.0");
  std::vector<Ipv4InterfaceContainer> terminalInterfaces(hostNum);

  for (unsigned int i = 0; i < hostNum; i++) {
    terminalInterfaces[i] = ipv4.Assign(terminals.Get(i)->GetDevice(0));
  }

  // Set up the P4 switch helper
  P4Helper p4Helper;
  p4Helper.SetDeviceAttribute(
      "JsonPath",
      StringValue(p4JsonPath));
  p4Helper.SetDeviceAttribute(
      "FlowTablePath", StringValue(flowTablePath));
  p4Helper.SetDeviceAttribute("ChannelType", UintegerValue(0));
  p4Helper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0)); // v1model

  // Setting up the controller
  P4Controller controller;

  for (uint32_t i = 0; i < switchNode.GetN(); ++i) {
    NetDeviceContainer devs;
    for (uint32_t j = 0; j < switchNode.Get(i)->GetNDevices(); ++j) {
      Ptr<NetDevice> dev = switchNode.Get(i)->GetDevice(j);
      devs.Add(dev);
    }

    NetDeviceContainer p4Devices = p4Helper.Install(switchNode.Get(i), devs);

    for (uint32_t k = 0; k < p4Devices.GetN(); ++k) {
      Ptr<P4SwitchNetDevice> p4dev =
          DynamicCast<P4SwitchNetDevice>(p4Devices.Get(k));
      if (p4dev) {
        controller.RegisterSwitch(p4dev);
      }
    }
  }

  Simulator::Schedule(Seconds(1.0), [this, &controller]() {
    NS_TEST_ASSERT_MSG_EQ(controller.GetN(), 1,
                          "Expecting exactly 1 P4 switch");

    uint32_t index = 0;
    std::string profile = "action_profile_0";
    std::string action = "cIngress.foo1";

    bm::ActionData actionData;
    bm::Data dstAddr(4);     // 4 bytes = 32 bits
    dstAddr.set(0x0a0a0a0a); // Example IP: 10.10.10.10
    actionData.push_back_action_data(dstAddr);
    std::vector<bm::ActionProfile::Member> members =
        controller.GetActionProfileMembers(0, profile);
    NS_TEST_ASSERT_MSG_EQ(members.size(), 0,
                          "Action profile member creation failed");
    bm::ActionProfile::mbr_hdl_t member = 0;
    controller.AddActionProfileMember(index, profile, action,
                                      std::move(actionData), member);
    members = controller.GetActionProfileMembers(0, profile);
    NS_TEST_ASSERT_MSG_EQ(members.size(), 1,
                          "Action profile member creation failed");

    controller.DeleteActionProfileMember(0, profile, member);
    members = controller.GetActionProfileMembers(0, profile);
    NS_TEST_ASSERT_MSG_EQ(members.size(), 0,
                          "Action profile member creation failed");

    // Modify the member
    bm::ActionData modData;
    dstAddr.set(0x0a0a0a0b);
    modData.push_back_action_data(dstAddr);
    controller.PrintActionProfileMembers(0, profile);
    controller.ModifyActionProfileMember(index, profile, member, action,
                                         std::move(modData));

    // Create action profile group
  });
  Simulator::Schedule(Seconds(2), [this, &controller]() {
    uint32_t index = 0;
    std::string profile = "action_profile_1";
    std::string action = "cIngress.foo1";
    bm::ActionProfile::mbr_hdl_t member = 0;
    bm::ActionProfile::grp_hdl_t groupId;

    // Create member first (required before adding to group)
    bm::ActionData data;
    bm::Data addrData;
    addrData.set(0x0a0a0a0a); // example IP
    data.push_back_action_data(addrData);
    std::vector<bm::ActionProfile::Member> members =
        controller.GetActionProfileMembers(0, profile);
    NS_TEST_EXPECT_MSG_EQ(members.size(), 0,
                          "Action profile member creation failed");
    controller.AddActionProfileMember(index, profile, action, std::move(data),
                                      member);
    members = controller.GetActionProfileMembers(0, profile);
    NS_TEST_EXPECT_MSG_EQ(members.size(), 1,
                          "Action profile member creation failed");

    controller.CreateActionProfileGroup(0, profile, &groupId);
    controller.PrintActionProfileGroups(0, profile);

    controller.AddMemberToGroup(0, profile, member, groupId);
    controller.PrintActionProfileGroups(0, profile);
  });

  Simulator::Stop(Seconds(3.0));
  Simulator::Run();
  Simulator::Destroy();
}
// The TestSuite class names the TestSuite, identifies what type of TestSuite,
// and enables the TestCases to be run.  Typically, only the constructor for
// this class must be defined
//
class P4ControllerTestSuite : public TestSuite {
public:
  P4ControllerTestSuite() : TestSuite("p4-controller", UNIT) {
    // TestDuration for TestCase can be QUICK, EXTENSIVE or TAKES_FOREVER
    AddTestCase(new P4ControllerCheckFlowEntryTestCase, TestCase::QUICK);
    AddTestCase(new P4ControllerActionProfileTestCase, TestCase::QUICK);
  };
} g_P4ControllerTestSuite;
