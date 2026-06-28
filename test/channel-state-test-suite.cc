/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 TU Dresden
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Vineet Goel
 *
 * Tests for SwitchedEthernetChannel wire-state transitions and the
 * P4SwitchNetDevice channel-query API (IsBusy / GetState / GetPortDeviceId).
 */

#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ChannelStateTestSuite");

// ===========================================================================
// Test 1: Wire-state transitions on a bare channel
//
// Creates a channel with two P4SwitchNetDevice endpoints (no P4 JSON, so
// they operate in NIC/passthrough mode).  Manually drives TransmitStart /
// TransmitEnd and checks GetState() / IsBusy() at each stage.
// ===========================================================================

class ChannelStateTransitionTest : public TestCase {
public:
  ChannelStateTransitionTest();

private:
  void DoRun() override;

  // Helpers scheduled at specific simulation times.
  void CheckIdleBeforeTx(Ptr<SwitchedEthernetChannel> ch, uint32_t slot);
  void StartTransmit(Ptr<SwitchedEthernetChannel> ch, uint32_t slot,
                     Ptr<Packet> pkt);
  void CheckTransmitting(Ptr<SwitchedEthernetChannel> ch, uint32_t slot);
  void EndTransmit(Ptr<SwitchedEthernetChannel> ch, uint32_t slot);
  void CheckPropagating(Ptr<SwitchedEthernetChannel> ch, uint32_t slot);
  void CheckIdleAfterProp(Ptr<SwitchedEthernetChannel> ch, uint32_t slot);
};

ChannelStateTransitionTest::ChannelStateTransitionTest()
    : TestCase("SwitchedEthernetChannel IDLE→TX→PROPAGATING→IDLE transitions") {
}

void ChannelStateTransitionTest::CheckIdleBeforeTx(
    Ptr<SwitchedEthernetChannel> ch, uint32_t slot) {
  NS_TEST_ASSERT_MSG_EQ(ch->GetState(slot), IDLE_STATE,
                        "Slot " << slot
                                << " should be IDLE before TransmitStart");
  NS_TEST_ASSERT_MSG_EQ(ch->IsBusy(slot), false,
                        "Slot " << slot
                                << " IsBusy() should be false when IDLE");
}

void ChannelStateTransitionTest::StartTransmit(Ptr<SwitchedEthernetChannel> ch,
                                               uint32_t slot, Ptr<Packet> pkt) {
  bool ok = ch->TransmitStart(pkt, slot);
  NS_TEST_ASSERT_MSG_EQ(ok, true,
                        "TransmitStart should succeed on an idle wire");
}

void ChannelStateTransitionTest::CheckTransmitting(
    Ptr<SwitchedEthernetChannel> ch, uint32_t slot) {
  NS_TEST_ASSERT_MSG_EQ(
      ch->GetState(slot), TRANSMITTING_STATE,
      "Slot " << slot << " should be TRANSMITTING after TransmitStart");
  NS_TEST_ASSERT_MSG_EQ(
      ch->IsBusy(slot), true,
      "Slot " << slot << " IsBusy() should be true while TRANSMITTING");
}

void ChannelStateTransitionTest::EndTransmit(Ptr<SwitchedEthernetChannel> ch,
                                             uint32_t slot) {
  bool ok = ch->TransmitEnd(slot);
  NS_TEST_ASSERT_MSG_EQ(ok, true, "TransmitEnd should succeed");
}

void ChannelStateTransitionTest::CheckPropagating(
    Ptr<SwitchedEthernetChannel> ch, uint32_t slot) {
  NS_TEST_ASSERT_MSG_EQ(ch->GetState(slot), PROPAGATING_STATE,
                        "Slot " << slot
                                << " should be PROPAGATING after TransmitEnd");
  NS_TEST_ASSERT_MSG_EQ(
      ch->IsBusy(slot), true,
      "Slot " << slot << " IsBusy() should be true while PROPAGATING");
}

void ChannelStateTransitionTest::CheckIdleAfterProp(
    Ptr<SwitchedEthernetChannel> ch, uint32_t slot) {
  NS_TEST_ASSERT_MSG_EQ(
      ch->GetState(slot), IDLE_STATE,
      "Slot " << slot << " should be IDLE after propagation completes");
  NS_TEST_ASSERT_MSG_EQ(
      ch->IsBusy(slot), false,
      "Slot " << slot << " IsBusy() should be false after propagation");
}

void ChannelStateTransitionTest::DoRun() {
  // --- Topology: two P4SwitchNetDevices in NIC mode (no JsonPath) ---
  Ptr<Node> nodeA = CreateObject<Node>();
  Ptr<Node> nodeB = CreateObject<Node>();

  Ptr<P4SwitchNetDevice> devA = CreateObject<P4SwitchNetDevice>();
  Ptr<P4SwitchNetDevice> devB = CreateObject<P4SwitchNetDevice>();

  devA->SetAddress(Mac48Address::Allocate());
  devB->SetAddress(Mac48Address::Allocate());

  nodeA->AddDevice(devA);
  nodeB->AddDevice(devB);

  // Channel: 100 Mbps, 2 µs propagation delay.
  Ptr<SwitchedEthernetChannel> ch = CreateObject<SwitchedEthernetChannel>();
  ch->SetAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
  ch->SetAttribute("Delay", TimeValue(MicroSeconds(2)));

  devA->Attach(ch); // slot 0
  devB->Attach(ch); // slot 1

  // Initialize devices (NIC mode — no P4 core created).
  devA->Initialize();
  devB->Initialize();

  const uint32_t slotA = 0;

  // A 100-byte packet on 100 Mbps → serialisation time = 8 µs.
  Ptr<Packet> pkt = Create<Packet>(100);

  // t = 0: both slots should be IDLE.
  Simulator::Schedule(Seconds(0.0),
                      &ChannelStateTransitionTest::CheckIdleBeforeTx, this, ch,
                      slotA);

  // t = 1 µs: start transmitting from slot A.
  Simulator::Schedule(MicroSeconds(1),
                      &ChannelStateTransitionTest::StartTransmit, this, ch,
                      slotA, pkt);

  // t = 1 µs + 1 ns: verify state is TRANSMITTING.
  Simulator::Schedule(MicroSeconds(1) + NanoSeconds(1),
                      &ChannelStateTransitionTest::CheckTransmitting, this, ch,
                      slotA);

  // t = 9 µs: serialisation done (1 µs start + 8 µs TX time), call TransmitEnd.
  Simulator::Schedule(MicroSeconds(9), &ChannelStateTransitionTest::EndTransmit,
                      this, ch, slotA);

  // t = 9 µs + 1 ns: verify state is PROPAGATING.
  Simulator::Schedule(MicroSeconds(9) + NanoSeconds(1),
                      &ChannelStateTransitionTest::CheckPropagating, this, ch,
                      slotA);

  // t = 11 µs + 1 ns: propagation delay (2 µs) has elapsed → should be IDLE.
  Simulator::Schedule(MicroSeconds(11) + NanoSeconds(1),
                      &ChannelStateTransitionTest::CheckIdleAfterProp, this, ch,
                      slotA);

  Simulator::Run();
  Simulator::Destroy();
}

// ===========================================================================
// Test 2: Full-duplex independence
//
// Both slots transmit simultaneously.  Verify that slot A being busy does
// NOT affect slot B's state, and vice versa.
// ===========================================================================

class FullDuplexIndependenceTest : public TestCase {
public:
  FullDuplexIndependenceTest();

private:
  void DoRun() override;
};

FullDuplexIndependenceTest::FullDuplexIndependenceTest()
    : TestCase("Full-duplex: both slots transmit independently") {}

void FullDuplexIndependenceTest::DoRun() {
  Ptr<Node> nodeA = CreateObject<Node>();
  Ptr<Node> nodeB = CreateObject<Node>();

  Ptr<P4SwitchNetDevice> devA = CreateObject<P4SwitchNetDevice>();
  Ptr<P4SwitchNetDevice> devB = CreateObject<P4SwitchNetDevice>();

  devA->SetAddress(Mac48Address::Allocate());
  devB->SetAddress(Mac48Address::Allocate());

  nodeA->AddDevice(devA);
  nodeB->AddDevice(devB);

  Ptr<SwitchedEthernetChannel> ch = CreateObject<SwitchedEthernetChannel>();
  ch->SetAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
  ch->SetAttribute("Delay", TimeValue(MicroSeconds(1)));

  devA->Attach(ch); // slot 0
  devB->Attach(ch); // slot 1

  devA->Initialize();
  devB->Initialize();

  Ptr<Packet> pktA = Create<Packet>(500);
  Ptr<Packet> pktB = Create<Packet>(500);

  // Both start transmitting at t = 0.
  Simulator::Schedule(Seconds(0.0), [this, ch, pktA]() {
    bool ok = ch->TransmitStart(pktA, 0);
    NS_TEST_ASSERT_MSG_EQ(ok, true, "Slot 0 TransmitStart should succeed");
  });

  Simulator::Schedule(Seconds(0.0), [this, ch, pktB]() {
    bool ok = ch->TransmitStart(pktB, 1);
    NS_TEST_ASSERT_MSG_EQ(ok, true,
                          "Slot 1 TransmitStart should succeed simultaneously");
  });

  // At t = 1 ns: both should be TRANSMITTING independently.
  Simulator::Schedule(NanoSeconds(1), [this, ch]() {
    NS_TEST_ASSERT_MSG_EQ(ch->IsBusy(0), true, "Slot 0 should be busy");
    NS_TEST_ASSERT_MSG_EQ(ch->IsBusy(1), true, "Slot 1 should be busy");
    NS_TEST_ASSERT_MSG_EQ(ch->GetState(0), TRANSMITTING_STATE,
                          "Slot 0 should be TRANSMITTING");
    NS_TEST_ASSERT_MSG_EQ(ch->GetState(1), TRANSMITTING_STATE,
                          "Slot 1 should be TRANSMITTING");
  });

  // 500 bytes at 1 Gbps = 4 µs serialisation.  End slot 0 only.
  Simulator::Schedule(MicroSeconds(4), [ch]() { ch->TransmitEnd(0); });

  // Slot 0 is now PROPAGATING, slot 1 is still TRANSMITTING.
  Simulator::Schedule(MicroSeconds(4) + NanoSeconds(1), [this, ch]() {
    NS_TEST_ASSERT_MSG_EQ(ch->GetState(0), PROPAGATING_STATE,
                          "Slot 0 should be PROPAGATING");
    NS_TEST_ASSERT_MSG_EQ(ch->GetState(1), TRANSMITTING_STATE,
                          "Slot 1 should still be TRANSMITTING");
  });

  // End slot 1 at the same time.
  Simulator::Schedule(MicroSeconds(4) + NanoSeconds(100),
                      [ch]() { ch->TransmitEnd(1); });

  // After propagation (4 µs TX + 1 µs prop = 5 µs), slot 0 should be IDLE.
  Simulator::Schedule(MicroSeconds(5) + NanoSeconds(1), [this, ch]() {
    NS_TEST_ASSERT_MSG_EQ(ch->GetState(0), IDLE_STATE,
                          "Slot 0 should be IDLE after prop");
    // Slot 1 still propagating (started prop at ~4 µs + 100 ns).
    NS_TEST_ASSERT_MSG_EQ(ch->IsBusy(1), true, "Slot 1 should still be busy");
  });

  Simulator::Run();
  Simulator::Destroy();
}

// ===========================================================================
// Test 3: GetPortDeviceId accessor on P4SwitchNetDevice
//
// Verifies that GetPortDeviceId() returns the correct channel slot IDs
// and UINT32_MAX for invalid port indices.
// ===========================================================================

class PortDeviceIdAccessorTest : public TestCase {
public:
  PortDeviceIdAccessorTest();

private:
  void DoRun() override;
};

PortDeviceIdAccessorTest::PortDeviceIdAccessorTest()
    : TestCase("P4SwitchNetDevice::GetPortDeviceId returns correct slot IDs") {}

void PortDeviceIdAccessorTest::DoRun() {
  Ptr<Node> switchNode = CreateObject<Node>();
  Ptr<Node> hostA = CreateObject<Node>();
  Ptr<Node> hostB = CreateObject<Node>();

  Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
  Ptr<P4SwitchNetDevice> nicA = CreateObject<P4SwitchNetDevice>();
  Ptr<P4SwitchNetDevice> nicB = CreateObject<P4SwitchNetDevice>();

  sw->SetAddress(Mac48Address::Allocate());
  nicA->SetAddress(Mac48Address::Allocate());
  nicB->SetAddress(Mac48Address::Allocate());

  switchNode->AddDevice(sw);
  hostA->AddDevice(nicA);
  hostB->AddDevice(nicB);

  // Channel 0: switch port 0 ↔ hostA
  Ptr<SwitchedEthernetChannel> ch0 = CreateObject<SwitchedEthernetChannel>();
  ch0->SetAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
  sw->Attach(ch0);   // switch takes slot 0 in ch0
  nicA->Attach(ch0); // host takes slot 1 in ch0

  // Channel 1: switch port 1 ↔ hostB
  Ptr<SwitchedEthernetChannel> ch1 = CreateObject<SwitchedEthernetChannel>();
  ch1->SetAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
  sw->Attach(ch1);   // switch takes slot 0 in ch1
  nicB->Attach(ch1); // host takes slot 1 in ch1

  // Switch has 2 ports.
  NS_TEST_ASSERT_MSG_EQ(sw->GetNPorts(), 2, "Switch should have 2 ports");

  // Port 0 → slot 0 in ch0, Port 1 → slot 0 in ch1
  // (switch always attaches first to each channel, so it gets slot 0).
  NS_TEST_ASSERT_MSG_EQ(sw->GetPortDeviceId(0), 0u,
                        "Port 0 should map to channel slot 0");
  NS_TEST_ASSERT_MSG_EQ(sw->GetPortDeviceId(1), 0u,
                        "Port 1 should map to channel slot 0");

  // Invalid port index should return UINT32_MAX.
  NS_TEST_ASSERT_MSG_EQ(sw->GetPortDeviceId(99), UINT32_MAX,
                        "Invalid port should return UINT32_MAX");

  // Verify GetPortChannel returns the correct channels.
  NS_TEST_ASSERT_MSG_EQ(sw->GetPortChannel(0), ch0, "Port 0 should be on ch0");
  NS_TEST_ASSERT_MSG_EQ(sw->GetPortChannel(1), ch1, "Port 1 should be on ch1");

  // Cross-check: IsBusy on the channel using the device ID from
  // GetPortDeviceId.
  uint32_t devId0 = sw->GetPortDeviceId(0);
  Ptr<SwitchedEthernetChannel> portCh0 = sw->GetPortChannel(0);
  NS_TEST_ASSERT_MSG_EQ(portCh0->IsBusy(devId0), false,
                        "Port 0 channel should be idle initially");
}

// ===========================================================================
// Test 4: TransmitStart fails on a busy wire
//
// Verifies that a second TransmitStart on the same slot returns false
// while the wire is TRANSMITTING or PROPAGATING.
// ===========================================================================

class TransmitStartBusyTest : public TestCase {
public:
  TransmitStartBusyTest();

private:
  void DoRun() override;
};

TransmitStartBusyTest::TransmitStartBusyTest()
    : TestCase("TransmitStart returns false when wire is busy") {}

void TransmitStartBusyTest::DoRun() {
  Ptr<Node> nodeA = CreateObject<Node>();
  Ptr<Node> nodeB = CreateObject<Node>();

  Ptr<P4SwitchNetDevice> devA = CreateObject<P4SwitchNetDevice>();
  Ptr<P4SwitchNetDevice> devB = CreateObject<P4SwitchNetDevice>();

  devA->SetAddress(Mac48Address::Allocate());
  devB->SetAddress(Mac48Address::Allocate());

  nodeA->AddDevice(devA);
  nodeB->AddDevice(devB);

  Ptr<SwitchedEthernetChannel> ch = CreateObject<SwitchedEthernetChannel>();
  ch->SetAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
  ch->SetAttribute("Delay", TimeValue(MicroSeconds(5)));

  devA->Attach(ch);
  devB->Attach(ch);

  devA->Initialize();
  devB->Initialize();

  Ptr<Packet> pkt1 = Create<Packet>(200);
  Ptr<Packet> pkt2 = Create<Packet>(100);

  // Start first transmission.
  Simulator::Schedule(Seconds(0.0), [this, ch, pkt1]() {
    bool ok = ch->TransmitStart(pkt1, 0);
    NS_TEST_ASSERT_MSG_EQ(ok, true, "First TransmitStart should succeed");
  });

  // Try a second TransmitStart while still TRANSMITTING → should fail.
  Simulator::Schedule(NanoSeconds(100), [this, ch, pkt2]() {
    NS_TEST_ASSERT_MSG_EQ(ch->GetState(0), TRANSMITTING_STATE,
                          "Should still be TRANSMITTING");
    bool ok = ch->TransmitStart(pkt2, 0);
    NS_TEST_ASSERT_MSG_EQ(ok, false,
                          "Second TransmitStart should fail while TX");
  });

  // 200 bytes at 100 Mbps = 16 µs.  Call TransmitEnd.
  Simulator::Schedule(MicroSeconds(16), [ch]() { ch->TransmitEnd(0); });

  // Try TransmitStart while PROPAGATING → should also fail.
  Simulator::Schedule(MicroSeconds(16) + NanoSeconds(1), [this, ch, pkt2]() {
    NS_TEST_ASSERT_MSG_EQ(ch->GetState(0), PROPAGATING_STATE,
                          "Should be PROPAGATING");
    bool ok = ch->TransmitStart(pkt2, 0);
    NS_TEST_ASSERT_MSG_EQ(ok, false,
                          "TransmitStart should fail while PROPAGATING");
  });

  // After propagation (16 µs + 5 µs = 21 µs), should be IDLE again.
  Simulator::Schedule(MicroSeconds(21) + NanoSeconds(1), [this, ch, pkt2]() {
    NS_TEST_ASSERT_MSG_EQ(ch->GetState(0), IDLE_STATE,
                          "Should be IDLE after propagation");
    bool ok = ch->TransmitStart(pkt2, 0);
    NS_TEST_ASSERT_MSG_EQ(ok, true,
                          "TransmitStart should succeed once IDLE again");
  });

  Simulator::Run();
  Simulator::Destroy();
}

// ===========================================================================
// Test Suite
// ===========================================================================

class ChannelStateTestSuite : public TestSuite {
public:
  ChannelStateTestSuite();
};

ChannelStateTestSuite::ChannelStateTestSuite()
    : TestSuite("channel-state-test-suite", Type::UNIT) {
  AddTestCase(new ChannelStateTransitionTest, TestCase::QUICK);
  AddTestCase(new FullDuplexIndependenceTest, TestCase::QUICK);
  AddTestCase(new PortDeviceIdAccessorTest, TestCase::QUICK);
  AddTestCase(new TransmitStartBusyTest, TestCase::QUICK);
}

static ChannelStateTestSuite g_channelStateTestSuite;
