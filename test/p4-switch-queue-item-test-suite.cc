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
 * Tests for P4SwitchQueueItem and per-port QueueDisc integration.
 */

#include "ns3/fifo-queue-disc.h"
#include "ns3/log.h"
#include "ns3/mac48-address.h"
#include "ns3/node.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4-switch-queue-item.h"
#include "ns3/packet.h"
#include "ns3/queue-disc.h"
#include "ns3/simulator.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4SwitchQueueItemTestSuite");

// ===========================================================================
// Test 1: P4SwitchQueueItem basic accessors
//
// Verifies that constructor arguments are stored correctly and that
// AddHeader() and Mark() behave as expected (no-op and false).
// ===========================================================================

class P4SwitchQueueItemAccessorTest : public TestCase
{
  public:
    P4SwitchQueueItemAccessorTest();

  private:
    void DoRun() override;
};

P4SwitchQueueItemAccessorTest::P4SwitchQueueItemAccessorTest()
    : TestCase("P4SwitchQueueItem: construction and accessor methods")
{
}

void
P4SwitchQueueItemAccessorTest::DoRun()
{
    Ptr<Packet> pkt = Create<Packet>(500);
    Mac48Address dst = Mac48Address("aa:bb:cc:dd:ee:ff");
    uint16_t proto = 0x0800; // IPv4
    uint32_t portIdx = 3;

    Ptr<P4SwitchQueueItem> item = Create<P4SwitchQueueItem>(pkt, dst, proto, portIdx);

    // --- Verify accessors ---
    NS_TEST_ASSERT_MSG_EQ(item->GetPacket()->GetSize(),
                           500,
                           "Packet size should be 500 bytes");

    NS_TEST_ASSERT_MSG_EQ(item->GetProtocol(), proto, "Protocol should be 0x0800");

    NS_TEST_ASSERT_MSG_EQ(Mac48Address::ConvertFrom(item->GetAddress()),
                           dst,
                           "Destination MAC should match");

    NS_TEST_ASSERT_MSG_EQ(item->GetPortIndex(), portIdx, "Port index should be 3");

    // --- AddHeader is a no-op (should not crash or modify packet) ---
    uint32_t sizeBefore = item->GetPacket()->GetSize();
    item->AddHeader();
    NS_TEST_ASSERT_MSG_EQ(item->GetPacket()->GetSize(),
                           sizeBefore,
                           "AddHeader() should not change packet size");

    // --- Mark returns false (no ECN support) ---
    NS_TEST_ASSERT_MSG_EQ(item->Mark(), false, "Mark() should return false");
}

// ===========================================================================
// Test 2: FifoQueueDisc with P4SwitchQueueItem — FIFO ordering
//
// Creates a FifoQueueDisc, enqueues three P4SwitchQueueItems with
// different packet sizes, and verifies they dequeue in FIFO order.
// ===========================================================================

class FifoQueueDiscOrderTest : public TestCase
{
  public:
    FifoQueueDiscOrderTest();

  private:
    void DoRun() override;
};

FifoQueueDiscOrderTest::FifoQueueDiscOrderTest()
    : TestCase("FifoQueueDisc with P4SwitchQueueItem: FIFO dequeue order")
{
}

void
FifoQueueDiscOrderTest::DoRun()
{
    // Create and initialize a FifoQueueDisc.
    Ptr<FifoQueueDisc> qd = CreateObject<FifoQueueDisc>();
    qd->Initialize();

    Mac48Address dst = Mac48Address("11:22:33:44:55:66");

    // Enqueue three packets of different sizes so we can identify them.
    Ptr<P4SwitchQueueItem> item1 = Create<P4SwitchQueueItem>(Create<Packet>(100), dst, 0x0800, 0);
    Ptr<P4SwitchQueueItem> item2 = Create<P4SwitchQueueItem>(Create<Packet>(200), dst, 0x0800, 0);
    Ptr<P4SwitchQueueItem> item3 = Create<P4SwitchQueueItem>(Create<Packet>(300), dst, 0x0800, 0);

    NS_TEST_ASSERT_MSG_EQ(qd->Enqueue(item1), true, "Enqueue item1 should succeed");
    NS_TEST_ASSERT_MSG_EQ(qd->Enqueue(item2), true, "Enqueue item2 should succeed");
    NS_TEST_ASSERT_MSG_EQ(qd->Enqueue(item3), true, "Enqueue item3 should succeed");

    NS_TEST_ASSERT_MSG_EQ(qd->GetNPackets(), 3u, "QueueDisc should have 3 packets");

    // Dequeue and verify FIFO order by packet size.
    Ptr<QueueDiscItem> out1 = qd->Dequeue();
    NS_TEST_ASSERT_MSG_NE(out1, nullptr, "First dequeue should not be null");
    NS_TEST_ASSERT_MSG_EQ(out1->GetPacket()->GetSize(),
                           100,
                           "First dequeue should be 100 B packet");

    Ptr<QueueDiscItem> out2 = qd->Dequeue();
    NS_TEST_ASSERT_MSG_NE(out2, nullptr, "Second dequeue should not be null");
    NS_TEST_ASSERT_MSG_EQ(out2->GetPacket()->GetSize(),
                           200,
                           "Second dequeue should be 200 B packet");

    Ptr<QueueDiscItem> out3 = qd->Dequeue();
    NS_TEST_ASSERT_MSG_NE(out3, nullptr, "Third dequeue should not be null");
    NS_TEST_ASSERT_MSG_EQ(out3->GetPacket()->GetSize(),
                           300,
                           "Third dequeue should be 300 B packet");

    // Queue should be empty now.
    Ptr<QueueDiscItem> out4 = qd->Dequeue();
    NS_TEST_ASSERT_MSG_EQ(out4, nullptr, "Dequeue from empty QueueDisc should return null");
    NS_TEST_ASSERT_MSG_EQ(qd->GetNPackets(), 0u, "QueueDisc should be empty");
}

// ===========================================================================
// Test 3: Multiple ports with different QueueDisc configurations
//
// Verifies that items enqueued to different port-specific QueueDiscs
// are independently managed (no cross-port leakage).
// ===========================================================================

class MultiPortQueueDiscTest : public TestCase
{
  public:
    MultiPortQueueDiscTest();

  private:
    void DoRun() override;
};

MultiPortQueueDiscTest::MultiPortQueueDiscTest()
    : TestCase("Multiple independent per-port FifoQueueDiscs")
{
}

void
MultiPortQueueDiscTest::DoRun()
{
    Ptr<FifoQueueDisc> qd0 = CreateObject<FifoQueueDisc>();
    Ptr<FifoQueueDisc> qd1 = CreateObject<FifoQueueDisc>();
    qd0->Initialize();
    qd1->Initialize();

    Mac48Address dst = Mac48Address("aa:bb:cc:dd:ee:ff");

    // Enqueue 2 packets to port 0's queue, 1 to port 1's queue.
    Ptr<P4SwitchQueueItem> p0a = Create<P4SwitchQueueItem>(Create<Packet>(100), dst, 0x0800, 0);
    Ptr<P4SwitchQueueItem> p0b = Create<P4SwitchQueueItem>(Create<Packet>(200), dst, 0x0800, 0);
    Ptr<P4SwitchQueueItem> p1a = Create<P4SwitchQueueItem>(Create<Packet>(300), dst, 0x0800, 1);

    qd0->Enqueue(p0a);
    qd0->Enqueue(p0b);
    qd1->Enqueue(p1a);

    // Port 0 should have 2, port 1 should have 1.
    NS_TEST_ASSERT_MSG_EQ(qd0->GetNPackets(), 2u, "Port 0 QueueDisc should have 2 packets");
    NS_TEST_ASSERT_MSG_EQ(qd1->GetNPackets(), 1u, "Port 1 QueueDisc should have 1 packet");

    // Dequeue from port 1 first — should not affect port 0.
    Ptr<QueueDiscItem> out1 = qd1->Dequeue();
    NS_TEST_ASSERT_MSG_NE(out1, nullptr, "Port 1 dequeue should succeed");
    NS_TEST_ASSERT_MSG_EQ(out1->GetPacket()->GetSize(),
                           300,
                           "Port 1 should dequeue the 300 B packet");

    NS_TEST_ASSERT_MSG_EQ(qd0->GetNPackets(), 2u, "Port 0 should still have 2 packets");
    NS_TEST_ASSERT_MSG_EQ(qd1->GetNPackets(), 0u, "Port 1 should be empty");

    // Dequeue from port 0 — FIFO order.
    Ptr<QueueDiscItem> out0a = qd0->Dequeue();
    NS_TEST_ASSERT_MSG_EQ(out0a->GetPacket()->GetSize(),
                           100,
                           "Port 0 first dequeue should be 100 B");

    Ptr<QueueDiscItem> out0b = qd0->Dequeue();
    NS_TEST_ASSERT_MSG_EQ(out0b->GetPacket()->GetSize(),
                           200,
                           "Port 0 second dequeue should be 200 B");

    NS_TEST_ASSERT_MSG_EQ(qd0->GetNPackets(), 0u, "Port 0 should be empty");
}

// ===========================================================================
// Test 4: P4SwitchQueueItem port index preservation through QueueDisc
//
// Enqueues items with different port indices into a single QueueDisc,
// verifies the port index survives the enqueue/dequeue round-trip.
// ===========================================================================

class PortIndexPreservationTest : public TestCase
{
  public:
    PortIndexPreservationTest();

  private:
    void DoRun() override;
};

PortIndexPreservationTest::PortIndexPreservationTest()
    : TestCase("P4SwitchQueueItem port index preserved through QueueDisc enqueue-dequeue")
{
}

void
PortIndexPreservationTest::DoRun()
{
    Ptr<FifoQueueDisc> qd = CreateObject<FifoQueueDisc>();
    qd->Initialize();

    Mac48Address dst = Mac48Address("ff:ff:ff:ff:ff:ff");

    // Enqueue items with different port indices.
    Ptr<P4SwitchQueueItem> item0 = Create<P4SwitchQueueItem>(Create<Packet>(100), dst, 0x0800, 0);
    Ptr<P4SwitchQueueItem> item5 = Create<P4SwitchQueueItem>(Create<Packet>(200), dst, 0x0800, 5);
    Ptr<P4SwitchQueueItem> item7 = Create<P4SwitchQueueItem>(Create<Packet>(300), dst, 0x86DD, 7);

    qd->Enqueue(item0);
    qd->Enqueue(item5);
    qd->Enqueue(item7);

    // Dequeue and verify port index is preserved via downcast.
    Ptr<QueueDiscItem> out0 = qd->Dequeue();
    Ptr<P4SwitchQueueItem> p4out0 = DynamicCast<P4SwitchQueueItem>(out0);
    NS_TEST_ASSERT_MSG_NE(p4out0, nullptr, "Downcast to P4SwitchQueueItem should succeed");
    NS_TEST_ASSERT_MSG_EQ(p4out0->GetPortIndex(), 0u, "First item port index should be 0");

    Ptr<QueueDiscItem> out5 = qd->Dequeue();
    Ptr<P4SwitchQueueItem> p4out5 = DynamicCast<P4SwitchQueueItem>(out5);
    NS_TEST_ASSERT_MSG_NE(p4out5, nullptr, "Downcast should succeed");
    NS_TEST_ASSERT_MSG_EQ(p4out5->GetPortIndex(), 5u, "Second item port index should be 5");
    NS_TEST_ASSERT_MSG_EQ(p4out5->GetProtocol(), 0x0800, "Protocol should be IPv4");

    Ptr<QueueDiscItem> out7 = qd->Dequeue();
    Ptr<P4SwitchQueueItem> p4out7 = DynamicCast<P4SwitchQueueItem>(out7);
    NS_TEST_ASSERT_MSG_NE(p4out7, nullptr, "Downcast should succeed");
    NS_TEST_ASSERT_MSG_EQ(p4out7->GetPortIndex(), 7u, "Third item port index should be 7");
    NS_TEST_ASSERT_MSG_EQ(p4out7->GetProtocol(), 0x86DD, "Protocol should be IPv6");
}

// ===========================================================================
// Test Suite
// ===========================================================================

class P4SwitchQueueItemTestSuite : public TestSuite
{
  public:
    P4SwitchQueueItemTestSuite();
};

P4SwitchQueueItemTestSuite::P4SwitchQueueItemTestSuite()
    : TestSuite("p4-switch-queue-item-test-suite", Type::UNIT)
{
    AddTestCase(new P4SwitchQueueItemAccessorTest, TestCase::QUICK);
    AddTestCase(new FifoQueueDiscOrderTest, TestCase::QUICK);
    AddTestCase(new MultiPortQueueDiscTest, TestCase::QUICK);
    AddTestCase(new PortIndexPreservationTest, TestCase::QUICK);
}

static P4SwitchQueueItemTestSuite g_p4SwitchQueueItemTestSuite;
