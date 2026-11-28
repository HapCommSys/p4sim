/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 INRIA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
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
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#include "ns3/p4sim-ns3-compat.h"
#include "ns3/test.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/simulator.h"
#include "ns3/custom-p2p-net-device.h"
#include "ns3/p4-p2p-channel.h"
#include "ns3/net-device-queue-interface.h"

#include <cmath>
#include <string>
#include <vector>

using namespace ns3;

/**
 * \brief Test class for PointToPoint model
 *
 * It tries to send one packet from one NetDevice to another, over a
 * P4P2PChannel.
 */
class PointToPointTest : public TestCase
{
public:
  /**
   * \brief Create the test
   */
  PointToPointTest ();

  /**
   * \brief Run the test
   */
  virtual void DoRun (void);

private:
  Ptr<const Packet> m_recvdPacket; //!< received packet
  /**
   * \brief Send one packet to the device specified
   *
   * \param device NetDevice to send to.
   * \param buffer Payload content of the packet.
   * \param size Size of the payload.
   */
  void SendOnePacket (Ptr<CustomP2PNetDevice> device, uint8_t const *buffer, uint32_t size);
  /**
   * \brief Callback function which sets the recvdPacket parameter
   *
   * \param dev The receiving device.
   * \param pkt The received packet.
   * \param mode The protocol mode used.
   * \param sender The sender address.
   * 
   * \return A boolean indicating packet handled properly.
   */
  bool RxPacket (Ptr<NetDevice> dev, Ptr<const Packet> pkt, uint16_t mode, const Address &sender);
};

PointToPointTest::PointToPointTest () : TestCase ("PointToPoint")
{
}

void
PointToPointTest::SendOnePacket (Ptr<CustomP2PNetDevice> device, uint8_t const *buffer,
                                 uint32_t size)
{
  Ptr<Packet> p = Create<Packet> (buffer, size);
  device->Send (p, device->GetBroadcast (), 0x800);
}

bool
PointToPointTest::RxPacket (Ptr<NetDevice> dev, Ptr<const Packet> pkt, uint16_t mode,
                            const Address &sender)
{
  m_recvdPacket = pkt;
  return true;
}

void
PointToPointTest::DoRun (void)
{
  Ptr<Node> a = CreateObject<Node> ();
  Ptr<Node> b = CreateObject<Node> ();
  Ptr<CustomP2PNetDevice> devA = CreateObject<CustomP2PNetDevice> ();
  Ptr<CustomP2PNetDevice> devB = CreateObject<CustomP2PNetDevice> ();
  Ptr<P4P2PChannel> channel = CreateObject<P4P2PChannel> ();

  devA->Attach (channel);
  devA->SetAddress (Mac48Address::Allocate ());
  devA->SetQueue (CreateObject<DropTailQueue<Packet>> ());
  devB->Attach (channel);
  devB->SetAddress (Mac48Address::Allocate ());
  devB->SetQueue (CreateObject<DropTailQueue<Packet>> ());

  a->AddDevice (devA);
  b->AddDevice (devB);

  devB->SetReceiveCallback (MakeCallback (&PointToPointTest::RxPacket, this));
  uint8_t txBuffer[] = "\"Can you tell me where my country lies?\" \\ said the unifaun to his true "
                       "love's eyes. \\ \"It lies with me!\" cried the Queen of Maybe \\ - for her "
                       "merchandise, he traded in his prize.";
  size_t txBufferSize = sizeof (txBuffer);

  Simulator::Schedule (Seconds (1.0), &PointToPointTest::SendOnePacket, this, devA, txBuffer,
                       txBufferSize);

  Simulator::Run ();

  NS_TEST_EXPECT_MSG_EQ (m_recvdPacket->GetSize (), txBufferSize, "trivial");

  uint8_t rxBuffer[1500]; // As large as the P2P MTU size, assuming that the user didn't change it.

  m_recvdPacket->CopyData (rxBuffer, txBufferSize);
  NS_TEST_EXPECT_MSG_EQ (memcmp (rxBuffer, txBuffer, txBufferSize), 0, "trivial");

  Simulator::Destroy ();
}

/**
 * \brief Short frames on a 100 Gbps link keep the exact line rate
 *
 * A short frame takes a fraction of a nanosecond more than a whole number of
 * nanoseconds. The simulator rounds each event time to 1 ns, but back-to-back
 * frames must still arrive at the exact line rate: the rounding must not add up.
 */
class PointToPointExactRateTest : public TestCase
{
public:
  PointToPointExactRateTest () : TestCase ("Short frames on a 100 Gbps link keep the exact line rate")
  {
  }

private:
  void DoRun (void) override
  {
    const uint32_t frames = 50;
    Ptr<Node> a = CreateObject<Node> ();
    Ptr<Node> b = CreateObject<Node> ();
    Ptr<CustomP2PNetDevice> devA = CreateObject<CustomP2PNetDevice> ();
    Ptr<CustomP2PNetDevice> devB = CreateObject<CustomP2PNetDevice> ();
    Ptr<P4P2PChannel> channel = CreateObject<P4P2PChannel> ();
    devA->SetAttribute ("DataRate", DataRateValue (DataRate ("100Gbps")));
    devA->Attach (channel);
    devA->SetAddress (Mac48Address::Allocate ());
    devA->SetQueue (CreateObject<DropTailQueue<Packet>> ());
    devB->Attach (channel);
    devB->SetAddress (Mac48Address::Allocate ());
    devB->SetQueue (CreateObject<DropTailQueue<Packet>> ());
    a->AddDevice (devA);
    b->AddDevice (devB);

    devA->TraceConnectWithoutContext ("PhyTxBegin",
                                      MakeCallback (&PointToPointExactRateTest::TxBegin, this));
    devB->SetReceiveCallback (MakeCallback (&PointToPointExactRateTest::Rx, this));
    for (uint32_t k = 0; k < frames; k++)
      {
        Simulator::Schedule (MicroSeconds (1), &PointToPointExactRateTest::Send, this, devA);
      }
    Simulator::Run ();
    Simulator::Destroy ();

    NS_TEST_ASSERT_MSG_EQ (m_arrivals.size (), frames, "Frames were lost");
    // The size of a frame on the wire, headers included
    const double txNs = m_wireBytes * 8.0 / 100e9 * 1e9;
    for (size_t k = 1; k < m_arrivals.size (); k++)
      {
        // Frame k arrives k serialisation times after the first one
        double error = (m_arrivals[k] - m_arrivals[0]).GetNanoSeconds () - k * txNs;
        NS_TEST_EXPECT_MSG_LT_OR_EQ (std::abs (error), 1.0,
                                     "Frame " << k << " is " << error
                                              << " ns from its exact arrival");
      }
  }

  void Send (Ptr<CustomP2PNetDevice> device)
  {
    device->Send (Create<Packet> (40), device->GetBroadcast (), 0x800);
  }

  void TxBegin (Ptr<const Packet> frame)
  {
    m_wireBytes = frame->GetSize ();
  }

  bool Rx (Ptr<NetDevice> dev, Ptr<const Packet> pkt, uint16_t mode, const Address &sender)
  {
    m_arrivals.push_back (Simulator::Now ());
    return true;
  }

  uint32_t m_wireBytes{0};      //!< size of a frame on the wire
  std::vector<Time> m_arrivals; //!< arrival times at device B
};

/**
 * \brief TestSuite for PointToPoint module
 */
class PointToPointTestSuite : public TestSuite
{
public:
  /**
   * \brief Constructor
   */
  PointToPointTestSuite ();
};

PointToPointTestSuite::PointToPointTestSuite () : TestSuite ("p4-p2p-channel", TestSuite::Type::UNIT)
{
  AddTestCase (new PointToPointTest, P4SIM_TEST_QUICK);
  AddTestCase (new PointToPointExactRateTest, P4SIM_TEST_QUICK);
}

static PointToPointTestSuite g_pointToPointTestSuite; //!< The testsuite
