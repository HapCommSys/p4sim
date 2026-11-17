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

#include "ns3/test.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/simulator.h"
#include "ns3/custom-p2p-net-device.h"
#include "ns3/p4-p2p-channel.h"
#include "ns3/net-device-queue-interface.h"

#include <string>

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

PointToPointTestSuite::PointToPointTestSuite () : TestSuite ("p4-p2p-channel", UNIT)
{
  AddTestCase (new PointToPointTest, TestCase::QUICK);
}

static PointToPointTestSuite g_pointToPointTestSuite; //!< The testsuite
