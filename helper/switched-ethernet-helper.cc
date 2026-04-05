/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2012
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
 * Author: Jeff Young
 *         Based on csma-helper by Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 * 		   
 */

#include "ns3/abort.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/object-factory.h"
#include "ns3/queue.h"
#include "ns3/switched-ethernet-net-device.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/config.h"
#include "ns3/packet.h"
#include "ns3/names.h"

#include "ns3/trace-helper.h"
#include "switched-ethernet-helper.h"

#include <string>

NS_LOG_COMPONENT_DEFINE ("SwitchedEthernetHelper");

namespace ns3 {

SwitchedEthernetHelper::SwitchedEthernetHelper ()
{
  m_queueFactory.SetTypeId ("ns3::DropTailQueue");
  m_deviceFactory.SetTypeId ("ns3::SwitchedEthernetNetDevice");
  m_channelFactory.SetTypeId ("ns3::SwitchedEthernetChannel");
}

void 
SwitchedEthernetHelper::SetQueue (std::string type,
                      std::string n1, const AttributeValue &v1,
                      std::string n2, const AttributeValue &v2,
                      std::string n3, const AttributeValue &v3,
                      std::string n4, const AttributeValue &v4)
{
  m_queueFactory.SetTypeId (type);
  m_queueFactory.Set (n1, v1);
  m_queueFactory.Set (n2, v2);
  m_queueFactory.Set (n3, v3);
  m_queueFactory.Set (n4, v4);
}

void 
SwitchedEthernetHelper::SetDeviceAttribute (std::string n1, const AttributeValue &v1)
{
  m_deviceFactory.Set (n1, v1);
}

void 
SwitchedEthernetHelper::SetChannelAttribute (std::string n1, const AttributeValue &v1)
{
  m_channelFactory.Set (n1, v1);
}

void 
SwitchedEthernetHelper::EnablePcapInternal (std::string prefix, Ptr<NetDevice> nd, bool promiscuous, bool explicitFilename)
{
  //
  // All of the Pcap enable functions vector through here including the ones
  // that are wandering through all of devices on perhaps all of the nodes in
  // the system.  We can only deal with devices of type SwitchedEthernetNetDevice.
  //
  Ptr<SwitchedEthernetNetDevice> device = nd->GetObject<SwitchedEthernetNetDevice> ();
  if (device == 0)
    {
      NS_LOG_INFO ("SwitchedEthernetHelper::EnablePcapInternal(): Device " << device << " not of type ns3::SwitchedEthernetNetDevice");
      return;
    }

  PcapHelper pcapHelper;

  std::string filename;
  if (explicitFilename)
    {
      filename = prefix;
    }
  else
    {
      filename = pcapHelper.GetFilenameFromDevice (prefix, device);
    }

  Ptr<PcapFileWrapper> file = pcapHelper.CreateFile (filename, std::ios::out, 
                                                     PcapHelper::DLT_EN10MB);
  if (promiscuous)
    {
      pcapHelper.HookDefaultSink<SwitchedEthernetNetDevice> (device, "PromiscSniffer", file);
    }
  else
    {
      pcapHelper.HookDefaultSink<SwitchedEthernetNetDevice> (device, "Sniffer", file);
    }
}

void 
SwitchedEthernetHelper::EnableAsciiInternal (
  Ptr<OutputStreamWrapper> stream, 
  std::string prefix, 
  Ptr<NetDevice> nd,
  bool explicitFilename)
{
  //
  // All of the ascii enable functions vector through here including the ones
  // that are wandering through all of devices on perhaps all of the nodes in
  // the system.  We can only deal with devices of type SwitchedEthernetNetDevice.
  //
  Ptr<SwitchedEthernetNetDevice> device = nd->GetObject<SwitchedEthernetNetDevice> ();
  if (device == 0)
    {
      NS_LOG_INFO ("SwitchedEthernetHelper::EnableAsciiInternal(): Device " << device << " not of type ns3::SwitchedEthernetNetDevice");
      return;
    }

  //
  // Our default trace sinks are going to use packet printing, so we have to 
  // make sure that is turned on.
  //
  Packet::EnablePrinting ();

  //
  // If we are not provided an OutputStreamWrapper, we are expected to create 
  // one using the usual trace filename conventions and do a Hook*WithoutContext
  // since there will be one file per context and therefore the context would
  // be redundant.
  //
  if (stream == 0)
    {
      //
      // Set up an output stream object to deal with private ofstream copy 
      // constructor and lifetime issues.  Let the helper decide the actual
      // name of the file given the prefix.
      //
      AsciiTraceHelper asciiTraceHelper;

      std::string filename;
      if (explicitFilename)
        {
          filename = prefix;
        }
      else
        {
          filename = asciiTraceHelper.GetFilenameFromDevice (prefix, device);
        }

      Ptr<OutputStreamWrapper> theStream = asciiTraceHelper.CreateFileStream (filename);

      //
      // The MacRx trace source provides our "r" event.
      //
      asciiTraceHelper.HookDefaultReceiveSinkWithoutContext<SwitchedEthernetNetDevice> (device, "MacRx", theStream);

      //
      // The "+", '-', and 'd' events are driven by trace sources actually in the
      // transmit queue.
      //
      Ptr<Queue> queue = device->GetQueue ();
      asciiTraceHelper.HookDefaultEnqueueSinkWithoutContext<Queue> (queue, "Enqueue", theStream);
      asciiTraceHelper.HookDefaultDropSinkWithoutContext<Queue> (queue, "Drop", theStream);
      asciiTraceHelper.HookDefaultDequeueSinkWithoutContext<Queue> (queue, "Dequeue", theStream);

      return;
    }

  //
  // If we are provided an OutputStreamWrapper, we are expected to use it, and
  // to provide a context.  We are free to come up with our own context if we
  // want, and use the AsciiTraceHelper Hook*WithContext functions, but for 
  // compatibility and simplicity, we just use Config::Connect and let it deal
  // with the context.
  //
  // Note that we are going to use the default trace sinks provided by the 
  // ascii trace helper.  There is actually no AsciiTraceHelper in sight here,
  // but the default trace sinks are actually publicly available static 
  // functions that are always there waiting for just such a case.
  //
  uint32_t nodeid = nd->GetNode ()->GetId ();
  uint32_t deviceid = nd->GetIfIndex ();
  std::ostringstream oss;

  oss << "/NodeList/" << nd->GetNode ()->GetId () << "/DeviceList/" << deviceid << "/$ns3::SwitchedEthernetNetDevice/MacRx";
  Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultReceiveSinkWithContext, stream));

  oss.str ("");
  oss << "/NodeList/" << nodeid << "/DeviceList/" << deviceid << "/$ns3::SwitchedEthernetNetDevice/TxQueue/Enqueue";
  Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultEnqueueSinkWithContext, stream));

  oss.str ("");
  oss << "/NodeList/" << nodeid << "/DeviceList/" << deviceid << "/$ns3::SwitchedEthernetNetDevice/TxQueue/Dequeue";
  Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultDequeueSinkWithContext, stream));

  oss.str ("");
  oss << "/NodeList/" << nodeid << "/DeviceList/" << deviceid << "/$ns3::SwitchedEthernetNetDevice/TxQueue/Drop";
  Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultDropSinkWithContext, stream));
}

NetDeviceContainer
SwitchedEthernetHelper::Install (Ptr<Node> node) const
{
  Ptr<SwitchedEthernetChannel> channel = m_channelFactory.Create ()->GetObject<SwitchedEthernetChannel> ();
  return Install (node, channel);
}

NetDeviceContainer
SwitchedEthernetHelper::Install (std::string nodeName) const
{
  Ptr<Node> node = Names::Find<Node> (nodeName);
  return Install (node);
}

NetDeviceContainer
SwitchedEthernetHelper::Install (Ptr<Node> node, Ptr<SwitchedEthernetChannel> channel) const
{
  return NetDeviceContainer (InstallPriv (node, channel));
}

NetDeviceContainer
SwitchedEthernetHelper::Install (Ptr<Node> node, std::string channelName) const
{
  Ptr<SwitchedEthernetChannel> channel = Names::Find<SwitchedEthernetChannel> (channelName);
  return NetDeviceContainer (InstallPriv (node, channel));
}

NetDeviceContainer
SwitchedEthernetHelper::Install (std::string nodeName, Ptr<SwitchedEthernetChannel> channel) const
{
  Ptr<Node> node = Names::Find<Node> (nodeName);
  return NetDeviceContainer (InstallPriv (node, channel));
}

NetDeviceContainer
SwitchedEthernetHelper::Install (std::string nodeName, std::string channelName) const
{
  Ptr<Node> node = Names::Find<Node> (nodeName);
  Ptr<SwitchedEthernetChannel> channel = Names::Find<SwitchedEthernetChannel> (channelName);
  return NetDeviceContainer (InstallPriv (node, channel));
}

NetDeviceContainer 
SwitchedEthernetHelper::Install (const NodeContainer &c) const
{
  Ptr<SwitchedEthernetChannel> channel = m_channelFactory.Create ()->GetObject<SwitchedEthernetChannel> ();

  return Install (c, channel);
}

NetDeviceContainer 
SwitchedEthernetHelper::Install (const NodeContainer &c, Ptr<SwitchedEthernetChannel> channel) const
{
  NetDeviceContainer devs;

  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); i++)
    {
      devs.Add (InstallPriv (*i, channel));
    }

  return devs;
}

NetDeviceContainer 
SwitchedEthernetHelper::Install (const NodeContainer &c, std::string channelName) const
{
  Ptr<SwitchedEthernetChannel> channel = Names::Find<SwitchedEthernetChannel> (channelName);
  return Install (c, channel);
}

Ptr<NetDevice>
SwitchedEthernetHelper::InstallPriv (Ptr<Node> node, Ptr<SwitchedEthernetChannel> channel) const
{
  Ptr<SwitchedEthernetNetDevice> device = m_deviceFactory.Create<SwitchedEthernetNetDevice> ();
  device->SetAddress (Mac48Address::Allocate ());
  node->AddDevice (device);
  Ptr<Queue> queue = m_queueFactory.Create<Queue> ();
  device->SetQueue (queue);
  device->Attach (channel);

  return device;
}

} // namespace ns3
