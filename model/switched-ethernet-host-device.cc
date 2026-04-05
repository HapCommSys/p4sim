/*
 * Copyright (c) 2025 TU Dresden
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
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#include "switched-ethernet-host-device.h"

#include "switched-ethernet-channel.h"

#include "ns3/ethernet-header.h"
#include "ns3/log.h"
#include "ns3/mac48-address.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("SwitchedEthernetHostDevice");
NS_OBJECT_ENSURE_REGISTERED(SwitchedEthernetHostDevice);

TypeId
SwitchedEthernetHostDevice::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::SwitchedEthernetHostDevice")
            .SetParent<NetDevice>()
            .SetGroupName("P4sim")
            .AddConstructor<SwitchedEthernetHostDevice>()
            .AddAttribute("Mtu",
                          "Maximum Transmission Unit.",
                          UintegerValue(1500),
                          MakeUintegerAccessor(&SwitchedEthernetHostDevice::SetMtu,
                                               &SwitchedEthernetHostDevice::GetMtu),
                          MakeUintegerChecker<uint16_t>())
            .AddTraceSource("MacTx",
                            "A packet is queued for transmission by this device.",
                            MakeTraceSourceAccessor(&SwitchedEthernetHostDevice::m_macTxTrace),
                            "ns3::Packet::TracedCallback")
            .AddTraceSource("MacRx",
                            "A packet has been received and is being delivered up the stack.",
                            MakeTraceSourceAccessor(&SwitchedEthernetHostDevice::m_macRxTrace),
                            "ns3::Packet::TracedCallback")
            .AddTraceSource("MacTxDrop",
                            "A packet was dropped before transmission.",
                            MakeTraceSourceAccessor(&SwitchedEthernetHostDevice::m_macTxDropTrace),
                            "ns3::Packet::TracedCallback");
    return tid;
}

SwitchedEthernetHostDevice::SwitchedEthernetHostDevice()
{
    NS_LOG_FUNCTION_NOARGS();
}

SwitchedEthernetHostDevice::~SwitchedEthernetHostDevice()
{
    NS_LOG_FUNCTION_NOARGS();
}

// ---------------------------------------------------------------------------
// Channel attachment
// ---------------------------------------------------------------------------

void
SwitchedEthernetHostDevice::Attach(Ptr<SwitchedEthernetChannel> channel)
{
    NS_LOG_FUNCTION(this << channel);
    NS_ASSERT_MSG(channel, "Attach: null channel");
    NS_ASSERT_MSG(!m_channel, "Attach: already attached to a channel");

    int32_t id = channel->AttachHost(this);
    NS_ASSERT_MSG(id >= 0, "Attach: channel rejected host device");
    m_channel = channel;
    m_devId = static_cast<uint32_t>(id);
}

// ---------------------------------------------------------------------------
// Receive (called by SwitchedEthernetChannel after propagation delay)
// ---------------------------------------------------------------------------

void
SwitchedEthernetHostDevice::ReceiveFrame(Ptr<Packet> frame)
{
    NS_LOG_FUNCTION(this << frame);

    EthernetHeader eth;
    frame->PeekHeader(eth);
    Mac48Address dst = eth.GetDestination();
    Mac48Address src = eth.GetSource();
    uint16_t proto = eth.GetLengthType();

    // Accept unicast-to-us, broadcast, and multicast.
    if (dst != m_address && dst != Mac48Address::GetBroadcast() && !dst.IsGroup())
    {
        NS_LOG_DEBUG("ReceiveFrame: dst " << dst << " != our MAC " << m_address << " — drop");
        return;
    }

    m_macRxTrace(frame);

    if (!m_promiscRxCallback.IsNull())
    {
        m_promiscRxCallback(this, frame->Copy(), proto, src, dst, PACKET_OTHERHOST);
    }

    Ptr<Packet> stripped = frame->Copy();
    EthernetHeader hdr;
    stripped->RemoveHeader(hdr);

    if (!m_rxCallback.IsNull())
    {
        m_rxCallback(this, stripped, proto, src);
    }
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

bool
SwitchedEthernetHostDevice::Send(Ptr<Packet> packet,
                                  const Address& dest,
                                  uint16_t protocolNumber)
{
    return SendFrom(packet, m_address, dest, protocolNumber);
}

bool
SwitchedEthernetHostDevice::SendFrom(Ptr<Packet> packet,
                                      const Address& source,
                                      const Address& dest,
                                      uint16_t protocolNumber)
{
    NS_LOG_FUNCTION(this << packet << dest << protocolNumber);

    if (!m_channel)
    {
        NS_LOG_WARN("SendFrom: device not attached to channel — drop");
        m_macTxDropTrace(packet);
        return false;
    }

    EthernetHeader eth;
    eth.SetSource(Mac48Address::ConvertFrom(source));
    eth.SetDestination(Mac48Address::ConvertFrom(dest));
    eth.SetLengthType(protocolNumber);
    packet->AddHeader(eth);

    m_macTxTrace(packet);

    if (!m_channel->TransmitStart(packet, m_devId))
    {
        NS_LOG_WARN("SendFrom: channel busy — drop");
        m_macTxDropTrace(packet);
        return false;
    }

    DataRate rate = m_channel->GetDataRate();
    Time txTime = rate.CalculateBytesTxTime(packet->GetSize());
    Simulator::Schedule(txTime, &SwitchedEthernetChannel::TransmitEnd, m_channel, m_devId);
    return true;
}

// ---------------------------------------------------------------------------
// NetDevice interface
// ---------------------------------------------------------------------------

void
SwitchedEthernetHostDevice::SetIfIndex(const uint32_t index)
{
    m_ifIndex = index;
}

uint32_t
SwitchedEthernetHostDevice::GetIfIndex() const
{
    return m_ifIndex;
}

Ptr<Channel>
SwitchedEthernetHostDevice::GetChannel() const
{
    return m_channel;
}

void
SwitchedEthernetHostDevice::SetAddress(Address address)
{
    m_address = Mac48Address::ConvertFrom(address);
}

Address
SwitchedEthernetHostDevice::GetAddress() const
{
    return m_address;
}

bool
SwitchedEthernetHostDevice::SetMtu(const uint16_t mtu)
{
    m_mtu = mtu;
    return true;
}

uint16_t
SwitchedEthernetHostDevice::GetMtu() const
{
    return m_mtu;
}

bool
SwitchedEthernetHostDevice::IsLinkUp() const
{
    return m_channel != nullptr;
}

void
SwitchedEthernetHostDevice::AddLinkChangeCallback(Callback<void> /*callback*/)
{
}

bool
SwitchedEthernetHostDevice::IsBroadcast() const
{
    return true;
}

Address
SwitchedEthernetHostDevice::GetBroadcast() const
{
    return Mac48Address::GetBroadcast();
}

bool
SwitchedEthernetHostDevice::IsMulticast() const
{
    return true;
}

Address
SwitchedEthernetHostDevice::GetMulticast(Ipv4Address multicastGroup) const
{
    return Mac48Address::GetMulticast(multicastGroup);
}

Address
SwitchedEthernetHostDevice::GetMulticast(Ipv6Address addr) const
{
    return Mac48Address::GetMulticast(addr);
}

bool
SwitchedEthernetHostDevice::IsPointToPoint() const
{
    return false;
}

bool
SwitchedEthernetHostDevice::IsBridge() const
{
    return false;
}

Ptr<Node>
SwitchedEthernetHostDevice::GetNode() const
{
    return m_node;
}

void
SwitchedEthernetHostDevice::SetNode(Ptr<Node> n)
{
    m_node = n;
}

bool
SwitchedEthernetHostDevice::NeedsArp() const
{
    return true;
}

void
SwitchedEthernetHostDevice::SetReceiveCallback(NetDevice::ReceiveCallback cb)
{
    m_rxCallback = cb;
}

void
SwitchedEthernetHostDevice::SetPromiscReceiveCallback(NetDevice::PromiscReceiveCallback cb)
{
    m_promiscRxCallback = cb;
}

bool
SwitchedEthernetHostDevice::SupportsSendFrom() const
{
    return true;
}

} // namespace ns3
