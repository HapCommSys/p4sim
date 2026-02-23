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

#include "ns3/dummy-switch-net-device.h"

#include "ns3/boolean.h"
#include "ns3/channel.h"
#include "ns3/ethernet-header.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("DummySwitchNetDevice");
NS_OBJECT_ENSURE_REGISTERED(DummySwitchNetDevice);

TypeId
DummySwitchNetDevice::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::DummySwitchNetDevice")
            .SetParent<NetDevice>()
            .SetGroupName("P4sim")
            .AddConstructor<DummySwitchNetDevice>()

            .AddAttribute("Mtu",
                          "The MAC-level Maximum Transmission Unit",
                          UintegerValue(1500),
                          MakeUintegerAccessor(&DummySwitchNetDevice::SetMtu,
                                              &DummySwitchNetDevice::GetMtu),
                          MakeUintegerChecker<uint16_t>())

            .AddTraceSource("Rx",
                            "A packet received by the dummy switch",
                            MakeTraceSourceAccessor(&DummySwitchNetDevice::m_rxTrace),
                            "ns3::Packet::TracedCallback")

            .AddTraceSource("Tx",
                            "A packet transmitted by the dummy switch",
                            MakeTraceSourceAccessor(&DummySwitchNetDevice::m_txTrace),
                            "ns3::Packet::TracedCallback");

    return tid;
}

DummySwitchNetDevice::DummySwitchNetDevice()
    : m_node(nullptr),
      m_ifIndex(0),
      m_mtu(1500)
{
    NS_LOG_FUNCTION(this);
    m_channel = CreateObject<P4BridgeChannel>();
}

DummySwitchNetDevice::~DummySwitchNetDevice()
{
    NS_LOG_FUNCTION(this);
}

void
DummySwitchNetDevice::DoInitialize()
{
    NS_LOG_FUNCTION(this);
    NS_LOG_INFO("DummySwitchNetDevice initialized with " << m_ports.size() << " ports");
    NetDevice::DoInitialize();
}

void
DummySwitchNetDevice::DoDispose()
{
    NS_LOG_FUNCTION(this);
    for (auto& port : m_ports)
    {
        port = nullptr;
    }
    m_ports.clear();
    m_channel = nullptr;
    m_node = nullptr;
    NetDevice::DoDispose();
}

// =============================================================================
// Port management
// =============================================================================

uint32_t
DummySwitchNetDevice::AddPort(Ptr<NetDevice> portDevice)
{
    NS_LOG_FUNCTION(this << portDevice);
    NS_ASSERT(portDevice != this);

    if (!Mac48Address::IsMatchingType(portDevice->GetAddress()))
    {
        NS_FATAL_ERROR("Device does not support EUI-48 addresses: cannot be added to switch.");
    }
    if (!portDevice->SupportsSendFrom())
    {
        NS_FATAL_ERROR("Device does not support SendFrom: cannot be added to switch.");
    }

    // Adopt the MAC of the first port added
    if (m_address == Mac48Address())
    {
        m_address = Mac48Address::ConvertFrom(portDevice->GetAddress());
    }

    // Create the port wrapper
    Ptr<DummySwitchPort> port = CreateObject<DummySwitchPort>();
    uint32_t portId = m_ports.size();
    port->SetPortId(portId);
    port->SetNetDevice(portDevice);

    // Register protocol handler on the node
    NS_LOG_DEBUG("Registering protocol handler for port " << portId
                 << " (" << portDevice->GetInstanceTypeId().GetName() << ")");

    m_node->RegisterProtocolHandler(
        MakeCallback(&DummySwitchNetDevice::ReceiveFromPort, this),
        0,
        portDevice,
        true);

    m_ports.push_back(port);
    m_channel->AddChannel(portDevice->GetChannel());

    NS_LOG_INFO("Added port " << portId << " to dummy switch ("
                              << portDevice->GetInstanceTypeId().GetName() << ")");
    return portId;
}

uint32_t
DummySwitchNetDevice::GetNPorts() const
{
    return m_ports.size();
}

Ptr<DummySwitchPort>
DummySwitchNetDevice::GetPort(uint32_t portId) const
{
    if (portId >= m_ports.size())
    {
        return nullptr;
    }
    return m_ports[portId];
}

int32_t
DummySwitchNetDevice::GetPortIdForDevice(Ptr<NetDevice> device) const
{
    for (uint32_t i = 0; i < m_ports.size(); i++)
    {
        if (m_ports[i]->GetNetDevice() == device)
        {
            return static_cast<int32_t>(i);
        }
    }
    return -1;
}

// =============================================================================
// Traffic manager configuration
// =============================================================================

bool
DummySwitchNetDevice::SetPortTrafficManager(uint32_t portId, Ptr<QueueDisc> qdisc)
{
    NS_LOG_FUNCTION(this << portId << qdisc);
    if (portId >= m_ports.size())
    {
        NS_LOG_ERROR("Port " << portId << " does not exist");
        return false;
    }
    m_ports[portId]->SetTrafficManager(qdisc);
    return true;
}

// =============================================================================
// Forwarding
// =============================================================================

void
DummySwitchNetDevice::ReceiveFromPort(Ptr<NetDevice> device,
                                      Ptr<const Packet> packet,
                                      uint16_t protocol,
                                      const Address& source,
                                      const Address& destination,
                                      PacketType packetType)
{
    NS_LOG_FUNCTION(this << device << packet << protocol << source << destination << packetType);

    int32_t inPort = GetPortIdForDevice(device);
    NS_LOG_INFO("Rx packet (uid=" << packet->GetUid()
                << ", size=" << packet->GetSize()
                << ") on port " << inPort);

    // Fire trace
    m_rxTrace(packet);

    // Promiscuous callback
    if (!m_promiscRxCallback.IsNull())
    {
        m_promiscRxCallback(this, packet, protocol, source, destination, packetType);
    }

    // Check if addressed to this switch
    Mac48Address dst48 = Mac48Address::ConvertFrom(destination);
    if (dst48 == m_address)
    {
        if (!m_rxCallback.IsNull())
        {
            m_rxCallback(this, packet, protocol, source);
        }
        return;
    }

    // === Skeleton forwarding: flood to all ports except ingress ===
    NS_LOG_DEBUG("Flooding packet to all ports except port " << inPort);
    for (uint32_t i = 0; i < m_ports.size(); i++)
    {
        if (static_cast<int32_t>(i) == inPort)
        {
            continue; // skip ingress port
        }

        Ptr<Packet> pktCopy = packet->Copy();
        SendToPort(pktCopy, i, protocol, destination);
    }
}

void
DummySwitchNetDevice::SendToPort(Ptr<Packet> packet,
                                 uint32_t egressPort,
                                 uint16_t protocolNumber,
                                 const Address& destination)
{
    NS_LOG_FUNCTION(this << packet << egressPort << protocolNumber << destination);

    if (egressPort >= m_ports.size())
    {
        NS_LOG_ERROR("Egress port " << egressPort << " out of range");
        return;
    }

    Ptr<DummySwitchPort> port = m_ports[egressPort];
    if (!port->IsPortUp())
    {
        NS_LOG_DEBUG("Egress port " << egressPort << " is down, dropping");
        return;
    }

    NS_LOG_DEBUG("Tx packet (size=" << packet->GetSize()
                 << ") to port " << egressPort);

    // Fire trace
    m_txTrace(packet);

    port->EnqueueEgress(packet, destination, protocolNumber);
}

// =============================================================================
// NetDevice interface
// =============================================================================

void
DummySwitchNetDevice::SetIfIndex(const uint32_t index)
{
    m_ifIndex = index;
}

uint32_t
DummySwitchNetDevice::GetIfIndex() const
{
    return m_ifIndex;
}

Ptr<Channel>
DummySwitchNetDevice::GetChannel() const
{
    return m_channel;
}

void
DummySwitchNetDevice::SetAddress(Address address)
{
    m_address = Mac48Address::ConvertFrom(address);
}

Address
DummySwitchNetDevice::GetAddress() const
{
    return m_address;
}

bool
DummySwitchNetDevice::SetMtu(const uint16_t mtu)
{
    m_mtu = mtu;
    return true;
}

uint16_t
DummySwitchNetDevice::GetMtu() const
{
    return m_mtu;
}

bool
DummySwitchNetDevice::IsLinkUp() const
{
    return true;
}

void
DummySwitchNetDevice::AddLinkChangeCallback(Callback<void> callback)
{
    // Not implemented for skeleton
}

bool
DummySwitchNetDevice::IsBroadcast() const
{
    return true;
}

Address
DummySwitchNetDevice::GetBroadcast() const
{
    return Mac48Address::GetBroadcast();
}

bool
DummySwitchNetDevice::IsMulticast() const
{
    return true;
}

Address
DummySwitchNetDevice::GetMulticast(Ipv4Address multicastGroup) const
{
    return Mac48Address::GetMulticast(multicastGroup);
}

Address
DummySwitchNetDevice::GetMulticast(Ipv6Address addr) const
{
    return Mac48Address::GetMulticast(addr);
}

bool
DummySwitchNetDevice::IsPointToPoint() const
{
    return false;
}

bool
DummySwitchNetDevice::IsBridge() const
{
    return true;
}

bool
DummySwitchNetDevice::Send(Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber)
{
    NS_LOG_FUNCTION(this << packet << dest << protocolNumber);
    return SendFrom(packet, m_address, dest, protocolNumber);
}

bool
DummySwitchNetDevice::SendFrom(Ptr<Packet> packet,
                               const Address& source,
                               const Address& dest,
                               uint16_t protocolNumber)
{
    NS_LOG_FUNCTION(this << packet << source << dest << protocolNumber);

    // Flood to all ports
    for (uint32_t i = 0; i < m_ports.size(); i++)
    {
        Ptr<Packet> pktCopy = packet->Copy();
        Ptr<NetDevice> portDev = m_ports[i]->GetNetDevice();
        portDev->SendFrom(pktCopy, source, dest, protocolNumber);
    }
    return true;
}

Ptr<Node>
DummySwitchNetDevice::GetNode() const
{
    return m_node;
}

void
DummySwitchNetDevice::SetNode(Ptr<Node> node)
{
    m_node = node;
}

bool
DummySwitchNetDevice::NeedsArp() const
{
    return true;
}

void
DummySwitchNetDevice::SetReceiveCallback(NetDevice::ReceiveCallback cb)
{
    m_rxCallback = cb;
}

void
DummySwitchNetDevice::SetPromiscReceiveCallback(NetDevice::PromiscReceiveCallback cb)
{
    m_promiscRxCallback = cb;
}

bool
DummySwitchNetDevice::SupportsSendFrom() const
{
    return true;
}

} // namespace ns3
