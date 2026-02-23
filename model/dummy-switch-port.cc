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

#include "ns3/dummy-switch-port.h"

#include "ns3/log.h"
#include "ns3/queue-disc.h"
#include "ns3/uinteger.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("DummySwitchPort");
NS_OBJECT_ENSURE_REGISTERED(DummySwitchPort);

TypeId
DummySwitchPort::GetTypeId()
{
    static TypeId tid = TypeId("ns3::DummySwitchPort")
                            .SetParent<Object>()
                            .SetGroupName("P4sim")
                            .AddConstructor<DummySwitchPort>();
    return tid;
}

DummySwitchPort::DummySwitchPort()
    : m_netDevice(nullptr),
      m_portId(0),
      m_egressTm(nullptr),
      m_isUp(true)
{
    NS_LOG_FUNCTION(this);
}

DummySwitchPort::~DummySwitchPort()
{
    NS_LOG_FUNCTION(this);
}

void
DummySwitchPort::DoDispose()
{
    NS_LOG_FUNCTION(this);
    m_netDevice = nullptr;
    m_egressTm = nullptr;
    Object::DoDispose();
}

void
DummySwitchPort::SetNetDevice(Ptr<NetDevice> device)
{
    NS_LOG_FUNCTION(this << device);
    m_netDevice = device;
}

Ptr<NetDevice>
DummySwitchPort::GetNetDevice() const
{
    return m_netDevice;
}

void
DummySwitchPort::SetPortId(uint32_t portId)
{
    NS_LOG_FUNCTION(this << portId);
    m_portId = portId;
}

uint32_t
DummySwitchPort::GetPortId() const
{
    return m_portId;
}

void
DummySwitchPort::SetTrafficManager(Ptr<QueueDisc> qdisc)
{
    NS_LOG_FUNCTION(this << qdisc);
    m_egressTm = qdisc;
    NS_LOG_INFO("Port " << m_portId << ": Traffic manager "
                        << (qdisc ? "attached" : "detached"));
}

Ptr<QueueDisc>
DummySwitchPort::GetTrafficManager() const
{
    return m_egressTm;
}

bool
DummySwitchPort::HasTrafficManager() const
{
    return (m_egressTm != nullptr);
}

void
DummySwitchPort::SetPortUp(bool isUp)
{
    NS_LOG_FUNCTION(this << isUp);
    m_isUp = isUp;
}

bool
DummySwitchPort::IsPortUp() const
{
    return m_isUp;
}

bool
DummySwitchPort::EnqueueEgress(Ptr<Packet> packet,
                               const Address& dest,
                               uint16_t protocolNumber)
{
    NS_LOG_FUNCTION(this << packet << dest << protocolNumber);

    if (!m_isUp)
    {
        NS_LOG_DEBUG("Port " << m_portId << " is down, dropping packet");
        return false;
    }

    if (!m_netDevice)
    {
        NS_LOG_ERROR("Port " << m_portId << " has no underlying NetDevice");
        return false;
    }

    if (m_egressTm)
    {
        // Enqueue through the traffic manager
        NS_LOG_DEBUG("Port " << m_portId << ": enqueueing packet (size "
                             << packet->GetSize() << ") into traffic manager");
        // NOTE: Full QueueDisc integration requires QueueDiscItem wrapping.
        // For the skeleton, we bypass the TM and send directly, but log
        // that the TM is present.
        NS_LOG_INFO("Port " << m_portId << ": TM present ("
                            << m_egressTm->GetInstanceTypeId().GetName()
                            << "), forwarding packet directly for now");
    }

    // Send directly on the underlying NetDevice
    NS_LOG_DEBUG("Port " << m_portId << ": sending packet (size "
                         << packet->GetSize() << ") on " 
                         << m_netDevice->GetInstanceTypeId().GetName());

    return m_netDevice->Send(packet, dest, protocolNumber);
}

void
DummySwitchPort::TransmitFromQueue()
{
    NS_LOG_FUNCTION(this);
    // Placeholder: will be used when full QueueDisc integration is implemented.
    // The QueueDisc dequeue callback would invoke this method to actually
    // transmit the packet on the underlying NetDevice.
    NS_LOG_DEBUG("Port " << m_portId << ": TransmitFromQueue called (placeholder)");
}

} // namespace ns3
