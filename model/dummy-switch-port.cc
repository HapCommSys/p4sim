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
#include "ns3/queue-item.h"
#include "ns3/uinteger.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("DummySwitchPort");
NS_OBJECT_ENSURE_REGISTERED(DummySwitchPort);

// =============================================================================
// DummySwitchQueueItem — concrete QueueDiscItem for L2 switch forwarding
// =============================================================================

/**
 * \brief A minimal concrete QueueDiscItem for use in DummySwitchPort.
 *
 * ns3::QueueDiscItem is abstract (pure virtual AddHeader() and Mark()).
 * This subclass provides trivial implementations since the dummy switch
 * operates at L2 and does not need to manipulate headers or support ECN
 * marking.
 */
class DummySwitchQueueItem : public QueueDiscItem
{
  public:
    /**
     * \brief Construct a DummySwitchQueueItem.
     * \param p       the packet
     * \param addr    the destination MAC address
     * \param protocol the L3 protocol number (EtherType)
     */
    DummySwitchQueueItem(Ptr<Packet> p, const Address& addr, uint16_t protocol)
        : QueueDiscItem(p, addr, protocol)
    {
    }

    /** No header manipulation needed for L2 forwarding. */
    void AddHeader() override
    {
    }

    /**
     * \brief ECN marking is not supported by the dummy switch.
     * \return always false
     */
    bool Mark() override
    {
        return false;
    }
};

// =============================================================================
// DummySwitchPort implementation
// =============================================================================

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
    if (qdisc && !qdisc->IsInitialized())
    {
        qdisc->Initialize();
    }
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
        // Wrap packet in a QueueDiscItem and enqueue through the traffic manager
        Ptr<DummySwitchQueueItem> item =
            Create<DummySwitchQueueItem>(packet, dest, protocolNumber);

        NS_LOG_DEBUG("Port " << m_portId << ": enqueueing packet (size "
                             << packet->GetSize() << ") into traffic manager ("
                             << m_egressTm->GetInstanceTypeId().GetName() << ")");

        bool enqueued = m_egressTm->Enqueue(item);
        if (!enqueued)
        {
            NS_LOG_DEBUG("Port " << m_portId
                                 << ": traffic manager dropped packet (queue full)");
            return false;
        }

        // Immediately try to dequeue and transmit
        TransmitFromQueue();
        return true;
    }

    // No traffic manager — send directly on the underlying NetDevice
    NS_LOG_DEBUG("Port " << m_portId << ": sending packet (size "
                         << packet->GetSize() << ") on "
                         << m_netDevice->GetInstanceTypeId().GetName());

    return m_netDevice->Send(packet, dest, protocolNumber);
}

void
DummySwitchPort::TransmitFromQueue()
{
    NS_LOG_FUNCTION(this);

    if (!m_egressTm || !m_netDevice)
    {
        return;
    }

    // Dequeue all available packets and transmit them
    Ptr<QueueDiscItem> item = m_egressTm->Dequeue();
    while (item)
    {
        Ptr<Packet> packet = item->GetPacket();
        Address dest = item->GetAddress();
        uint16_t protocol = item->GetProtocol();

        NS_LOG_DEBUG("Port " << m_portId << ": dequeued packet (size "
                             << packet->GetSize() << ") from traffic manager");

        m_netDevice->Send(packet, dest, protocol);
        item = m_egressTm->Dequeue();
    }
}

} // namespace ns3
