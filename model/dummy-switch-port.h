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

#ifndef DUMMY_SWITCH_PORT_H
#define DUMMY_SWITCH_PORT_H

#include "ns3/net-device.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/queue-disc.h"

namespace ns3
{

/**
 * \ingroup p4sim
 * \brief Represents a single port on a DummySwitchNetDevice.
 *
 * DummySwitchPort wraps an underlying ns-3 NetDevice (e.g. CsmaNetDevice,
 * PointToPointNetDevice) and adds an optional egress Traffic Manager (QueueDisc)
 * slot. When a QueueDisc is attached, egress packets are enqueued into it;
 * otherwise they are forwarded directly to the underlying NetDevice.
 */
class DummySwitchPort : public Object
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();

    DummySwitchPort();
    ~DummySwitchPort() override;

    /**
     * \brief Set the underlying NetDevice for this port.
     * \param device the NetDevice to attach
     */
    void SetNetDevice(Ptr<NetDevice> device);

    /**
     * \brief Get the underlying NetDevice.
     * \return the NetDevice attached to this port
     */
    Ptr<NetDevice> GetNetDevice() const;

    /**
     * \brief Set the port index.
     * \param portId the port index on the switch
     */
    void SetPortId(uint32_t portId);

    /**
     * \brief Get the port index.
     * \return the port index on the switch
     */
    uint32_t GetPortId() const;

    /**
     * \brief Attach a traffic manager (QueueDisc) to this egress port.
     * \param qdisc the QueueDisc to use for egress traffic management
     */
    void SetTrafficManager(Ptr<QueueDisc> qdisc);

    /**
     * \brief Get the traffic manager attached to this port.
     * \return the QueueDisc, or nullptr if none is attached
     */
    Ptr<QueueDisc> GetTrafficManager() const;

    /**
     * \brief Check whether this port has a traffic manager attached.
     * \return true if a QueueDisc is attached
     */
    bool HasTrafficManager() const;

    /**
     * \brief Set the administrative up/down state of this port.
     * \param isUp true to set port up, false to set port down
     */
    void SetPortUp(bool isUp);

    /**
     * \brief Check whether this port is administratively up.
     * \return true if port is up
     */
    bool IsPortUp() const;

    /**
     * \brief Enqueue a packet for egress on this port.
     *
     * If a traffic manager is attached, the packet is enqueued into
     * the QueueDisc. Otherwise, it is sent directly on the underlying
     * NetDevice.
     *
     * \param packet the packet to send
     * \param dest the destination address
     * \param protocolNumber the protocol number
     * \return true if successfully enqueued or sent
     */
    bool EnqueueEgress(Ptr<Packet> packet,
                       const Address& dest,
                       uint16_t protocolNumber);

  protected:
    void DoDispose() override;

  private:
    /**
     * \brief Transmit a packet from the queue onto the underlying NetDevice.
     *
     * This is the callback invoked when the QueueDisc dequeues a packet.
     */
    void TransmitFromQueue();

    Ptr<NetDevice> m_netDevice; //!< The underlying ns-3 NetDevice
    uint32_t m_portId;          //!< Port index on the switch
    Ptr<QueueDisc> m_egressTm;  //!< Optional egress traffic manager (QueueDisc)
    bool m_isUp;                //!< Administrative up/down state
};

} // namespace ns3

#endif /* DUMMY_SWITCH_PORT_H */
