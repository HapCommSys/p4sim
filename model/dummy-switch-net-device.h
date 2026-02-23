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

#ifndef DUMMY_SWITCH_NET_DEVICE_H
#define DUMMY_SWITCH_NET_DEVICE_H

#include "ns3/dummy-switch-port.h"
#include "ns3/mac48-address.h"
#include "ns3/net-device.h"
#include "ns3/p4-bridge-channel.h"
#include "ns3/traced-callback.h"

#include <string>
#include <vector>

namespace ns3
{

class Node;

/**
 * \ingroup p4sim
 * \brief A skeleton dummy switch NetDevice for the P4sim Plan A architecture.
 *
 * DummySwitchNetDevice implements a minimal multi-port switch following the
 * bridge pattern used by ns3::BridgeNetDevice and ns3::P4SwitchNetDevice.
 * Each port is wrapped in a DummySwitchPort object that supports an optional
 * egress Traffic Manager (QueueDisc).
 *
 * This skeleton does not contain any real packet processing logic — it
 * performs simple learning-bridge-style forwarding (flood if destination
 * unknown). It serves as the architectural starting point for the full
 * P4 switch implementation.
 */
class DummySwitchNetDevice : public NetDevice
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();

    DummySwitchNetDevice();
    ~DummySwitchNetDevice() override;

    // Delete copy constructor and assignment operator
    DummySwitchNetDevice(const DummySwitchNetDevice&) = delete;
    DummySwitchNetDevice& operator=(const DummySwitchNetDevice&) = delete;

    // === Port management ===

    /**
     * \brief Add a port to the switch.
     *
     * Wraps the given NetDevice in a DummySwitchPort and registers
     * a protocol handler to receive frames from it.
     *
     * \param portDevice the NetDevice to add as a switch port
     * \return the port index assigned to this device
     */
    uint32_t AddPort(Ptr<NetDevice> portDevice);

    /**
     * \brief Get the number of ports on this switch.
     * \return the number of ports
     */
    uint32_t GetNPorts() const;

    /**
     * \brief Get a port by its index.
     * \param portId the port index
     * \return the DummySwitchPort, or nullptr if index out of range
     */
    Ptr<DummySwitchPort> GetPort(uint32_t portId) const;

    /**
     * \brief Get the port index for a given NetDevice.
     * \param device the NetDevice to look up
     * \return the port index, or -1 if not found
     */
    int32_t GetPortIdForDevice(Ptr<NetDevice> device) const;

    // === Traffic Manager configuration ===

    /**
     * \brief Attach a traffic manager (QueueDisc) to a specific egress port.
     * \param portId the port index
     * \param qdisc the QueueDisc to attach
     * \return true if successfully attached
     */
    bool SetPortTrafficManager(uint32_t portId, Ptr<QueueDisc> qdisc);

    // === Forwarding ===

    /**
     * \brief Send a packet out a specific port.
     *
     * Delegates to the port's EnqueueEgress method, which may
     * pass through a traffic manager if one is attached.
     *
     * \param packet the packet to send
     * \param egressPort the egress port index
     * \param protocolNumber the protocol number
     * \param destination the destination address
     */
    void SendToPort(Ptr<Packet> packet,
                    uint32_t egressPort,
                    uint16_t protocolNumber,
                    const Address& destination);

    // === NetDevice interface overrides ===
    void SetIfIndex(const uint32_t index) override;
    uint32_t GetIfIndex() const override;
    Ptr<Channel> GetChannel() const override;
    void SetAddress(Address address) override;
    Address GetAddress() const override;
    bool SetMtu(const uint16_t mtu) override;
    uint16_t GetMtu() const override;
    bool IsLinkUp() const override;
    void AddLinkChangeCallback(Callback<void> callback) override;
    bool IsBroadcast() const override;
    Address GetBroadcast() const override;
    bool IsMulticast() const override;
    Address GetMulticast(Ipv4Address multicastGroup) const override;
    Address GetMulticast(Ipv6Address addr) const override;
    bool IsPointToPoint() const override;
    bool IsBridge() const override;
    bool Send(Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber) override;
    bool SendFrom(Ptr<Packet> packet,
                  const Address& source,
                  const Address& dest,
                  uint16_t protocolNumber) override;
    Ptr<Node> GetNode() const override;
    void SetNode(Ptr<Node> node) override;
    bool NeedsArp() const override;
    void SetReceiveCallback(NetDevice::ReceiveCallback cb) override;
    void SetPromiscReceiveCallback(NetDevice::PromiscReceiveCallback cb) override;
    bool SupportsSendFrom() const override;

  protected:
    void DoInitialize() override;
    void DoDispose() override;

    /**
     * \brief Handle a packet received from one of the switch ports.
     *
     * In the skeleton, this performs simple flood-based forwarding:
     * the packet is sent out all ports except the ingress port.
     *
     * \param device the originating port NetDevice
     * \param packet the received packet
     * \param protocol the packet protocol
     * \param source the source address
     * \param destination the destination address
     * \param packetType the packet type
     */
    void ReceiveFromPort(Ptr<NetDevice> device,
                         Ptr<const Packet> packet,
                         uint16_t protocol,
                         const Address& source,
                         const Address& destination,
                         PacketType packetType);

  private:
    // === Port storage ===
    std::vector<Ptr<DummySwitchPort>> m_ports; //!< List of switch ports

    // === Network device information ===
    Mac48Address m_address;              //!< MAC address of switch
    Ptr<Node> m_node;                    //!< Node that owns this NetDevice
    Ptr<P4BridgeChannel> m_channel;      //!< Virtual bridge channel
    uint32_t m_ifIndex;                  //!< Interface index
    uint16_t m_mtu;                      //!< MTU

    // === Callbacks ===
    NetDevice::ReceiveCallback m_rxCallback;               //!< Receive callback
    NetDevice::PromiscReceiveCallback m_promiscRxCallback;  //!< Promiscuous receive callback

    // === Trace sources ===
    TracedCallback<Ptr<const Packet>> m_rxTrace;   //!< Rx trace
    TracedCallback<Ptr<const Packet>> m_txTrace;   //!< Tx trace
};

} // namespace ns3

#endif /* DUMMY_SWITCH_NET_DEVICE_H */
