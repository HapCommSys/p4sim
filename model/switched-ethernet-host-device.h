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

#ifndef SWITCHED_ETHERNET_HOST_DEVICE_H
#define SWITCHED_ETHERNET_HOST_DEVICE_H

#include "ns3/mac48-address.h"
#include "ns3/net-device.h"
#include "ns3/traced-callback.h"

namespace ns3
{

class SwitchedEthernetChannel;

/**
 * \ingroup p4sim
 *
 * \brief Plain Ethernet host device for the host side of a SwitchedEthernetChannel.
 *
 * Used to connect a regular (non-P4) host node to a P4SwitchNetDevice via a
 * SwitchedEthernetChannel.  On the wire the link carries full Ethernet frames;
 * this device strips/adds the Ethernet header when handing off to/from the
 * IP stack, exactly like a CsmaNetDevice.
 *
 * Typical setup via P4Helper:
 * \code
 *   NetDeviceContainer devs = p4.Install(switchNode, hosts);
 *   // devs[0] = P4SwitchNetDevice on switchNode
 *   // devs[1] = SwitchedEthernetHostDevice on hosts[0]
 *   // devs[2] = SwitchedEthernetHostDevice on hosts[1]
 * \endcode
 */
class SwitchedEthernetHostDevice : public NetDevice
{
  public:
    static TypeId GetTypeId();

    SwitchedEthernetHostDevice();
    ~SwitchedEthernetHostDevice() override;

    /**
     * \brief Attach this device to \p channel.
     *
     * Must be called exactly once after construction.  The device registers
     * itself as the host slot on the channel.
     */
    void Attach(Ptr<SwitchedEthernetChannel> channel);

    /**
     * \brief Deliver an incoming Ethernet frame from the channel.
     *
     * Called by SwitchedEthernetChannel after the propagation delay.
     * Checks the destination MAC, strips the Ethernet header and calls
     * the registered receive callbacks.
     */
    void ReceiveFrame(Ptr<Packet> frame);

    // -----------------------------------------------------------------------
    // NetDevice interface
    // -----------------------------------------------------------------------
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

  private:
    Ptr<SwitchedEthernetChannel> m_channel;
    uint32_t m_devId{0};
    Mac48Address m_address;
    uint16_t m_mtu{1500};
    Ptr<Node> m_node;
    uint32_t m_ifIndex{0};
    NetDevice::ReceiveCallback m_rxCallback;
    NetDevice::PromiscReceiveCallback m_promiscRxCallback;

    TracedCallback<Ptr<const Packet>> m_macTxTrace;
    TracedCallback<Ptr<const Packet>> m_macRxTrace;
    TracedCallback<Ptr<const Packet>> m_macTxDropTrace;
    /**
     * A trace source that emulates a non-promiscuous protocol sniffer connected
     * to the device.  Unlike your average everyday sniffer, this trace source
     * will not fire on PACKET_OTHERHOST events.
     *
     * On the transmit size, this trace hook will fire after a packet is dequeued
     * from the device queue for transmission.  In Linux, for example, this would
     * correspond to the point just before a device hard_start_xmit where
     * dev_queue_xmit_nit is called to dispatch the packet to the PF_PACKET
     * ETH_P_ALL handlers.
     *
     * On the receive side, this trace hook will fire when a packet is received,
     * just before the receive callback is executed.  In Linux, for example,
     * this would correspond to the point at which the packet is dispatched to
     * packet sniffers in netif_receive_skb.
     *
     * \see class CallBackTraceSource
     */
    TracedCallback<Ptr<const Packet>> m_snifferTrace;

    /**
     * A trace source that emulates a promiscuous mode protocol sniffer connected
     * to the device.  This trace source fire on packets destined for any host
     * just like your average everyday packet sniffer.
     *
     * On the transmit size, this trace hook will fire after a packet is dequeued
     * from the device queue for transmission.  In Linux, for example, this would
     * correspond to the point just before a device hard_start_xmit where
     * dev_queue_xmit_nit is called to dispatch the packet to the PF_PACKET
     * ETH_P_ALL handlers.
     *
     * On the receive side, this trace hook will fire when a packet is received,
     * just before the receive callback is executed.  In Linux, for example,
     * this would correspond to the point at which the packet is dispatched to
     * packet sniffers in netif_receive_skb.
     *
     * \see class CallBackTraceSource
     */
    TracedCallback<Ptr<const Packet>> m_promiscSnifferTrace;
};

} // namespace ns3

#endif // SWITCHED_ETHERNET_HOST_DEVICE_H
