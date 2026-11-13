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

#ifndef CUSTOM_P2P_NET_DEVICE_H
#define CUSTOM_P2P_NET_DEVICE_H

#include "ns3/address.h"
#include "ns3/callback.h"
#include "ns3/custom-header.h"
#include "ns3/data-rate.h"
#include "ns3/ethernet-header.h"
#include "ns3/net-device.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/p4-p2p-channel.h"
#include "ns3/packet.h"
#include "ns3/ptr.h"
#include "ns3/queue.h"
#include "ns3/traced-callback.h"
#include <ns3/arp-header.h>
#include <ns3/arp-l3-protocol.h>
#include <ns3/ipv4-l3-protocol.h>
#include <ns3/tcp-header.h>
#include <ns3/udp-header.h>

#include <cstring>

namespace ns3
{

class ErrorModel;
class P4P2PChannel;

class CustomP2PNetDevice : public NetDevice
{
  public:
    static TypeId GetTypeId(void);

    CustomP2PNetDevice();
    virtual ~CustomP2PNetDevice();

    bool RemoveEthernetHeader(Ptr<Packet> p);

    uint16_t GetDstPort(Ptr<Packet> p);
    bool HandleTransportLayerHeader(Ptr<Packet> p,
                                    CustomHeader& cus_hd,
                                    uint16_t protocol,
                                    bool removeHeader = false);
    void HandleLayer2(Ptr<Packet> p, CustomHeader& cus_hd, EthernetHeader& eeh_header);
    void HandleLayer3(Ptr<Packet> p, CustomHeader& cus_hd, EthernetHeader& eeh_header);
    void HandleLayer4(Ptr<Packet> p, CustomHeader& cus_hd, EthernetHeader& eeh_header);

    /**
     * Set the Data Rate used for transmission of packets.  The data rate is
     * set in the Attach () method from the corresponding field in the channel
     * to which the device is attached.  It can be overridden using this method.
     *
     * \param bps the data rate at which this object operates
     */
    void SetDataRate(DataRate bps);

    /**
     * Set the interframe gap used to separate packets.  The interframe gap
     * defines the minimum space required between packets sent by this device.
     *
     * \param t the interframe gap time
     */
    void SetInterframeGap(Time t);

    /**
     * Attach the device to a channel.
     *
     * \param ch Ptr to the channel to which this object is being attached.
     * \return true if the operation was successful (always true actually)
     */
    bool Attach(Ptr<P4P2PChannel> ch);

    /**
     * Attach a queue to the PointToPointNetDevice.
     *
     * The PointToPointNetDevice "owns" a queue that implements a queueing
     * method such as DropTailQueue or RedQueue
     *
     * \param queue Ptr to the new queue.
     */
    void SetQueue(Ptr<Queue<Packet>> queue);

    /**
     * Get a copy of the attached Queue.
     *
     * \returns Ptr to the queue.
     */
    Ptr<Queue<Packet>> GetQueue(void) const;

    /**
     * Attach a receive ErrorModel to the CustomP2PNetDevice.
     *
     * The CustomP2PNetDevice may optionally include an ErrorModel in
     * the packet receive chain.
     *
     * \param em Ptr to the ErrorModel.
     */
    void SetReceiveErrorModel(Ptr<ErrorModel> em);

    /**
     * Receive a packet from a connected P4P2PChannel.
     *
     * The CustomP2PNetDevice receives packets from its connected channel
     * and forwards them up the protocol stack.  This is the public method
     * used by the channel to indicate that the last bit of a packet has
     * arrived at the device.
     *
     * \param p Ptr to the received packet.
     */
    void Receive(Ptr<Packet> p);

    void SetWithCustomHeader(bool withHeader);

    bool IsWithCustomHeader(void) const;

    void SetCustomHeader(CustomHeader customHeader);

    // The remaining methods are documented in ns3::NetDevice*

    virtual void SetIfIndex(const uint32_t index);
    virtual uint32_t GetIfIndex(void) const;

    virtual Ptr<Channel> GetChannel(void) const;

    virtual void SetAddress(Address address);
    virtual Address GetAddress(void) const;

    virtual bool SetMtu(const uint16_t mtu);
    virtual uint16_t GetMtu(void) const;

    virtual bool IsLinkUp(void) const;

    virtual void AddLinkChangeCallback(Callback<void> callback);

    virtual bool IsBroadcast(void) const;
    virtual Address GetBroadcast(void) const;

    virtual bool IsMulticast(void) const;
    virtual Address GetMulticast(Ipv4Address multicastGroup) const;

    virtual bool IsPointToPoint(void) const;
    virtual bool IsBridge(void) const;

    /**
     * Start sending a packet down the channel.
     * \param packet packet to send
     * \param dest layer 2 destination address
     * \param protocolNumber protocol number
     * \return true if successful, false otherwise (drop, ...)
     */
    virtual bool Send(Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber);

    /**
     * Start sending a packet down the channel, with MAC spoofing
     * \param packet packet to send
     * \param source layer 2 source address
     * \param dest layer 2 destination address
     * \param protocolNumber protocol number
     * \return true if successful, false otherwise (drop, ...)
     */
    virtual bool SendFrom(Ptr<Packet> packet,
                          const Address& source,
                          const Address& dest,
                          uint16_t protocolNumber);

    virtual Ptr<Node> GetNode(void) const;
    virtual void SetNode(Ptr<Node> node);

    virtual bool NeedsArp(void) const;

    virtual void SetReceiveCallback(NetDevice::ReceiveCallback cb);

    virtual Address GetMulticast(Ipv6Address addr) const;

    virtual void SetPromiscReceiveCallback(PromiscReceiveCallback cb);
    virtual bool SupportsSendFrom(void) const;

    uint16_t CheckIfEthernetHeader(Ptr<Packet> p, EthernetHeader& eeh_hd);
    uint8_t CheckIfIpv4Header(Ptr<Packet> p, Ipv4Header& ip_hd);
    uint64_t CheckIfArpHeader(Ptr<Packet> p, ArpHeader& arp_hd);
    uint64_t CheckIfCustomHeader(Ptr<Packet> p);
    uint64_t CheckIfUdpHeader(Ptr<Packet> p, UdpHeader& udp_hd);
    uint64_t CheckIfTcpHeader(Ptr<Packet> p, TcpHeader& tcp_hd);

  protected:
    /**
     * \brief Handler for MPI receive event
     *
     * \param p Packet received
     */
    void DoMpiReceive(Ptr<Packet> p);

  private:
    /**
     * \brief Assign operator
     *
     * The method is private, so it is DISABLED.
     *
     * \param o Other NetDevice
     * \return New instance of the NetDevice
     */
    CustomP2PNetDevice& operator=(const CustomP2PNetDevice& o);

    /**
     * \brief Copy constructor
     *
     * The method is private, so it is DISABLED.

     * \param o Other NetDevice
     */
    CustomP2PNetDevice(const CustomP2PNetDevice& o);

    /**
     * \brief Dispose of the object
     */
    virtual void DoDispose(void);

  private:
    /**
     * \returns the address of the remote device connected to this device
     * through the point to point channel.
     */
    Address GetRemote(void) const;

    /**
     * Adds the necessary headers and trailers to a packet of data in order to
     * respect the protocol implemented by the agent.
     * \param p packet
     * \param protocolNumber protocol number
     */
    void AddHeader(Ptr<Packet> p, uint16_t protocolNumber);

    void AddHeader(Ptr<Packet> p, Mac48Address source, Mac48Address dest, uint16_t protocolNumber);

    void AddEthernetHeader(Ptr<Packet> p,
                           Mac48Address source,
                           Mac48Address dest,
                           uint16_t protocolNumber);

    /**
     * Removes, from a packet of data, all headers and trailers that
     * relate to the protocol implemented by the agent
     * \param p Packet whose headers need to be processed
     * \param param An integer parameter that can be set by the function
     * \return Returns true if the packet should be forwarded up the
     * protocol stack.
     */
    bool ProcessHeader(Ptr<Packet> p, uint16_t& param);

    /** */
    void RestoreHeaders(Ptr<Packet> p);

    /**
     * Start Sending a Packet Down the Wire.
     *
     * The TransmitStart method is the method that is used internally in the
     * CustomP2PNetDevice to begin the process of sending a packet out on
     * the channel.  The corresponding method is called on the channel to let
     * it know that the physical device this class represents has virtually
     * started sending signals.  An event is scheduled for the time at which
     * the bits have been completely transmitted.
     *
     * \see P4P2PChannel::TransmitStart ()
     * \see TransmitComplete()
     * \param p a reference to the packet to send
     * \returns true if success, false on failure
     */
    bool TransmitStart(Ptr<Packet> p);

    /**
     * Stop Sending a Packet Down the Wire and Begin the Interframe Gap.
     *
     * The TransmitComplete method is used internally to finish the process
     * of sending a packet out on the channel.
     */
    void TransmitComplete(void);

    /**
     * \brief Make the link up and running
     *
     * It calls also the linkChange callback.
     */
    void NotifyLinkUp(void);

    /**
     * Enumeration of the states of the transmit machine of the net device.
     */
    enum TxMachineState
    {
        READY, /**< The transmitter is ready to begin transmission of a packet */
        BUSY   /**< The transmitter is busy transmitting a packet */
    };

    /**
     * The state of the Net Device transmit state machine.
     */
    TxMachineState m_txMachineState;

    /**
     * The data rate that the Net Device uses to simulate packet transmission
     * timing.
     */
    DataRate m_bps;

    /**
     * The interframe gap that the Net Device uses to throttle packet
     * transmission
     */
    Time m_tInterframeGap;

    /**
     * The P4P2PChannel to which this CustomP2PNetDevice has been
     * attached.
     */
    Ptr<P4P2PChannel> m_channel;

    /**
     * The Queue which this CustomP2PNetDevice uses as a packet source.
     * Management of this Queue has been delegated to the CustomP2PNetDevice
     * and it has the responsibility for deletion.
     * \see class DropTailQueue
     */
    Ptr<Queue<Packet>> m_queue;

    /**
     * Error model for receive packet events
     */
    Ptr<ErrorModel> m_receiveErrorModel;

    /**
     * The trace source fired when packets come into the "top" of the device
     * at the L3/L2 transition, before being queued for transmission.
     */
    TracedCallback<Ptr<const Packet>> m_macTxTrace;

    /**
     * The trace source fired when packets coming into the "top" of the device
     * at the L3/L2 transition are dropped before being queued for transmission.
     */
    TracedCallback<Ptr<const Packet>> m_macTxDropTrace;

    /**
     * The trace source fired for packets successfully received by the device
     * immediately before being forwarded up to higher layers (at the L2/L3
     * transition).  This is a promiscuous trace (which doesn't mean a lot here
     * in the point-to-point device).
     */
    TracedCallback<Ptr<const Packet>> m_macPromiscRxTrace;

    /**
     * The trace source fired for packets successfully received by the device
     * immediately before being forwarded up to higher layers (at the L2/L3
     * transition).  This is a non-promiscuous trace (which doesn't mean a lot
     * here in the point-to-point device).
     */
    TracedCallback<Ptr<const Packet>> m_macRxTrace;

    /**
     * The trace source fired for packets successfully received by the device
     * but are dropped before being forwarded up to higher layers (at the L2/L3
     * transition).
     */
    TracedCallback<Ptr<const Packet>> m_macRxDropTrace;

    /**
     * The trace source fired when a packet begins the transmission process on
     * the medium.
     */
    TracedCallback<Ptr<const Packet>> m_phyTxBeginTrace;

    /**
     * The trace source fired when a packet ends the transmission process on
     * the medium.
     */
    TracedCallback<Ptr<const Packet>> m_phyTxEndTrace;

    /**
     * The trace source fired when the phy layer drops a packet before it tries
     * to transmit it.
     */
    TracedCallback<Ptr<const Packet>> m_phyTxDropTrace;

    /**
     * The trace source fired when a packet begins the reception process from
     * the medium -- when the simulated first bit(s) arrive.
     */
    TracedCallback<Ptr<const Packet>> m_phyRxBeginTrace;

    /**
     * The trace source fired when a packet ends the reception process from
     * the medium.
     */
    TracedCallback<Ptr<const Packet>> m_phyRxEndTrace;

    /**
     * The trace source fired when the phy layer drops a packet it has received.
     * This happens if the receiver is not enabled or the error model is active
     * and indicates that the packet is corrupt.
     */
    TracedCallback<Ptr<const Packet>> m_phyRxDropTrace;

    /**
     * A trace source that emulates a non-promiscuous protocol sniffer connected
     * to the device.  Unlike your average everyday sniffer, this trace source
     * will not fire on PACKET_OTHERHOST events.
     *
     * On the transmit size, this trace hook will fire after a packet is dequeued
     * from the device queue for transmission.  In Linux, for example, this would
     * correspond to the point just before a device \c hard_start_xmit where
     * \c dev_queue_xmit_nit is called to dispatch the packet to the PF_PACKET
     * ETH_P_ALL handlers.
     *
     * On the receive side, this trace hook will fire when a packet is received,
     * just before the receive callback is executed.  In Linux, for example,
     * this would correspond to the point at which the packet is dispatched to
     * packet sniffers in \c netif_receive_skb.
     */
    TracedCallback<Ptr<const Packet>> m_snifferTrace;

    /**
     * A trace source that emulates a promiscuous mode protocol sniffer connected
     * to the device.  This trace source fire on packets destined for any host
     * just like your average everyday packet sniffer.
     *
     * On the transmit size, this trace hook will fire after a packet is dequeued
     * from the device queue for transmission.  In Linux, for example, this would
     * correspond to the point just before a device \c hard_start_xmit where
     * \c dev_queue_xmit_nit is called to dispatch the packet to the PF_PACKET
     * ETH_P_ALL handlers.
     *
     * On the receive side, this trace hook will fire when a packet is received,
     * just before the receive callback is executed.  In Linux, for example,
     * this would correspond to the point at which the packet is dispatched to
     * packet sniffers in \c netif_receive_skb.
     */
    TracedCallback<Ptr<const Packet>> m_promiscSnifferTrace;

    Ptr<Node> m_node;       //!< Node owning this NetDevice
    Mac48Address m_address; //!< Mac48Address of this NetDevice

    bool m_NeedProcessHeader; //!< Identify if the device should take care of custom header
    CustomHeader m_header;    //!< Custom header

    NetDevice::ReceiveCallback m_rxCallback;             //!< Receive callback
    NetDevice::PromiscReceiveCallback m_promiscCallback; //!< Receive callback
                                                         //   (promisc data)
    uint32_t m_ifIndex;                                  //!< Index of the interface
    bool m_linkUp;                                       //!< Identify if the link is up or not
    TracedCallback<> m_linkChangeCallbacks;              //!< Callback for the link change event

    static const uint16_t DEFAULT_MTU = 1500; //!< Default MTU

    // port range used to determine whether a packet should include the custom header.
    // In ns-3, the same NetDevice may handle different types of packets.
    // If the destination port in the UDP/TCP header falls within
    // [CUSTOM_DST_PORT_MIN, CUSTOM_DST_PORT_MAX], the packet will be assigned a custom header.
    uint16_t m_customDstPortMin;
    uint16_t m_customDstPortMax;

    // Protocol number used to identify the custom P4 header in nested packet parsing.
    // The previous header's protocol field indicates that the next is a custom header
    static constexpr uint16_t m_p4ProtocolNumber = 0xDC;

    /**
     * \brief The Maximum Transmission Unit
     *
     * This corresponds to the maximum
     * number of bytes that can be transmitted as seen from higher layers.
     * This corresponds to the 1500 byte MTU size often seen on IP over
     * Ethernet.
     */
    uint32_t m_mtu;

    Ptr<Packet> m_currentPkt; //!< Current packet processed

    // /**
    //  * \brief PPP to Ethernet protocol number mapping
    //  * \param protocol A PPP protocol number
    //  * \return The corresponding Ethernet protocol number
    //  */
    // static uint16_t PppToEther (uint16_t protocol);

    // /**
    //  * \brief Ethernet to PPP protocol number mapping
    //  * \param protocol An Ethernet protocol number
    //  * \return The corresponding PPP protocol number
    //  */
    // static uint16_t EtherToPpp (uint16_t protocol);
};

} // namespace ns3

#endif // CUSTOM_P2P_NET_DEVICE_H
