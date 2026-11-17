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
 * Modified: Vineet Goel <vineetgoel692@gmail.com>
 */

#ifndef P4_SWITCH_NET_DEVICE_H
#define P4_SWITCH_NET_DEVICE_H

#include "ns3/data-rate.h"
#include "ns3/mac48-address.h"
#include "ns3/net-device.h"
#include "ns3/nstime.h"
#include "ns3/traced-callback.h"

#include <cstdint>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

/**
 * \file
 * \ingroup p4sim
 * ns3::P4SwitchNetDevice declaration.
 */

namespace ns3
{

#define P4SWITCH_ARCH_V1MODEL 0
#define P4SWITCH_ARCH_PSA 1
#define P4NIC_ARCH_PNA 2
#define P4SWITCH_ARCH_PIPELINE 3

// Values of the "ChannelType" attribute, kept for main's examples (it has no effect)
#define P4CHANNELCSMA 0
#define P4CHANNELP2P 1

class Node;
class SwitchedEthernetChannel;
class P4CoreV1model;
class P4CorePsa;
class P4PnaNic;
class P4SwitchCore;
class P4CorePipeline;
class P4BridgeChannel;

/**
 * \ingroup p4sim
 *
 * \brief P4-programmable switch / NIC NetDevice.
 *
 * P4SwitchNetDevice is a standalone NetDevice that can operate in two modes:
 *
 * **Switch mode** (JsonPath + FlowTablePath configured):
 *   The device owns a P4 pipeline core (V1model / PSA / PNA / Pipeline).
 *   Each port is either a SwitchedEthernetChannel attached via Attach(), or
 *   an ordinary ns-3 device of the switch's node (CSMA, point-to-point, ...)
 *   added via AddBridgePort().  When a port receives a frame the device
 *   feeds it into the P4 pipeline;
 *   the pipeline calls back via SendNs3Packet() to emit the processed frame
 *   on the chosen egress port.
 *
 * **NIC / host mode** (no JsonPath):
 *   No P4 core is initialised.  Frames received from the channel are
 *   delivered directly up the ns-3 protocol stack via the standard receive
 *   callbacks.  Send() / SendFrom() put frames onto the channel.
 *
 * Typical switch setup:
 * \code
 *   // On the switch node:
 *   Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
 *   sw->SetAttribute("JsonPath",      StringValue("/path/p4.json"));
 *   sw->SetAttribute("FlowTablePath", StringValue("/path/rules.txt"));
 *   switchNode->AddDevice(sw);
 *
 *   // On the host node:
 *   Ptr<P4SwitchNetDevice> nic = CreateObject<P4SwitchNetDevice>();
 *   hostNode->AddDevice(nic);
 *
 *   // Wire them together:
 *   Ptr<SwitchedEthernetChannel> ch = CreateObject<SwitchedEthernetChannel>();
 *   sw->Attach(ch);   // switch port 0
 *   nic->Attach(ch);  // host NIC
 * \endcode
 */
class P4SwitchNetDevice : public NetDevice
{
  public:
    static TypeId GetTypeId();

    P4SwitchNetDevice();
    ~P4SwitchNetDevice() override;

    P4SwitchNetDevice(const P4SwitchNetDevice&) = delete;
    P4SwitchNetDevice& operator=(const P4SwitchNetDevice&) = delete;

    // -----------------------------------------------------------------------
    // Channel attachment
    // -----------------------------------------------------------------------

    /**
     * \brief Attach this device to \p channel as the next available port.
     *
     * Each call adds one port.  The port index (0-based) is the order in
     * which Attach() is called.  For a host NIC, Attach() is called once.
     * For a multi-port switch, Attach() is called once per link.
     *
     * \param channel The full-duplex channel to attach to.
     */
    void Attach(Ptr<SwitchedEthernetChannel> channel);

    /**
     * \brief Add \p bridgePort, a device of this switch's node, as the next port.
     *
     * A bridge port connects the switch through an ordinary ns-3 device, such
     * as a CSMA or point-to-point device, for example to another switch. The
     * two kinds of port can be mixed: the port index is the order of the
     * Attach() and AddBridgePort() calls.
     *
     * The device must support SendFrom() and EUI-48 addresses, and this
     * switch device must already be added to the node. The frames the device
     * receives go to the P4 pipeline, and its PhyTxEnd and PhyTxDrop traces
     * tell the P4 core that the port is free again.
     */
    void AddBridgePort(Ptr<NetDevice> bridgePort);

    // -----------------------------------------------------------------------
    // Ingress from channel (called directly by SwitchedEthernetChannel)
    // -----------------------------------------------------------------------

    /**
     * \brief Receive a frame from the channel.
     *
     * Called by SwitchedEthernetChannel::PropagationCompleteEvent() after the
     * propagation delay.  The packet arrives as a complete Ethernet frame
     * (header already present).
     *
     * In switch mode the frame is injected into the P4 pipeline.
     * In NIC mode the frame is delivered up the protocol stack.
     *
     * \param packet Full Ethernet frame.
     * \param sender The device that transmitted the frame.
     */
    void Receive(Ptr<Packet> packet, Ptr<P4SwitchNetDevice> sender);

    // -----------------------------------------------------------------------
    // Egress from P4 pipeline (called by pipeline cores)
    // -----------------------------------------------------------------------

    /**
     * \brief Emit \p packetOut on port \p outPort (thin wrapper).
     */
    void SendPacket(Ptr<Packet> packetOut,
                    int outPort,
                    uint16_t protocol,
                    const Address& destination);

    /**
     * \brief Emit a post-pipeline frame on port \p outPort.
     *
     * The packet must still carry the Ethernet header produced by the
     * P4 pipeline.  Port 511 is the conventional drop port.
     * Transmission timing is computed from the channel's DataRate.
     *
     * \param [out] txTime  if non-null, set to the frame's serialisation time
     *                      when the frame was accepted onto the channel (left
     *                      unchanged when the frame was dropped).
     * \return true if the frame was handed to the channel; false if it was
     *         dropped (null packet, drop port, invalid port, or channel busy).
     */
    bool SendNs3Packet(Ptr<Packet> packetOut,
                       int outPort,
                       uint16_t protocol,
                       const Address& destination,
                       Time* txTime = nullptr);

    // -----------------------------------------------------------------------
    // Port accessors
    // -----------------------------------------------------------------------

    /** \return Number of channels attached (= number of switch ports). */
    uint32_t GetNPorts() const;

    /** \return Channel at port \p n, or nullptr if out of range. */
    Ptr<SwitchedEthernetChannel> GetPortChannel(uint32_t n) const;

    /** \return Port index of \p sender, or UINT32_MAX if not found. */
    uint32_t GetPortNumber(Ptr<P4SwitchNetDevice> sender) const;

    /** \return Number of ports of both kinds, the same as GetNPorts() (main's name). */
    uint32_t GetNBridgePorts() const;

    /** \return The device of port \p n, or nullptr if \p n is not a bridge port. */
    Ptr<NetDevice> GetBridgePort(uint32_t n) const;

    /** \return Port index of bridge port \p device, or UINT32_MAX if it is not one. */
    uint32_t GetBridgePortNumber(Ptr<NetDevice> device) const;

    /**
     * \return The data rate of port \p n: its channel's, or for a bridge port the
     *         "DataRate" attribute of its device (point-to-point) or of its
     *         channel (CSMA). 0 if unknown.
     */
    DataRate GetPortDataRate(uint32_t n) const;
    /** \return Device-slot ID for port \p n in its channel, or UNIT32_MAX if invalid. */
    uint32_t GetPortDeviceId(uint32_t n) const;

    /**
     * \brief Set the callback that runs when a port has finished serialising a
     *        frame, with the port number as argument.
     *
     * The P4 core uses it to start the next frame on that port: the channel,
     * not the core, decides when a port is free again.
     */
    void SetPortTxDoneCallback(Callback<void, uint32_t> cb);
    // -----------------------------------------------------------------------
    // P4 core accessor
    // -----------------------------------------------------------------------

    /** \return V1model core pointer, or nullptr if another arch is active. */
    P4CoreV1model* GetV1ModelCore() const;

    /**
     * \brief Get the Thrift port of the P4 core of this switch
     * \return the port, or 0 if the core is not created yet (or already released)
     */
    int GetThriftPort() const;

    /**
     * \brief Emit a switch event trace (called by pipeline cores).
     */
    void EmitSwitchEvent(uint32_t id, const std::string& msg);

    /**
     * \brief Fire MacRxDrop: the P4 core dropped \p packet on reception
     *        because its input buffer was full (see SwitchRate).
     */
    void NotifyMacRxDrop(Ptr<const Packet> packet);

    /**
     * \brief Connect the P4 core's internal event trace to this device's
     *        public SwitchEvent trace source.
     */
    void ConnectCoreEvent();

    // -----------------------------------------------------------------------
    // P4 program configuration
    // -----------------------------------------------------------------------
    void SetJsonPath(const std::string& jsonPath);
    std::string GetJsonPath() const;
    void SetFlowTablePath(const std::string& flowTablePath);
    std::string GetFlowTablePath() const;

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

  protected:
    void DoInitialize() override;
    void DoDispose() override;

  private:
    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * \brief Transmit \p packet on port \p port.
     *        Schedules PortTransmitEnd() based on the channel's DataRate.
     *
     * \param [out] txTime  if non-null, set to the frame's serialisation time
     *                      when the transmission started (unchanged on failure).
     * \return true if the channel accepted the frame; false if it was busy or
     *         the device was inactive (frame dropped).
     */
    bool TransmitOn(uint32_t port, Ptr<Packet> packet, Time* txTime = nullptr);

    /**
     * \brief The frame on port \p port has been serialised: free the channel
     *        slot, then run the port-TX-done callback.
     */
    void PortTransmitEnd(uint32_t port);

    /**
     * \brief Pass the BMv2 options of this device (BmLogLevel, ThriftPort) to
     *        its P4 core, before the core loads the P4 JSON.
     * \param core the P4 core created by DoInitialize()
     */
    void ConfigureCore(P4SwitchCore& core) const;

    /**
     * \brief Feed \p frame, a full Ethernet frame received on \p inPort, into
     *        the P4 core.
     */
    void DeliverToCore(Ptr<Packet> frame, uint32_t inPort, uint16_t protocol, Mac48Address dst);

    /// Receives the frames of the bridge ports (a promiscuous protocol handler)
    void ReceiveFromDevice(Ptr<NetDevice> incomingPort,
                           Ptr<const Packet> packet,
                           uint16_t protocol,
                           const Address& src,
                           const Address& dst,
                           PacketType packetType);

    /**
     * \brief Send \p frame, a full Ethernet frame, on bridge port \p port.
     * \return true if the device accepted it.
     */
    bool SendOnBridgePort(uint32_t port, Ptr<Packet> frame, Time* txTime);

    /// Bridge port \p port has sent (PhyTxEnd) or given up (PhyTxDrop) a frame
    void BridgePortTxEnd(uint32_t port, Ptr<const Packet> packet);

    /// Runs when a port has finished serialising a frame (see SetPortTxDoneCallback())
    Callback<void, uint32_t> m_portTxDone;

    // -----------------------------------------------------------------------
    // P4 switch configuration
    // -----------------------------------------------------------------------
    bool m_enableTracing;
    bool m_enableSwap;
    uint32_t m_switchArch;

    std::string m_jsonPath;
    std::string m_flowTablePath;
    std::string m_bmLogLevel; //!< BMv2 log level ("trace" ... "off")
    uint16_t m_thriftPort;    //!< Requested Thrift port, 0 = automatic

    // The device owns its P4 core: DoInitialize() creates the one selected by
    // m_switchArch (the others stay null) and DoDispose() releases it.
    std::unique_ptr<P4CoreV1model> m_v1modelSwitch; //!< V1model switch core
    std::unique_ptr<P4CorePsa> m_psaSwitch;         //!< PSA switch core
    std::unique_ptr<P4PnaNic> m_pnaNic;             //!< PNA NIC core
    std::unique_ptr<P4CorePipeline> m_p4Pipeline;   //!< Pipeline core

    uint32_t m_channelType{P4CHANNELCSMA}; //!< "ChannelType" attribute (no effect)

    // -----------------------------------------------------------------------
    // Queue / rate configuration
    // -----------------------------------------------------------------------
    size_t m_InputBufferSizeLow;
    size_t m_InputBufferSizeHigh;
    size_t m_queueBufferSize;
    uint64_t m_switchRate;

    /// When true, a V1model core routes traffic through the VOQ + fabric
    /// Traffic Manager instead of the legacy output queues (attribute
    /// "EnableVoqFabric"; default false).  Propagated to the core in
    /// DoInitialize() before start_and_return_().
    bool m_enableVoqFabric{false};

    // -----------------------------------------------------------------------
    // NetDevice state
    // -----------------------------------------------------------------------
    Mac48Address m_address;
    Ptr<Node> m_node;
    uint32_t m_ifIndex;
    uint16_t m_mtu;

    /**
     * Channels attached via Attach() in order.
     * m_portChannels[i] is the channel for P4 port i, or nullptr if port i
     * is a bridge port.
     */
    std::vector<Ptr<SwitchedEthernetChannel>> m_portChannels;

    /**
     * Device-slot ID assigned by each channel when Attach() was called.
     * m_portDeviceIds[i] is this device's slot in m_portChannels[i]
     * (UINT32_MAX for a bridge port).
     */
    std::vector<uint32_t> m_portDeviceIds;

    /// m_bridgePorts[i] is the device of port i if it is a bridge port, else nullptr
    std::vector<Ptr<NetDevice>> m_bridgePorts;

    /// The channels of the bridge ports (GetChannel() when port 0 is a bridge port)
    Ptr<P4BridgeChannel> m_bridgeChannel;

    // -----------------------------------------------------------------------
    // Callbacks
    // -----------------------------------------------------------------------
    /**
     * The trace source fired when packets come into the "top" of the device
     * at the L3/L2 transition, before being queued for transmission.
     *
     * \see class CallBackTraceSource
     */
    TracedCallback<Ptr<const Packet>> m_macTxTrace;

    /**
     * The trace source fired when packets coming into the "top" of the device
     * at the L3/L2 transition are dropped before being queued for transmission.
     *
     * \see class CallBackTraceSource
     */
    TracedCallback<Ptr<const Packet>> m_macTxDropTrace;

    /**
     * The trace source fired for packets successfully received by the device
     * immediately before being forwarded up to higher layers (at the L2/L3
     * transition).  This is a non-promiscuous trace.
     *
     * \see class CallBackTraceSource
     */
    TracedCallback<Ptr<const Packet>> m_macRxTrace;

    /**
     * The trace source fired for a received packet that the P4 pipeline could
     * not take because its input buffer was full (see SwitchRate).
     */
    TracedCallback<Ptr<const Packet>> m_macRxDropTrace;

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

    NetDevice::ReceiveCallback m_rxCallback;
    NetDevice::PromiscReceiveCallback m_promiscRxCallback;
    TracedCallback<uint32_t, const std::string&> m_switchEvent;
};

} // namespace ns3

#endif /* P4_SWITCH_NET_DEVICE_H */
