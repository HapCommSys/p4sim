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

#ifndef P4_SWITCH_NET_DEVICE_H
#define P4_SWITCH_NET_DEVICE_H

#include "ns3/mac48-address.h"
#include "ns3/net-device.h"
#include "ns3/traced-callback.h"

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

class Node;
class SwitchedEthernetChannel;
class P4CoreV1model;
class P4CorePsa;
class P4PnaNic;
class P4CorePipeline;

/**
 * \ingroup p4sim
 *
 * \brief P4-programmable switch / NIC NetDevice.
 *
 * P4SwitchNetDevice is a standalone NetDevice that can operate in two modes:
 *
 * **Switch mode** (JsonPath + FlowTablePath configured):
 *   The device owns a P4 pipeline core (V1model / PSA / PNA / Pipeline).
 *   Each port is a SwitchedEthernetChannel attached via Attach().  When the
 *   channel delivers a frame the device feeds it into the P4 pipeline;
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
     */
    void SendNs3Packet(Ptr<Packet> packetOut,
                       int outPort,
                       uint16_t protocol,
                       const Address& destination);

    // -----------------------------------------------------------------------
    // Port accessors
    // -----------------------------------------------------------------------

    /** \return Number of channels attached (= number of switch ports). */
    uint32_t GetNPorts() const;

    /** \return Channel at port \p n, or nullptr if out of range. */
    Ptr<SwitchedEthernetChannel> GetPortChannel(uint32_t n) const;

    /** \return Port index of \p sender, or UINT32_MAX if not found. */
    uint32_t GetPortNumber(Ptr<P4SwitchNetDevice> sender) const;

    // -----------------------------------------------------------------------
    // P4 core accessor
    // -----------------------------------------------------------------------

    /** \return V1model core pointer, or nullptr if another arch is active. */
    P4CoreV1model* GetV1ModelCore() const;

    /**
     * \brief Emit a switch event trace (called by pipeline cores).
     */
    void EmitSwitchEvent(uint32_t id, const std::string& msg);

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
     * \brief Transmit \p packet on \p channel using slot \p devId.
     *        Schedules TransmitEnd() based on the channel's DataRate.
     */
    void TransmitOn(Ptr<SwitchedEthernetChannel> channel, uint32_t devId, Ptr<Packet> packet);

    // -----------------------------------------------------------------------
    // P4 switch configuration
    // -----------------------------------------------------------------------
    bool m_enableTracing;
    bool m_enableSwap;
    uint32_t m_switchArch;

    std::string m_jsonPath;
    std::string m_flowTablePath;

    P4CoreV1model* m_v1modelSwitch;
    P4CorePipeline* m_p4Pipeline;
    P4CorePsa* m_psaSwitch;
    P4PnaNic* m_pnaNic;

    // -----------------------------------------------------------------------
    // Queue / rate configuration
    // -----------------------------------------------------------------------
    size_t m_InputBufferSizeLow;
    size_t m_InputBufferSizeHigh;
    size_t m_queueBufferSize;
    uint64_t m_switchRate;

    // -----------------------------------------------------------------------
    // NetDevice state
    // -----------------------------------------------------------------------
    Mac48Address m_address;
    Ptr<Node> m_node;
    uint32_t m_ifIndex;
    uint16_t m_mtu;

    /**
     * Channels attached via Attach() in order.
     * m_portChannels[i] is the channel for P4 port i.
     */
    std::vector<Ptr<SwitchedEthernetChannel>> m_portChannels;

    /**
     * Device-slot ID assigned by each channel when Attach() was called.
     * m_portDeviceIds[i] is this device's slot in m_portChannels[i].
     */
    std::vector<uint32_t> m_portDeviceIds;

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

    NetDevice::ReceiveCallback m_rxCallback;
    NetDevice::PromiscReceiveCallback m_promiscRxCallback;
    TracedCallback<uint32_t, const std::string&> m_switchEvent;
};

} // namespace ns3

#endif /* P4_SWITCH_NET_DEVICE_H */
