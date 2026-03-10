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

#ifndef P4_SWITCH_NET_DEVICE
#define P4_SWITCH_NET_DEVICE

#include "ns3/callback.h"
#include "ns3/net-device.h"
#include "ns3/p4-bridge-channel.h"
#include "ns3/traced-callback.h"

#include <map>
#include <stdint.h>
#include <string>

/**
 * \file
 * \ingroup bridge
 * ns3::P4SwitchNetDevice declaration.
 */

namespace ns3
{

#define P4CHANNELCSMA 0
#define P4CHANNELP2P 1

#define P4SWITCH_ARCH_V1MODEL 0
#define P4SWITCH_ARCH_PSA 1
#define P4NIC_ARCH_PNA 2
#define P4SWITCH_ARCH_PIPELINE 3

class Node;
class P4CoreV1model;
class P4CorePsa;
class P4PnaNic;
class P4CorePipeline;

/**
 * \defgroup P4 Switch Network Device
 *
 * \brief P4 Switch Net Device with Programmable Data Plane, based on
 * ns3::BridgeNetDevice
 *
 * P4SwitchNetDevice is a subclass of NetDevice in the ns-3 domain and serves as
 * the Ethernet of a P4 target. It is compatible with other net devices in ns-3.
 */
class P4SwitchNetDevice : public NetDevice
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();

    P4SwitchNetDevice();
    ~P4SwitchNetDevice() override;

    // Delete copy constructor and assignment operator to avoid misuse
    P4SwitchNetDevice(const P4SwitchNetDevice&) = delete;
    P4SwitchNetDevice& operator=(const P4SwitchNetDevice&) = delete;
    /**
     * \brief Emit a switch event (called internally or by P4CoreV1model)
     * \param id    Switch-specific event ID
     * \param msg   Event message
     */
    void EmitSwitchEvent(uint32_t id, const std::string& msg);

    /**
     * \brief Connects the core's event to this device's public trace source.
     * Call after P4CoreV1model is created.
     */
    void ConnectCoreEvent();
    /**
     * \brief Add a 'port' to a P4 bridge device
     * \param bridgePort the NetDevice to add
     *
     * This method adds a new bridge port to a P4SwitchNetDevice, so that
     * the new bridge port NetDevice becomes part of the bridge and L2
     * frames start being forwarded to/from this NetDevice.
     *
     * \attention The netdevice that is being added as bridge port must
     * _not_ have an IP address.  In order to add IP connectivity to a
     * bridging node you must enable IP on the BridgeNetDevice itself,
     * never on its port netdevices.
     */
    void AddBridgePort(Ptr<NetDevice> bridgePort);

    /**
     * \brief Gets the number of bridged 'ports', i.e., the NetDevices currently
     * bridged.
     *
     * \return the number of bridged ports.
     */
    uint32_t GetNBridgePorts() const;

    /**
     * \brief Gets the number ID of a 'port' connected to P4 net device.
     * \param netdevice
     * \return the port number of the p4 bridge device
     */
    uint32_t GetPortNumber(Ptr<NetDevice> port) const;

    /**
     * \brief Gets the n-th bridged port.
     * \param n the port index
     * \return the n-th bridged NetDevice
     */
    Ptr<NetDevice> GetBridgePort(uint32_t n) const;

    /**
     * \brief Forwards a broadcast or a multicast packet
     * \param incomingPort the packet incoming port
     * \param packet the packet
     * \param protocol the packet protocol (e.g., Ethertype)
     * \param src the packet source
     * \param dst the packet destination
     */
    void ForwardBroadcast(Ptr<NetDevice> incomingPort,
                          Ptr<const Packet> packet,
                          uint16_t protocol,
                          Mac48Address src,
                          Mac48Address dst);

    /**
     * \brief This method sends a packet out to the destination port.
     * Same with function SendNs3Packet.
     * \param packetOut the packet need to be send out
     * \param outPort the port index to send out
     * \param protocol the packet protocol (e.g., Ethertype)
     * \param destination the packet destination
     */
    void SendPacket(Ptr<Packet> packetOut,
                    int outPort,
                    uint16_t protocol,
                    const Address& destination);

    /**
     * \brief This method sends a packet out to the destination port.
     * \param packetOut the packet need to be send out
     * \param outPort the port index to send out
     * \param protocol the packet protocol (e.g., Ethertype)
     * \param destination the packet destination
     */
    void SendNs3Packet(Ptr<Packet> packetOut,
                       int outPort,
                       uint16_t protocol,
                       const Address& destination);

    /**
     * \brief Register a callback that is invoked whenever an output port
     *        completes a physical transmission (PhyTxEnd).
     *
     * The callback signature is void(uint32_t portIndex).  It is called by
     * OnPortTxEnd() which is connected to every bridge port's PhyTxEnd trace
     * source in AddBridgePort().  The P4 core (e.g. P4CoreV1model) installs
     * its PortTxComplete handler here so that dequeue scheduling is driven by
     * actual device transmission completion rather than an internal timer.
     *
     * \param cb  Callback taking the zero-based port index.
     */
    void SetPortTxDoneCallback(Callback<void, uint32_t> cb);

    P4CoreV1model* GetV1ModelCore() const;

    // inherited from NetDevice base class.
    void SetIfIndex(const uint32_t index) override;
    uint32_t GetIfIndex() const override;
    Ptr<Channel> GetChannel() const override;
    void SetAddress(Address address) override;
    Address GetAddress() const override;
    bool SetMtu(const uint16_t mtu) override;
    uint16_t GetMtu() const override;

    void SetJsonPath(const std::string& jsonPath);
    std::string GetJsonPath(void) const;
    void SetFlowTablePath(const std::string& flowTablePath);
    std::string GetFlowTablePath(void) const;

    bool IsLinkUp() const override;
    void AddLinkChangeCallback(Callback<void> callback) override;
    bool IsBroadcast() const override;
    Address GetBroadcast() const override;
    bool IsMulticast() const override;
    Address GetMulticast(Ipv4Address multicastGroup) const override;
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
    Address GetMulticast(Ipv6Address addr) const override;

  protected:
    virtual void DoInitialize() override;
    void DoDispose() override;

    /**
     * \brief Receives a packet from one bridged port.
     * \param device the originating port
     * \param packet the received packet
     * \param protocol the packet protocol (e.g., Ethertype)
     * \param source the packet source
     * \param destination the packet destination
     * \param packetType the packet type (e.g., host, broadcast, etc.)
     */
    void ReceiveFromDevice(Ptr<NetDevice> device,
                           Ptr<const Packet> packet,
                           uint16_t protocol,
                           const Address& source,
                           const Address& destination,
                           PacketType packetType);

    // /**
    //  * \brief Gets the port associated to a source address
    //  * \param source the source address
    //  * \returns the port the source is associated to, or NULL if no association
    //  is known.
    //  */
    // Ptr<NetDevice> GetLearnedState(Mac48Address source);

  private:
    // === Basic configuration ===
    bool m_enableTracing;  //!< Enable tracing
    bool m_enableSwap;     //!< Enable swapping
    uint32_t m_switchArch; //!< Switch architecture type

    // === P4 configuration and initialization ===
    std::string m_jsonPath;         //!< Path to the P4 JSON configuration file.
    std::string m_flowTablePath;    //!< Path to the flow table file.
    P4CoreV1model* m_v1modelSwitch; //!< V1model switch core
    P4CorePipeline* m_p4Pipeline;   //!< P4 pipeline core
    P4CorePsa* m_psaSwitch;         //!< PSA switch core
    P4PnaNic* m_pnaNic;             //!< PNA NIC core

    // === Buffer and queue configuration ===
    size_t m_InputBufferSizeLow;  //!< Input buffer normal packets(low priority) size
    size_t m_InputBufferSizeHigh; //!< Input buffer (high priority) size
    size_t m_queueBufferSize;     //!< Queue buffer size
    uint64_t m_switchRate;        //!< Switch rate, packet processing speed in switch
                                  //!< (unit: pps)

    // === Network device information ===
    uint32_t m_channelType;              //!< Channel type
    Mac48Address m_address;              //!< MAC address of NetDevice
    Ptr<Node> m_node;                    //!< Node that owns this NetDevice
    Ptr<P4BridgeChannel> m_channel;      //!< Virtual bridge channel
    std::vector<Ptr<NetDevice>> m_ports; //!< List of bridged ports
    uint32_t m_ifIndex;                  //!< Interface index
    uint16_t m_mtu; //!< [Deprecated] MTU (maximum transmission unit) of NetDevice

    // === Callback function ===
    NetDevice::ReceiveCallback m_rxCallback;               //!< Receive callback
    NetDevice::PromiscReceiveCallback m_promiscRxCallback; //!< Promiscuous mode receive callback
    TracedCallback<uint32_t, const std::string&> m_switchEvent;

    /**
     * \brief Fired by AddBridgePort() when a port's PhyTxEnd trace fires.
     *
     * Translates the NetDevice pointer back to a port index and invokes
     * m_portTxDoneCallback if one has been registered.
     *
     * \param srcDevice  The port device that just finished transmitting.
     * \param packet     The packet that was transmitted (ignored; for trace compat).
     */
    void OnPortTxEnd(Ptr<NetDevice> srcDevice, Ptr<const Packet> packet);

    Callback<void, uint32_t> m_portTxDoneCallback; //!< Called on port PhyTxEnd (may be null)
};

} // namespace ns3

#endif /* P4_SWITCH_NET_DEVICE */
