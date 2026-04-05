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

#include "ns3/p4-switch-net-device.h"

#include "ns3/boolean.h"
#include "ns3/ethernet-header.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/p4-core-pipeline.h"
#include "ns3/p4-core-psa.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-nic-pna.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/uinteger.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("P4SwitchNetDevice");
NS_OBJECT_ENSURE_REGISTERED(P4SwitchNetDevice);

// ---------------------------------------------------------------------------
// TypeId
// ---------------------------------------------------------------------------

TypeId
P4SwitchNetDevice::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::P4SwitchNetDevice")
            .SetParent<NetDevice>()
            .SetGroupName("P4sim")
            .AddConstructor<P4SwitchNetDevice>()

            .AddAttribute("EnableTracing",
                          "Enable per-packet tracing inside the P4 pipeline.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&P4SwitchNetDevice::m_enableTracing),
                          MakeBooleanChecker())

            .AddAttribute("EnableSwap",
                          "Enable live P4-program hot-swap.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&P4SwitchNetDevice::m_enableSwap),
                          MakeBooleanChecker())

            .AddAttribute("P4SwitchArch",
                          "P4 pipeline architecture: 0=V1model, 1=PSA, 2=PNA, 3=Pipeline.",
                          UintegerValue(P4SWITCH_ARCH_V1MODEL),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_switchArch),
                          MakeUintegerChecker<uint32_t>())

            .AddAttribute("JsonPath",
                          "Path to the compiled P4 JSON file. "
                          "Leave empty for NIC / passthrough mode.",
                          StringValue(""),
                          MakeStringAccessor(&P4SwitchNetDevice::GetJsonPath,
                                             &P4SwitchNetDevice::SetJsonPath),
                          MakeStringChecker())

            .AddAttribute("FlowTablePath",
                          "Path to the initial flow-table file.",
                          StringValue(""),
                          MakeStringAccessor(&P4SwitchNetDevice::GetFlowTablePath,
                                             &P4SwitchNetDevice::SetFlowTablePath),
                          MakeStringChecker())

            .AddAttribute("InputBufferSizeLow",
                          "Normal-priority input buffer depth (packets).",
                          UintegerValue(128),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_InputBufferSizeLow),
                          MakeUintegerChecker<size_t>())

            .AddAttribute("InputBufferSizeHigh",
                          "High-priority input buffer depth (packets).",
                          UintegerValue(128),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_InputBufferSizeHigh),
                          MakeUintegerChecker<size_t>())

            .AddAttribute("QueueBufferSize",
                          "Output queue buffer depth (packets).",
                          UintegerValue(128),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_queueBufferSize),
                          MakeUintegerChecker<size_t>())

            .AddAttribute("SwitchRate",
                          "Packet processing rate inside the switch (pps).",
                          UintegerValue(1000),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_switchRate),
                          MakeUintegerChecker<uint64_t>())

            .AddAttribute(
                "Mtu",
                "Maximum Transmission Unit.",
                UintegerValue(1500),
                MakeUintegerAccessor(&P4SwitchNetDevice::SetMtu, &P4SwitchNetDevice::GetMtu),
                MakeUintegerChecker<uint16_t>())

            .AddTraceSource("SwitchEvent",
                            "Fired when the P4 pipeline emits a switch event.",
                            MakeTraceSourceAccessor(&P4SwitchNetDevice::m_switchEvent),
                            "ns3::TracedCallback::Uint32String")

            .AddTraceSource(
                "MacTx",
                "Trace source indicating a packet has arrived for transmission by this device",
                MakeTraceSourceAccessor(&P4SwitchNetDevice::m_macTxTrace),
                "ns3::Packet::TracedCallback")

            .AddTraceSource("MacTxDrop",
                            "Trace source indicating a packet has been dropped by the device "
                            "before transmission",
                            MakeTraceSourceAccessor(&P4SwitchNetDevice::m_macTxDropTrace),
                            "ns3::Packet::TracedCallback")

            .AddTraceSource("MacRx",
                            "A packet has been received by this device, has been passed up from "
                            "the physical layer "
                            "and is being forwarded up the local protocol stack.  This is a "
                            "non-promiscuous trace,",
                            MakeTraceSourceAccessor(&P4SwitchNetDevice::m_macRxTrace),
                            "ns3::Packet::TracedCallback");

    return tid;
}

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

P4SwitchNetDevice::P4SwitchNetDevice()
    : m_enableTracing(false),
      m_enableSwap(false),
      m_switchArch(P4SWITCH_ARCH_V1MODEL),
      m_v1modelSwitch(nullptr),
      m_p4Pipeline(nullptr),
      m_psaSwitch(nullptr),
      m_pnaNic(nullptr),
      m_InputBufferSizeLow(1024),
      m_InputBufferSizeHigh(1024),
      m_queueBufferSize(1024),
      m_switchRate(1000),
      m_node(nullptr),
      m_ifIndex(0),
      m_mtu(1500)
{
    NS_LOG_FUNCTION_NOARGS();
}

P4SwitchNetDevice::~P4SwitchNetDevice()
{
    NS_LOG_FUNCTION_NOARGS();
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

void
P4SwitchNetDevice::DoInitialize()
{
    NS_LOG_FUNCTION(this);

    // NIC / passthrough mode: no JSON configured, no P4 core needed.
    if (m_jsonPath.empty())
    {
        NS_LOG_INFO("P4SwitchNetDevice (NIC mode) on node " << (m_node ? m_node->GetId() : 0));
        NetDevice::DoInitialize();
        return;
    }

    // Switch mode: boot the requested P4 pipeline.
    NS_LOG_INFO("P4SwitchNetDevice (switch mode, arch=" << m_switchArch << ", ports="
                                                        << m_portChannels.size() << ") on node "
                                                        << (m_node ? m_node->GetId() : 0));

    switch (m_switchArch)
    {
    case P4SWITCH_ARCH_V1MODEL:
        NS_LOG_DEBUG("Initialising V1model pipeline");
        m_v1modelSwitch = new P4CoreV1model(this,
                                            m_enableSwap,
                                            m_enableTracing,
                                            m_switchRate,
                                            m_InputBufferSizeLow,
                                            m_InputBufferSizeHigh,
                                            m_queueBufferSize);
        m_v1modelSwitch->InitializeSwitchFromP4Json(m_jsonPath);
        m_v1modelSwitch->LoadFlowTableToSwitch(m_flowTablePath);
        m_v1modelSwitch->start_and_return_();
        break;

    case P4SWITCH_ARCH_PSA:
        NS_LOG_DEBUG("Initialising PSA pipeline");
        m_psaSwitch = new P4CorePsa(this,
                                    m_enableSwap,
                                    m_enableTracing,
                                    m_switchRate,
                                    m_InputBufferSizeLow,
                                    m_queueBufferSize);
        m_psaSwitch->InitializeSwitchFromP4Json(m_jsonPath);
        m_psaSwitch->LoadFlowTableToSwitch(m_flowTablePath);
        m_psaSwitch->start_and_return_();
        break;

    case P4NIC_ARCH_PNA:
        NS_LOG_DEBUG("Initialising PNA NIC");
        m_pnaNic = new P4PnaNic(this, m_enableSwap);
        m_pnaNic->InitializeSwitchFromP4Json(m_jsonPath);
        m_pnaNic->start_and_return_();
        break;

    case P4SWITCH_ARCH_PIPELINE:
        NS_LOG_DEBUG("Initialising simple Pipeline");
        m_p4Pipeline = new P4CorePipeline(this, m_enableSwap, m_enableTracing);
        m_p4Pipeline->InitializeSwitchFromP4Json(m_jsonPath);
        m_p4Pipeline->LoadFlowTableToSwitch(m_flowTablePath);
        m_p4Pipeline->start_and_return_();
        break;

    default:
        NS_FATAL_ERROR("Unknown P4 switch architecture: " << m_switchArch);
    }

    NetDevice::DoInitialize();
}

void
P4SwitchNetDevice::DoDispose()
{
    NS_LOG_FUNCTION_NOARGS();

    delete m_v1modelSwitch;
    m_v1modelSwitch = nullptr;
    delete m_p4Pipeline;
    m_p4Pipeline = nullptr;
    delete m_psaSwitch;
    m_psaSwitch = nullptr;
    delete m_pnaNic;
    m_pnaNic = nullptr;

    m_portChannels.clear();
    m_portDeviceIds.clear();
    m_node = nullptr;

    NetDevice::DoDispose();
}

// ---------------------------------------------------------------------------
// Channel attachment
// ---------------------------------------------------------------------------

void
P4SwitchNetDevice::Attach(Ptr<SwitchedEthernetChannel> channel)
{
    NS_LOG_FUNCTION(this << channel);
    NS_ASSERT_MSG(channel, "Attach: null channel");

    int32_t devId = channel->Attach(this);
    NS_ASSERT_MSG(devId >= 0, "Attach: channel rejected device (already full?)");

    m_portChannels.push_back(channel);
    m_portDeviceIds.push_back(static_cast<uint32_t>(devId));

    NS_LOG_INFO("Attached to channel as port " << (m_portChannels.size() - 1) << " (channel slot "
                                               << devId << ")");
}

// ---------------------------------------------------------------------------
// Ingress: called directly by SwitchedEthernetChannel
// ---------------------------------------------------------------------------

void
P4SwitchNetDevice::Receive(Ptr<Packet> packet, Ptr<P4SwitchNetDevice> sender)
{
    NS_LOG_FUNCTION_NOARGS();
    NS_LOG_DEBUG("UID=" << packet->GetUid());

    // The packet arrives as a full Ethernet frame.  Peek at the header to
    // recover src/dst/protocol for callbacks and P4 metadata.
    EthernetHeader eth;
    packet->PeekHeader(eth);

    Mac48Address src48 = eth.GetSource();
    Mac48Address dst48 = eth.GetDestination();
    uint16_t proto = eth.GetLengthType();

    // Promiscuous sniffer (e.g. pcap): fire for every frame.
    if (!m_promiscRxCallback.IsNull())
    {
        m_promiscRxCallback(this, packet, proto, src48, dst48, PACKET_OTHERHOST);
    }

    // NIC / passthrough mode: no P4 core — deliver up the stack.
    bool hasCore = (m_v1modelSwitch || m_psaSwitch || m_pnaNic || m_p4Pipeline);
    if (!hasCore)
    {
        // Strip the Ethernet header before handing to the IP stack.
        Ptr<Packet> stripped = packet->Copy();
        EthernetHeader hdr;
        stripped->RemoveHeader(hdr);

        if (!m_rxCallback.IsNull())
        {
            m_rxCallback(this, stripped, proto, src48);
        }
        return;
    }

    // Switch mode: find the ingress port from the sender device.
    uint32_t inPort = GetPortNumber(sender);
    if (inPort == UINT32_MAX)
    {
        NS_LOG_WARN("Receive: sender not found in port list — dropping");
        return;
    }

    NS_LOG_DEBUG("Ingress port=" << inPort << " src=" << src48 << " dst=" << dst48 << " proto=0x"
                                 << std::hex << proto << std::dec);

    // Feed the full Ethernet frame into the P4 pipeline.
    Ptr<Packet> pkt = packet->Copy();
    switch (m_switchArch)
    {
    case P4SWITCH_ARCH_V1MODEL:
        m_v1modelSwitch->ReceivePacket(pkt, inPort, proto, dst48);
        break;
    case P4SWITCH_ARCH_PSA:
        m_psaSwitch->ReceivePacket(pkt, inPort, proto, dst48);
        break;
    case P4NIC_ARCH_PNA:
        m_pnaNic->ReceivePacket(pkt, inPort, proto, dst48);
        break;
    case P4SWITCH_ARCH_PIPELINE:
        m_p4Pipeline->ReceivePacket(pkt, inPort, proto, dst48);
        break;
    }
}

// ---------------------------------------------------------------------------
// Egress: called by P4 pipeline cores
// ---------------------------------------------------------------------------

void
P4SwitchNetDevice::SendPacket(Ptr<Packet> packetOut,
                              int outPort,
                              uint16_t protocol,
                              const Address& destination)
{
    SendNs3Packet(packetOut, outPort, protocol, destination);
}

void
P4SwitchNetDevice::SendNs3Packet(Ptr<Packet> packetOut,
                                 int outPort,
                                 uint16_t /*protocol*/,
                                 const Address& /*destination*/)
{
    NS_LOG_DEBUG("SendNs3Packet: port=" << outPort);

    if (!packetOut)
    {
        NS_LOG_DEBUG("Null packet — dropping");
        return;
    }

    // Port 511 = P4 convention for drop.
    if (outPort == 511)
    {
        NS_LOG_DEBUG("Drop port (511) — packet discarded");
        return;
    }

    if (outPort < 0 || static_cast<size_t>(outPort) >= m_portChannels.size())
    {
        NS_LOG_WARN("SendNs3Packet: invalid port " << outPort << " (" << m_portChannels.size()
                                                   << " ports available)");
        return;
    }

    // The P4 pipeline delivers a full Ethernet frame.
    // Transmit it directly onto the channel.
    Ptr<SwitchedEthernetChannel> ch = m_portChannels[static_cast<size_t>(outPort)];
    uint32_t devId = m_portDeviceIds[static_cast<size_t>(outPort)];
    TransmitOn(ch, devId, packetOut);
}

void
P4SwitchNetDevice::TransmitOn(Ptr<SwitchedEthernetChannel> channel,
                              uint32_t devId,
                              Ptr<Packet> packet)
{
    if (!channel->TransmitStart(packet, devId))
    {
        NS_LOG_WARN("TransmitOn: channel busy or device inactive — packet dropped");
        return;
    }

    // Compute serialisation delay from the channel's data rate.
    DataRate bps = channel->GetDataRate();
    Time txTime = bps.CalculateBytesTxTime(packet->GetSize());

    Simulator::Schedule(txTime, &SwitchedEthernetChannel::TransmitEnd, channel, devId);
}

// ---------------------------------------------------------------------------
// Port accessors
// ---------------------------------------------------------------------------

uint32_t
P4SwitchNetDevice::GetNPorts() const
{
    return static_cast<uint32_t>(m_portChannels.size());
}

Ptr<SwitchedEthernetChannel>
P4SwitchNetDevice::GetPortChannel(uint32_t n) const
{
    if (n >= m_portChannels.size())
    {
        return nullptr;
    }
    return m_portChannels[n];
}

uint32_t
P4SwitchNetDevice::GetPortNumber(Ptr<P4SwitchNetDevice> sender) const
{
    // Find the port whose far end is `sender`.
    for (uint32_t i = 0; i < m_portChannels.size(); ++i)
    {
        uint32_t mySlot = m_portDeviceIds[i];
        uint32_t otherSlot = (mySlot == 0) ? 1 : 0;

        if (m_portChannels[i]->GetNDevices() > otherSlot &&
            m_portChannels[i]->GetP4SwitchDevice(otherSlot) == sender)
        {
            return i;
        }
    }
    return UINT32_MAX;
}

// ---------------------------------------------------------------------------
// P4 core accessors / trace helpers
// ---------------------------------------------------------------------------

P4CoreV1model*
P4SwitchNetDevice::GetV1ModelCore() const
{
    return m_v1modelSwitch;
}

void
P4SwitchNetDevice::EmitSwitchEvent(uint32_t id, const std::string& msg)
{
    m_switchEvent(id, msg);
}

void
P4SwitchNetDevice::ConnectCoreEvent()
{
    // Intentionally empty: override or call after DoInitialize() to wire
    // pipeline-internal traces to m_switchEvent.
}

// ---------------------------------------------------------------------------
// P4 config getters / setters
// ---------------------------------------------------------------------------

void
P4SwitchNetDevice::SetJsonPath(const std::string& p)
{
    m_jsonPath = p;
}

std::string
P4SwitchNetDevice::GetJsonPath() const
{
    return m_jsonPath;
}

void
P4SwitchNetDevice::SetFlowTablePath(const std::string& p)
{
    m_flowTablePath = p;
}

std::string
P4SwitchNetDevice::GetFlowTablePath() const
{
    return m_flowTablePath;
}

// ---------------------------------------------------------------------------
// NetDevice interface
// ---------------------------------------------------------------------------

void
P4SwitchNetDevice::SetIfIndex(const uint32_t index)
{
    m_ifIndex = index;
}

uint32_t
P4SwitchNetDevice::GetIfIndex() const
{
    return m_ifIndex;
}

Ptr<Channel>
P4SwitchNetDevice::GetChannel() const
{
    // Return the first attached channel as the representative channel.
    if (!m_portChannels.empty())
    {
        return m_portChannels[0];
    }
    return nullptr;
}


void
P4SwitchNetDevice::SetAddress(Address address)
{
    m_address = Mac48Address::ConvertFrom(address);
}

Address
P4SwitchNetDevice::GetAddress() const
{
    return m_address;
}

bool
P4SwitchNetDevice::SetMtu(const uint16_t mtu)
{
    m_mtu = mtu;
    return true;
}

uint16_t
P4SwitchNetDevice::GetMtu() const
{
    return m_mtu;
}

bool
P4SwitchNetDevice::IsLinkUp() const
{
    return !m_portChannels.empty();
}

void
P4SwitchNetDevice::AddLinkChangeCallback(Callback<void> /*callback*/)
{
    // Not supported for a multi-port device.
}

bool
P4SwitchNetDevice::IsBroadcast() const
{
    return true;
}

Address
P4SwitchNetDevice::GetBroadcast() const
{
    return Mac48Address::GetBroadcast();
}

bool
P4SwitchNetDevice::IsMulticast() const
{
    return true;
}

Address
P4SwitchNetDevice::GetMulticast(Ipv4Address multicastGroup) const
{
    return Mac48Address::GetMulticast(multicastGroup);
}

Address
P4SwitchNetDevice::GetMulticast(Ipv6Address addr) const
{
    return Mac48Address::GetMulticast(addr);
}

bool
P4SwitchNetDevice::IsPointToPoint() const
{
    return false;
}

bool
P4SwitchNetDevice::IsBridge() const
{
    return false;
}

bool
P4SwitchNetDevice::Send(Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber)
{
    return SendFrom(packet, m_address, dest, protocolNumber);
}

bool
P4SwitchNetDevice::SendFrom(Ptr<Packet> packet,
                            const Address& src,
                            const Address& dest,
                            uint16_t protocolNumber)
{
    NS_LOG_FUNCTION_NOARGS();

    // Build an Ethernet frame and send it out on all attached channels
    // (used for management / control-plane traffic from the node's IP stack).
    EthernetHeader eth;
    eth.SetSource(Mac48Address::ConvertFrom(src));
    eth.SetDestination(Mac48Address::ConvertFrom(dest));
    eth.SetLengthType(protocolNumber);

    for (std::size_t i = 0; i < m_portChannels.size(); ++i)
    {
        Ptr<Packet> frame = packet->Copy();
        frame->AddHeader(eth);
        TransmitOn(m_portChannels[i], m_portDeviceIds[i], frame);
    }
    return true;
}

Ptr<Node>
P4SwitchNetDevice::GetNode() const
{
    return m_node;
}

void
P4SwitchNetDevice::SetNode(Ptr<Node> n)
{
    m_node = n;
}

bool
P4SwitchNetDevice::NeedsArp() const
{
    return true;
}

void
P4SwitchNetDevice::SetReceiveCallback(NetDevice::ReceiveCallback cb)
{
    m_rxCallback = cb;
}

void
P4SwitchNetDevice::SetPromiscReceiveCallback(NetDevice::PromiscReceiveCallback cb)
{
    m_promiscRxCallback = cb;
}

bool
P4SwitchNetDevice::SupportsSendFrom() const
{
    return true;
}

} // namespace ns3
