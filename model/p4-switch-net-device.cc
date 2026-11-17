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

#include "ns3/p4-switch-net-device.h"

#include "p4-switch-net-device.h"

#include "ns3/boolean.h"
#include "ns3/ethernet-header.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/p4-bridge-channel.h"
#include "ns3/p4-core-pipeline.h"
#include "ns3/p4-core-psa.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-nic-pna.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/uinteger.h"

#include <cstdint>

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

            .AddAttribute("ChannelType",
                          "Kept for main's examples, no effect: the ports are set by "
                          "Attach() and AddBridgePort().",
                          UintegerValue(P4CHANNELCSMA),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_channelType),
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

            .AddAttribute(
                "BmLogLevel",
                "Level of the BMv2 pipeline log written to "
                "/tmp/bmv2-<thrift port>-pipeline.log: trace, debug, info, notice, "
                "warn, error, critical, alert, emerg or off. With off, no log file "
                "is written, which also speeds up the simulation. The BMv2 logger "
                "is shared by all switches of a simulation, so use the same level "
                "for all of them (e.g. with Config::SetDefault).",
                StringValue("trace"),
                MakeStringAccessor(&P4SwitchNetDevice::m_bmLogLevel),
                MakeStringChecker())

            .AddAttribute(
                "ThriftPort",
                "Thrift port of the switch, used by the runtime CLI that loads "
                "the flow table. 0 picks the first free port, starting at "
                "$P4SIM_THRIFT_PORT_BASE (9090 if unset). A port is free if no "
                "other p4sim process has reserved it and no program listens on it.",
                UintegerValue(0),
                MakeUintegerAccessor(&P4SwitchNetDevice::m_thriftPort),
                MakeUintegerChecker<uint16_t>())

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
                          "Packet rate of the whole P4 pipeline (packets per second). "
                          "0 (the default) means no limit, as in a hardware switch. With a "
                          "rate R, the pipeline takes one packet per 1/R (resubmitted and "
                          "recirculated passes included); packets that arrive meanwhile wait "
                          "in the input buffer, and are dropped (MacRxDrop) when it is full.",
                          UintegerValue(0),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_switchRate),
                          MakeUintegerChecker<uint64_t>())

            .AddAttribute("EnableVoqFabric",
                          "If true, a V1model switch routes post-ingress traffic through the "
                          "VOQ + fabric Traffic Manager instead of the legacy output queues. "
                          "Default false keeps the legacy output-queued datapath.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&P4SwitchNetDevice::m_enableVoqFabric),
                          MakeBooleanChecker())

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
                            "ns3::Packet::TracedCallback")

            .AddTraceSource("MacRxDrop",
                            "A received packet was dropped because the input buffer of the "
                            "P4 pipeline was full (see SwitchRate)",
                            MakeTraceSourceAccessor(&P4SwitchNetDevice::m_macRxDropTrace),
                            "ns3::Packet::TracedCallback")
            //
            // Trace sources designed to simulate a packet sniffer facility (tcpdump).
            //
            .AddTraceSource("Sniffer",
                            "Trace source simulating a non-promiscuous "
                            "packet sniffer attached to the device",
                            MakeTraceSourceAccessor(&P4SwitchNetDevice::m_snifferTrace),
                            "ns3::Packet::TracedCallback")
            .AddTraceSource("PromiscSniffer",
                            "Trace source simulating a promiscuous "
                            "packet sniffer attached to the device",
                            MakeTraceSourceAccessor(&P4SwitchNetDevice::m_promiscSnifferTrace),
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
      m_bmLogLevel("trace"),
      m_thriftPort(0),
      m_v1modelSwitch(nullptr),
      m_psaSwitch(nullptr),
      m_pnaNic(nullptr),
      m_InputBufferSizeLow(1024),
      m_InputBufferSizeHigh(1024),
      m_queueBufferSize(1024),
      m_switchRate(0),
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
        m_v1modelSwitch = std::make_unique<P4CoreV1model>(this,
                                                          m_enableSwap,
                                                          m_enableTracing,
                                                          m_switchRate,
                                                          m_InputBufferSizeLow,
                                                          m_InputBufferSizeHigh,
                                                          m_queueBufferSize);
        ConfigureCore(*m_v1modelSwitch);
        m_v1modelSwitch->InitializeSwitchFromP4Json(m_jsonPath);
        m_v1modelSwitch->LoadFlowTableToSwitch(m_flowTablePath);
        m_v1modelSwitch->SetEnableVoqFabric(m_enableVoqFabric);
        SetPortTxDoneCallback(MakeCallback(&P4CoreV1model::PortTxComplete, m_v1modelSwitch.get()));
        m_v1modelSwitch->start_and_return_();
        break;

    case P4SWITCH_ARCH_PSA:
        NS_LOG_DEBUG("Initialising PSA pipeline");
        m_psaSwitch = std::make_unique<P4CorePsa>(this,
                                                  m_enableSwap,
                                                  m_enableTracing,
                                                  m_switchRate,
                                                  m_InputBufferSizeLow,
                                                  m_queueBufferSize);
        ConfigureCore(*m_psaSwitch);
        m_psaSwitch->InitializeSwitchFromP4Json(m_jsonPath);
        m_psaSwitch->LoadFlowTableToSwitch(m_flowTablePath);
        SetPortTxDoneCallback(MakeCallback(&P4CorePsa::PortTxComplete, m_psaSwitch.get()));
        m_psaSwitch->start_and_return_();
        break;

    case P4NIC_ARCH_PNA:
        NS_LOG_DEBUG("Initialising PNA NIC");
        m_pnaNic = std::make_unique<P4PnaNic>(this, m_enableSwap);
        ConfigureCore(*m_pnaNic);
        m_pnaNic->InitializeSwitchFromP4Json(m_jsonPath);
        m_pnaNic->start_and_return_();
        break;

    case P4SWITCH_ARCH_PIPELINE:
        NS_LOG_DEBUG("Initialising pipeline core");
        m_p4Pipeline = std::make_unique<P4CorePipeline>(this, m_enableSwap, m_enableTracing);
        ConfigureCore(*m_p4Pipeline);
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

    // The callback points into the core deleted below.
    m_portTxDone = MakeNullCallback<void, uint32_t>();
    m_v1modelSwitch.reset();
    m_psaSwitch.reset();
    m_pnaNic.reset();
    m_p4Pipeline.reset();

    m_portChannels.clear();
    m_portDeviceIds.clear();
    m_bridgePorts.clear();
    m_bridgePortTxEnd.clear();
    m_bridgeChannel = nullptr;
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
    m_bridgePorts.push_back(nullptr);
    m_bridgePortTxEnd.push_back(false);

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
        m_promiscSnifferTrace(packet);
        m_snifferTrace(packet);
        m_macRxTrace(packet);

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

    DeliverToCore(packet->Copy(), inPort, proto, dst48);
}

void
P4SwitchNetDevice::DeliverToCore(Ptr<Packet> frame,
                                 uint32_t inPort,
                                 uint16_t protocol,
                                 Mac48Address dst)
{
    if (!m_v1modelSwitch && !m_psaSwitch && !m_pnaNic && !m_p4Pipeline)
    {
        NS_LOG_WARN("No P4 core, dropping frame received on port " << inPort);
        return;
    }

    m_promiscSnifferTrace(frame);
    m_snifferTrace(frame);
    m_macRxTrace(frame);

    // Feed the full Ethernet frame into the P4 pipeline.
    switch (m_switchArch)
    {
    case P4SWITCH_ARCH_V1MODEL:
        m_v1modelSwitch->ReceivePacket(frame, inPort, protocol, dst);
        break;
    case P4SWITCH_ARCH_PSA:
        m_psaSwitch->ReceivePacket(frame, inPort, protocol, dst);
        break;
    case P4NIC_ARCH_PNA:
        m_pnaNic->ReceivePacket(frame, inPort, protocol, dst);
        break;
    case P4SWITCH_ARCH_PIPELINE:
        m_p4Pipeline->ReceivePacket(frame, inPort, protocol, dst);
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

bool
P4SwitchNetDevice::SendNs3Packet(Ptr<Packet> packetOut,
                                 int outPort,
                                 uint16_t /*protocol*/,
                                 const Address& /*destination*/,
                                 Time* txTime)
{
    NS_LOG_DEBUG("SendNs3Packet: port=" << outPort);

    if (!packetOut)
    {
        NS_LOG_DEBUG("Null packet — dropping");
        return false;
    }

    // Port 511 = P4 convention for drop.
    if (outPort == 511)
    {
        NS_LOG_DEBUG("Drop port (511) — packet discarded");
        m_macTxDropTrace(packetOut);
        return false;
    }

    if (outPort < 0 || static_cast<size_t>(outPort) >= m_portChannels.size())
    {
        NS_LOG_WARN("SendNs3Packet: invalid port " << outPort << " (" << m_portChannels.size()
                                                   << " ports available)");
        m_macTxDropTrace(packetOut);
        return false;
    }

    m_macTxTrace(packetOut);
    m_snifferTrace(packetOut);
    m_promiscSnifferTrace(packetOut);

    // The P4 pipeline delivers a full Ethernet frame.
    if (m_bridgePorts[outPort])
    {
        return SendOnBridgePort(static_cast<uint32_t>(outPort), packetOut, txTime);
    }
    // Transmit it directly onto the channel.
    return TransmitOn(static_cast<uint32_t>(outPort), packetOut, txTime);
}

bool
P4SwitchNetDevice::TransmitOn(uint32_t port, Ptr<Packet> packet, Time* txTime)
{
    Ptr<SwitchedEthernetChannel> channel = m_portChannels[port];
    if (!channel->TransmitStart(packet, m_portDeviceIds[port]))
    {
        NS_LOG_WARN("TransmitOn: channel busy or device inactive — packet dropped");
        m_macTxDropTrace(packet);
        return false;
    }

    // Compute serialisation delay from the channel's data rate.
    DataRate bps = channel->GetDataRate();
    Time serialisationTime = bps.CalculateBytesTxTime(packet->GetSize());

    Simulator::Schedule(serialisationTime, &P4SwitchNetDevice::PortTransmitEnd, this, port);

    if (txTime)
    {
        *txTime = serialisationTime;
    }
    return true;
}

void
P4SwitchNetDevice::PortTransmitEnd(uint32_t port)
{
    if (port >= m_portChannels.size())
    {
        return; // the device was disposed while the frame was on the wire
    }
    m_portChannels[port]->TransmitEnd(m_portDeviceIds[port]);
    if (!m_portTxDone.IsNull())
    {
        m_portTxDone(port);
    }
}

void
P4SwitchNetDevice::SetPortTxDoneCallback(Callback<void, uint32_t> cb)
{
    m_portTxDone = cb;
}

// ---------------------------------------------------------------------------
// Bridge ports
// ---------------------------------------------------------------------------

void
P4SwitchNetDevice::AddBridgePort(Ptr<NetDevice> bridgePort)
{
    NS_LOG_FUNCTION(this << bridgePort);
    NS_ASSERT_MSG(bridgePort && bridgePort != this, "AddBridgePort: invalid device");
    NS_ASSERT_MSG(m_node, "AddBridgePort: add the switch device to its node first");
    if (!Mac48Address::IsMatchingType(bridgePort->GetAddress()))
    {
        NS_FATAL_ERROR("Device does not support EUI-48 addresses: cannot be a bridge port.");
    }
    if (!bridgePort->SupportsSendFrom())
    {
        NS_FATAL_ERROR("Device does not support SendFrom: cannot be a bridge port.");
    }
    if (m_address == Mac48Address())
    {
        m_address = Mac48Address::ConvertFrom(bridgePort->GetAddress());
    }

    auto port = static_cast<uint32_t>(m_portChannels.size());
    m_portChannels.push_back(nullptr);
    m_portDeviceIds.push_back(UINT32_MAX);
    m_bridgePorts.push_back(bridgePort);

    m_node->RegisterProtocolHandler(MakeCallback(&P4SwitchNetDevice::ReceiveFromDevice, this),
                                    0,
                                    bridgePort,
                                    true);
    // The end of each transmission frees the port for the P4 core, as
    // PortTransmitEnd() does for a switched-Ethernet port.
    bool connected = false;
    for (const char* trace : {"PhyTxEnd", "PhyTxDrop"})
    {
        connected |= bridgePort->TraceConnectWithoutContext(
            trace,
            MakeCallback(&P4SwitchNetDevice::BridgePortTxEnd, this).Bind(port));
    }
    // Without these traces the port is free again as soon as the device has
    // taken a frame (see SendOnBridgePort()).
    m_bridgePortTxEnd.push_back(connected);
    if (!connected)
    {
        NS_LOG_INFO("AddBridgePort: " << bridgePort->GetInstanceTypeId().GetName()
                                      << " reports no end of transmission; its queue holds "
                                         "the frames that wait");
    }

    if (!m_bridgeChannel)
    {
        m_bridgeChannel = CreateObject<P4BridgeChannel>();
    }
    if (bridgePort->GetChannel())
    {
        m_bridgeChannel->AddChannel(bridgePort->GetChannel());
    }
    NS_LOG_INFO("Added " << bridgePort->GetInstanceTypeId().GetName() << " as bridge port "
                         << port);
}

uint32_t
P4SwitchNetDevice::GetNBridgePorts() const
{
    return GetNPorts();
}

Ptr<NetDevice>
P4SwitchNetDevice::GetBridgePort(uint32_t n) const
{
    if (n >= m_bridgePorts.size())
    {
        return nullptr;
    }
    return m_bridgePorts[n];
}

uint32_t
P4SwitchNetDevice::GetBridgePortNumber(Ptr<NetDevice> device) const
{
    for (uint32_t i = 0; i < m_bridgePorts.size(); ++i)
    {
        if (m_bridgePorts[i] && m_bridgePorts[i] == device)
        {
            return i;
        }
    }
    return UINT32_MAX;
}

DataRate
P4SwitchNetDevice::GetPortDataRate(uint32_t n) const
{
    if (n < m_portChannels.size() && m_portChannels[n])
    {
        return m_portChannels[n]->GetDataRate();
    }
    if (n < m_bridgePorts.size() && m_bridgePorts[n])
    {
        DataRateValue rate;
        if (m_bridgePorts[n]->GetAttributeFailSafe("DataRate", rate))
        {
            return rate.Get(); // point-to-point devices
        }
        Ptr<Channel> channel = m_bridgePorts[n]->GetChannel();
        if (channel && channel->GetAttributeFailSafe("DataRate", rate))
        {
            return rate.Get(); // CSMA channels
        }
    }
    return DataRate(0);
}

void
P4SwitchNetDevice::ReceiveFromDevice(Ptr<NetDevice> incomingPort,
                                     Ptr<const Packet> packet,
                                     uint16_t protocol,
                                     const Address& src,
                                     const Address& dst,
                                     PacketType packetType)
{
    NS_LOG_FUNCTION(this << incomingPort << packet);
    uint32_t inPort = GetBridgePortNumber(incomingPort);
    if (inPort == UINT32_MAX)
    {
        NS_LOG_WARN("ReceiveFromDevice: " << incomingPort << " is not a bridge port, dropping");
        return;
    }
    Mac48Address src48 = Mac48Address::ConvertFrom(src);
    Mac48Address dst48 = Mac48Address::ConvertFrom(dst);

    if (!m_promiscRxCallback.IsNull())
    {
        m_promiscRxCallback(this, packet, protocol, src48, dst48, PACKET_OTHERHOST);
    }

    // The port device has removed the frame's Ethernet header, and the P4
    // parser expects one: rebuild it from the frame's addresses and EtherType.
    Ptr<Packet> frame = packet->Copy();
    EthernetHeader eth;
    eth.SetSource(src48);
    eth.SetDestination(dst48);
    eth.SetLengthType(protocol);
    frame->AddHeader(eth);

    DeliverToCore(frame, inPort, protocol, dst48);
}

bool
P4SwitchNetDevice::SendOnBridgePort(uint32_t port, Ptr<Packet> frame, Time* txTime)
{
    // The port device adds its own header, so hand it the frame's addresses
    // and EtherType without the Ethernet header.
    Ptr<Packet> payload = frame->Copy();
    EthernetHeader eth;
    if (payload->RemoveHeader(eth) == 0)
    {
        NS_LOG_WARN("SendOnBridgePort: frame without an Ethernet header, dropping");
        m_macTxDropTrace(frame);
        return false;
    }
    if (!m_bridgePorts[port]->SendFrom(payload,
                                       eth.GetSource(),
                                       eth.GetDestination(),
                                       eth.GetLengthType()))
    {
        NS_LOG_WARN("SendOnBridgePort: port " << port << " did not take the frame, dropping");
        m_macTxDropTrace(frame);
        return false;
    }
    if (txTime)
    {
        *txTime = GetPortDataRate(port).CalculateBytesTxTime(frame->GetSize());
    }
    if (!m_bridgePortTxEnd[port])
    {
        // The device will not report the end of the transmission: the port is
        // free again now, and the device's queue holds the frames that wait.
        Simulator::ScheduleNow(&P4SwitchNetDevice::BridgePortTxEnd,
                               this,
                               port,
                               Ptr<const Packet>());
    }
    return true;
}

void
P4SwitchNetDevice::BridgePortTxEnd(uint32_t port, Ptr<const Packet> /*packet*/)
{
    if (!m_portTxDone.IsNull())
    {
        m_portTxDone(port);
    }
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
        if (!m_portChannels[i])
        {
            continue; // a bridge port
        }
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

uint32_t
P4SwitchNetDevice::GetPortDeviceId(uint32_t n) const
{
    if (n<m_portDeviceIds.size())
    {
        return m_portDeviceIds[n];
    }
    return UINT32_MAX;
}

// ---------------------------------------------------------------------------
// P4 core accessors / trace helpers
// ---------------------------------------------------------------------------

P4CoreV1model*
P4SwitchNetDevice::GetV1ModelCore() const
{
    return m_v1modelSwitch.get();
}

void
P4SwitchNetDevice::ConfigureCore(P4SwitchCore& core) const
{
    core.SetBmLogLevel(m_bmLogLevel);
    core.SetThriftPort(m_thriftPort);
}

int
P4SwitchNetDevice::GetThriftPort() const
{
    if (m_v1modelSwitch)
    {
        return m_v1modelSwitch->GetThriftPort();
    }
    if (m_psaSwitch)
    {
        return m_psaSwitch->GetThriftPort();
    }
    if (m_pnaNic)
    {
        return m_pnaNic->GetThriftPort();
    }
    if (m_p4Pipeline)
    {
        return m_p4Pipeline->GetThriftPort();
    }
    return 0;
}

void
P4SwitchNetDevice::EmitSwitchEvent(uint32_t id, const std::string& msg)
{
    m_switchEvent(id, msg);
}

void
P4SwitchNetDevice::NotifyMacRxDrop(Ptr<const Packet> packet)
{
    m_macRxDropTrace(packet);
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
    // Return the channel of port 0 as the representative channel.
    if (!m_portChannels.empty() && m_portChannels[0])
    {
        return m_portChannels[0];
    }
    return m_bridgeChannel;
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

    m_macTxTrace(packet);

    for (std::size_t i = 0; i < m_portChannels.size(); ++i)
    {
        Ptr<Packet> frame = packet->Copy();
        frame->AddHeader(eth);
        m_promiscSnifferTrace(frame);
        m_snifferTrace(frame);
        if (m_bridgePorts[i])
        {
            SendOnBridgePort(static_cast<uint32_t>(i), frame, nullptr);
        }
        else
        {
            TransmitOn(static_cast<uint32_t>(i), frame);
        }
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
