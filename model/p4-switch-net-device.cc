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
#include "ns3/enum.h"
#include "ns3/ethernet-header.h"
#include "ns3/link-framing.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/p4-bridge-channel.h"
#include "ns3/p4-core-pipeline.h"
#include "ns3/p4-core-psa.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-nic-pna.h"
#include "ns3/p4sim-ns3-compat.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/uinteger.h"

#include <algorithm>
#include <cstdint>
#include <iostream>

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
                          "No effect. To trace packets, use the trace sources of the "
                          "devices (MacTx, MacRx, ...), PacketSink or FlowMonitor.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&P4SwitchNetDevice::m_enableTracing),
                          MakeBooleanChecker(),
                          TypeId::SupportLevel::DEPRECATED,
                          "it has no effect and will be removed in the next major version. "
                          "To trace packets, use the trace sources of the devices (MacTx, "
                          "MacRx, ...), PacketSink or FlowMonitor.")

            .AddAttribute("EnableSwap",
                          "Allow swapping the P4 program at run time: load_new_config and "
                          "swap_configs of the runtime CLI, or P4Controller::LoadNewConfig() "
                          "and SwapConfigs(). The switch swaps once it holds no packet; frames "
                          "that arrive meanwhile wait and then use the new program.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&P4SwitchNetDevice::m_enableSwap),
                          MakeBooleanChecker())

            .AddAttribute("P4SwitchArch",
                          "P4 pipeline architecture: 0=V1model, 1=PSA, 2=PNA, 3=Pipeline.",
                          UintegerValue(P4SWITCH_ARCH_V1MODEL),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_switchArch),
                          MakeUintegerChecker<uint32_t>())

            .AddAttribute("ChannelType",
                          "No effect: the ports are set by Attach() and AddBridgePort().",
                          UintegerValue(P4CHANNELCSMA),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_channelType),
                          MakeUintegerChecker<uint32_t>(),
                          TypeId::SupportLevel::DEPRECATED,
                          "it has no effect and will be removed in the next major version. "
                          "The ports are set by Attach() and AddBridgePort().")

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

            .AddAttribute("BmLogLevel",
                          "Level of the BMv2 pipeline log written to "
                          "/tmp/bmv2-<thrift port>-pipeline.log.txt: trace, debug, info, notice, "
                          "warn, error, critical, alert, emerg or off. With off (the default), "
                          "no log file is written; trace logs every step of every packet, "
                          "which helps to debug a P4 program but slows the simulation down. "
                          "The BMv2 logger is shared by all switches of a simulation, so use "
                          "the same level for all of them (e.g. with Config::SetDefault).",
                          StringValue("off"),
                          MakeStringAccessor(&P4SwitchNetDevice::m_bmLogLevel),
                          MakeStringChecker())

            .AddAttribute("ThriftPort",
                          "Thrift port of the switch, used by the runtime CLI that loads "
                          "the flow table. 0 picks the first free port, starting at "
                          "$P4SIM_THRIFT_PORT_BASE (9090 if unset). A port is free if no "
                          "other p4sim process has reserved it and no program listens on it.",
                          UintegerValue(0),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_thriftPort),
                          MakeUintegerChecker<uint16_t>())

            .AddAttribute("InputBufferSizeLow",
                          "Capacity of the input buffer for the packets received on the "
                          "ports, in packets (PSA: for all packets that enter the ingress).",
                          UintegerValue(128),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_InputBufferSizeLow),
                          MakeUintegerChecker<size_t>())

            .AddAttribute("InputBufferSizeHigh",
                          "v1model: capacity of the input buffer for resubmitted and "
                          "recirculated packets, in packets. The ingress takes these "
                          "before the packets received on the ports.",
                          UintegerValue(128),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_InputBufferSizeHigh),
                          MakeUintegerChecker<size_t>())

            .AddAttribute("QueueBufferSize",
                          "Capacity of each output queue, in packets: per port and "
                          "priority (v1model, PSA), or per port (PNA). The queue_capacity "
                          "of a TargetProfile, if it gives one above 0, replaces it.",
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

            .AddAttribute(
                "PipelineDelay",
                "Time a packet spends in the P4 pipeline (parser, ingress, egress "
                "and deparser), as a fixed latency: every packet reaches the egress "
                "queues this much later, clones and multicast copies included; the "
                "egress then takes no time. The pipeline takes the next packet at "
                "once, so the delay does not lower the throughput (see SwitchRate). "
                "A recirculated packet passes the pipeline again and is delayed "
                "again. 0 (the default) means no delay. For scale: on Tofino, the ingress block "
                "(parser, control, deparser) was measured at 162 to 224 ns on 100G "
                "ports and 221 to 472 ns on 10G ports, depending on the program "
                "(Franco et al., Computer Communications 218, 2024).",
                TimeValue(Seconds(0)),
                MakeTimeAccessor(&P4SwitchNetDevice::m_pipelineDelay),
                MakeTimeChecker(Seconds(0)))

            .AddAttribute("TransferBufferSize",
                          "Frames that a port holds after the egress pipeline, besides the one "
                          "it is sending: the hardware port queue. A port takes its next "
                          "packet from the output queues when it is idle or this buffer has "
                          "room; the packet passes the egress at once and then waits here, in "
                          "order, so the backlog of a congested port stays in the output "
                          "queues, where the priorities apply, and a frame in this buffer is "
                          "not overtaken. The buffer never drops. 0 (the default): a port "
                          "takes its next packet only when it is idle. v1model and PSA; not "
                          "with EnableVoqFabric; PNA and the pipeline core ignore it.",
                          UintegerValue(0),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_transferBufferSize),
                          MakeUintegerChecker<uint32_t>())

            .AddAttribute("EnableVoqFabric",
                          "If true, a V1model switch routes post-ingress traffic through the "
                          "VOQ + fabric Traffic Manager instead of the legacy output queues. "
                          "Default false keeps the legacy output-queued datapath.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&P4SwitchNetDevice::m_enableVoqFabric),
                          MakeBooleanChecker())

            .AddAttribute("TargetProfile",
                          "A target profile (doc/latency-model.md): the name of a profile in "
                          "the folder profiles/ (\"tofino-like\", \"cut-through-reference\") or "
                          "a JSON file. It gives the latency of each packet from its arrival "
                          "to the egress queues, instead of PipelineDelay, and the forwarding "
                          "mode, buffering and lookup limits of the target. Empty (the "
                          "default): none.",
                          StringValue(""),
                          MakeStringAccessor(&P4SwitchNetDevice::m_targetProfileName),
                          MakeStringChecker())

            .AddAttribute("LearningTable",
                          "An exact-match table that the switch fills from the digests of the "
                          "P4 program, with the limits of the target profile (table_capacity, "
                          "eviction, entry_lifetime_s, learning_path): the first field of a "
                          "digest is the key, the others the parameters of LearningAction. "
                          "Empty (the default): none.",
                          StringValue(""),
                          MakeStringAccessor(&P4SwitchNetDevice::m_learningTableName),
                          MakeStringChecker())

            .AddAttribute("LearningAction",
                          "The action of the entries of LearningTable.",
                          StringValue(""),
                          MakeStringAccessor(&P4SwitchNetDevice::m_learningActionName),
                          MakeStringChecker())

            .AddAttribute("ControlPlaneDelay",
                          "Time from a digest to its entry in LearningTable when the target "
                          "learns through the control plane. Negative (the default): the "
                          "target profile's control_plane_update_delay_ns.",
                          TimeValue(NanoSeconds(-1)),
                          MakeTimeAccessor(&P4SwitchNetDevice::m_controlPlaneDelay),
                          MakeTimeChecker())

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

            .AddTraceSource("FrameArrival",
                            "A frame arrived on a port of the switch: its first and last bit "
                            "(cut-through: when its decision bytes have arrived)",
                            MakeTraceSourceAccessor(&P4SwitchNetDevice::m_frameArrivalTrace),
                            "ns3::P4SwitchNetDevice::FrameArrivalTracedCallback")

            .AddTraceSource("Digest",
                            "The record of a digest() in the P4 program (v1model and the "
                            "pipeline core): the fields of its learn list at the end of the "
                            "ingress of the packet, at that time",
                            MakeTraceSourceAccessor(&P4SwitchNetDevice::m_digestTrace),
                            "ns3::P4SwitchNetDevice::DigestTracedCallback")
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
      m_bmLogLevel("off"),
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

    // The target profile: its forwarding mode needs a matching setup
    if (!m_targetProfileName.empty())
    {
        m_targetProfile = TargetProfile::Load(m_targetProfileName);
        const TargetProfile& profile = *m_targetProfile;
        if (profile.forwardingMode == TargetProfile::ForwardingMode::CUT_THROUGH)
        {
            NS_ABORT_MSG_IF(m_switchArch != P4SWITCH_ARCH_V1MODEL,
                            "Target profile " << profile.name
                                              << ": cut-through works with v1model switches only");
            NS_ABORT_MSG_IF(profile.queueCapacity != 0,
                            "Target profile " << profile.name
                                              << ": cut-through works without a queue only "
                                                 "(queue_capacity 0)");
            NS_ABORT_MSG_IF(profile.ingressModel != TargetProfile::IngressModel::FIXED,
                            "Target profile " << profile.name
                                              << ": cut-through needs a fixed latency");
            NS_ABORT_MSG_IF(m_switchRate > 0,
                            "Target profile " << profile.name
                                              << ": cut-through has no input buffer; "
                                                 "SwitchRate must be 0");
            for (const Ptr<NetDevice>& bridgePort : m_bridgePorts)
            {
                NS_ABORT_MSG_IF(bridgePort,
                                "Target profile " << profile.name
                                                  << ": cut-through needs switched-Ethernet "
                                                     "ports, not bridge ports");
            }
            m_cutThroughBytes = profile.decisionHeaderBytes;
        }
        if (profile.queueCapacity > 0)
        {
            m_queueBufferSize = static_cast<size_t>(profile.queueCapacity);
        }
        for (uint32_t port = 0; port < m_portChannels.size(); port++)
        {
            if (!m_portChannels[port])
            {
                continue;
            }
            if (profile.lineRateBps > 0 &&
                static_cast<double>(m_portChannels[port]->GetDataRate().GetBitRate()) !=
                    profile.lineRateBps)
            {
                std::cerr << "P4sim warning: target profile " << profile.name << " describes "
                          << DataRate(static_cast<uint64_t>(profile.lineRateBps)) << " ports; port "
                          << port << " has " << m_portChannels[port]->GetDataRate() << std::endl;
            }
            if (profile.preambleBytes > 0 &&
                m_portChannels[port]->GetFraming() == LinkFraming::NONE)
            {
                std::cerr << "P4sim warning: target profile " << profile.name
                          << " counts the preamble and the gap; the channel of port " << port
                          << " has no framing (set its Framing attribute to Ethernet)" << std::endl;
            }
        }
    }

    // Switch mode: boot the requested P4 pipeline.
    NS_LOG_INFO("P4SwitchNetDevice (switch mode, arch=" << m_switchArch << ", ports="
                                                        << m_portChannels.size() << ") on node "
                                                        << (m_node ? m_node->GetId() : 0));

    switch (m_switchArch)
    {
    case P4SWITCH_ARCH_V1MODEL:
        NS_LOG_DEBUG("Initialising V1model pipeline");
        // The VOQ traffic manager hands each port one frame at a time itself
        NS_ABORT_MSG_IF(m_enableVoqFabric && m_transferBufferSize > 0,
                        "TransferBufferSize does not work with EnableVoqFabric yet");
        m_v1modelSwitch = std::make_unique<P4CoreV1model>(this,
                                                          m_enableSwap,
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
        m_pnaNic = std::make_unique<P4PnaNic>(this, m_enableSwap, m_queueBufferSize);
        ConfigureCore(*m_pnaNic);
        m_pnaNic->InitializeSwitchFromP4Json(m_jsonPath);
        m_pnaNic->LoadFlowTableToSwitch(m_flowTablePath);
        SetPortTxDoneCallback(MakeCallback(&P4PnaNic::PortTxComplete, m_pnaNic.get()));
        m_pnaNic->start_and_return_();
        break;

    case P4SWITCH_ARCH_PIPELINE:
        NS_LOG_DEBUG("Initialising pipeline core");
        m_p4Pipeline = std::make_unique<P4CorePipeline>(this, m_enableSwap);
        ConfigureCore(*m_p4Pipeline);
        m_p4Pipeline->InitializeSwitchFromP4Json(m_jsonPath);
        m_p4Pipeline->LoadFlowTableToSwitch(m_flowTablePath);
        m_p4Pipeline->start_and_return_();
        break;

    default:
        NS_FATAL_ERROR("Unknown P4 switch architecture: " << m_switchArch);
    }

    if (!m_learningTableName.empty())
    {
        NS_ABORT_MSG_IF(m_learningActionName.empty(), "LearningTable needs a LearningAction");
        P4LearningTable::Config config;
        config.table = m_learningTableName;
        config.action = m_learningActionName;
        if (m_targetProfile)
        {
            config.capacity = m_targetProfile->tableCapacity;
            config.evictOldest = m_targetProfile->evictOldest;
            config.lifetime = m_targetProfile->entryLifetime;
            config.dataPlane =
                m_targetProfile->learningPath != TargetProfile::LearningPath::CONTROL_PLANE;
        }
        if (!config.dataPlane)
        {
            config.controlPlaneDelay = m_controlPlaneDelay;
            if (m_controlPlaneDelay.IsStrictlyNegative())
            {
                NS_ABORT_MSG_IF(!m_targetProfile->controlPlaneDelayGiven,
                                "Target profile "
                                    << m_targetProfile->name
                                    << " learns through the control plane but gives no delay: "
                                       "set the ControlPlaneDelay attribute");
                config.controlPlaneDelay = m_targetProfile->controlPlaneDelay;
            }
        }
        GetCore()->SetLearningTable(config);
    }

    NetDevice::DoInitialize();
}

void
P4SwitchNetDevice::DoDispose()
{
    NS_LOG_FUNCTION_NOARGS();

    // The callback points into the core deleted below.
    m_portTxDone = MakeNullCallback<void, uint32_t>();
    // The Thrift server keeps running: stop the services before any part of the
    // core is destroyed (a call that runs now finishes first)
    if (P4SwitchCore* core = GetCore())
    {
        core->StopThriftServices();
    }
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
P4SwitchNetDevice::Receive(Ptr<Packet> packet, Ptr<SwitchedEthernetChannel> channel, uint32_t slot)
{
    NS_LOG_FUNCTION_NOARGS();
    NS_LOG_DEBUG("UID=" << packet->GetUid());

    if (m_cutThroughBytes > 0)
    {
        return; // ReceiveHeaders() got the frame when its decision bytes arrived
    }

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

    // Switch mode: the ingress port is the one attached to this channel in this
    // slot. (The other end may be a host device, which is not a P4SwitchNetDevice.)
    uint32_t inPort = UINT32_MAX;
    for (uint32_t i = 0; i < m_portChannels.size(); ++i)
    {
        if (m_portChannels[i] == channel && m_portDeviceIds[i] == slot)
        {
            inPort = i;
            break;
        }
    }
    if (inPort == UINT32_MAX)
    {
        NS_LOG_WARN("Receive: the channel is not attached to a port — dropping");
        return;
    }

    NS_LOG_DEBUG("Ingress port=" << inPort << " src=" << src48 << " dst=" << dst48 << " proto=0x"
                                 << std::hex << proto << std::dec);

    // The frame arrives with its last bit; its first bit (the preamble's, with
    // Ethernet framing) arrived its time on the wire earlier
    Time lastBit = Simulator::Now();
    Time firstBit =
        lastBit - channel->GetDataRate().CalculateBytesTxTime(
                      LinkFraming(channel->GetFraming()).GetWireBytes(packet->GetSize()));
    HandleArrival(packet->Copy(), inPort, proto, dst48, firstBit, lastBit);
}

void
P4SwitchNetDevice::ReceiveHeaders(Ptr<Packet> packet,
                                  Ptr<SwitchedEthernetChannel> channel,
                                  uint32_t slot,
                                  Time firstBit)
{
    NS_LOG_FUNCTION(this << packet << slot << firstBit);
    EthernetHeader eth;
    packet->PeekHeader(eth);
    if (!m_promiscRxCallback.IsNull())
    {
        m_promiscRxCallback(this,
                            packet,
                            eth.GetLengthType(),
                            eth.GetSource(),
                            eth.GetDestination(),
                            PACKET_OTHERHOST);
    }
    for (uint32_t i = 0; i < m_portChannels.size(); ++i)
    {
        if (m_portChannels[i] == channel && m_portDeviceIds[i] == slot)
        {
            Time lastBit =
                firstBit + channel->GetDataRate().CalculateBytesTxTime(
                               LinkFraming(channel->GetFraming()).GetWireBytes(packet->GetSize()));
            HandleArrival(packet->Copy(),
                          i,
                          eth.GetLengthType(),
                          eth.GetDestination(),
                          firstBit,
                          lastBit);
            return;
        }
    }
    NS_LOG_WARN("ReceiveHeaders: the channel is not attached to a port — dropping");
}

uint32_t
P4SwitchNetDevice::GetCutThroughBytes() const
{
    return m_cutThroughBytes;
}

uint64_t
P4SwitchNetDevice::GetLookupDrops() const
{
    return m_lookupDrops;
}

void
P4SwitchNetDevice::HandleArrival(Ptr<Packet> frame,
                                 uint32_t inPort,
                                 uint16_t protocol,
                                 Mac48Address dst,
                                 Time firstBit,
                                 Time lastBit)
{
    Time now = Simulator::Now();
    Time period = m_targetProfile ? m_targetProfile->clockPeriod : Time(0);
    if (period.IsStrictlyPositive())
    {
        // The target samples its inputs on a clock: an arrival counts at the next edge
        int64_t steps = period.GetTimeStep();
        int64_t late = ((firstBit.GetTimeStep() % steps) + steps) % steps;
        if (late > 0)
        {
            firstBit += TimeStep(steps - late);
            lastBit += TimeStep(steps - late);
        }
    }
    m_frameArrivalTrace(frame, inPort, firstBit, lastBit);

    if (m_targetProfile && m_targetProfile->lookupsPerCycle > 0)
    {
        // The lookup of a frame takes place in the clock period in which it
        // can be decided; the frames of one period queue for the lookups
        int64_t steps = period.GetTimeStep();
        int64_t index = (now.GetTimeStep() + steps - 1) / steps;
        std::vector<LookupRequest>& requests = m_lookupRequests[index];
        requests.push_back({frame, inPort, protocol, dst, firstBit, lastBit});
        if (requests.size() == 1)
        {
            Simulator::Schedule(TimeStep(index * steps) - now,
                                &P4SwitchNetDevice::Arbitrate,
                                this,
                                index);
        }
        return;
    }
    DeliverToCore(frame, inPort, protocol, dst, firstBit, lastBit);
}

void
P4SwitchNetDevice::Arbitrate(int64_t period)
{
    auto it = m_lookupRequests.find(period);
    if (it == m_lookupRequests.end())
    {
        return;
    }
    std::vector<LookupRequest> requests = std::move(it->second);
    m_lookupRequests.erase(it);
    // Fixed priority: the lowest port index wins; the others lose their frame on all ports
    std::stable_sort(
        requests.begin(),
        requests.end(),
        [](const LookupRequest& a, const LookupRequest& b) { return a.inPort < b.inPort; });
    for (size_t i = 0; i < requests.size(); i++)
    {
        LookupRequest& r = requests[i];
        if (i < m_targetProfile->lookupsPerCycle)
        {
            DeliverToCore(r.frame, r.inPort, r.protocol, r.dst, r.firstBit, r.lastBit);
        }
        else
        {
            NS_LOG_DEBUG("Port " << r.inPort << " lost the lookup arbitration, frame dropped");
            m_lookupDrops++;
            m_macRxDropTrace(r.frame);
        }
    }
}

void
P4SwitchNetDevice::DeliverToCore(Ptr<Packet> frame,
                                 uint32_t inPort,
                                 uint16_t protocol,
                                 Mac48Address dst,
                                 Time firstBit,
                                 Time lastBit)
{
    if (!m_v1modelSwitch && !m_psaSwitch && !m_pnaNic && !m_p4Pipeline)
    {
        NS_LOG_WARN("No P4 core, dropping frame received on port " << inPort);
        return;
    }

    m_promiscSnifferTrace(frame);
    m_snifferTrace(frame);
    m_macRxTrace(frame);

    // While a swap of the P4 program waits for the switch to empty, the frame
    // waits too (see P4SwitchCore::swap_configs())
    if (GetCore()->HoldDuringSwap(frame, inPort, protocol, dst))
    {
        return;
    }

    // Feed the full Ethernet frame into the P4 pipeline.
    GetCore()->NoteArrival(firstBit, lastBit);
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

    // A frame for the drop port is dropped without a warning. The pipeline
    // core, for example, passes the egress_spec of the ingress, which
    // mark_to_drop() sets to the drop port.
    if (outPort == SSWITCH_DROP_PORT)
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

    // ns-3 cannot carry a frame shorter than an Ethernet header: the devices
    // read the header and would read past the end of the frame. The P4
    // program can emit one, e.g. with truncate().
    if (packetOut->GetSize() < EthernetHeader().GetSerializedSize())
    {
        NS_LOG_WARN("SendNs3Packet: frame of " << packetOut->GetSize() << " bytes on port "
                                               << outPort
                                               << " is shorter than an Ethernet header, dropping");
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
    // The channel computes the serialisation time from its data rate
    Time serialisationTime;
    if (!channel->TransmitStart(packet, m_portDeviceIds[port], &serialisationTime))
    {
        NS_LOG_WARN("TransmitOn: channel busy or device inactive — packet dropped");
        m_macTxDropTrace(packet);
        return false;
    }

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
    // Without these traces the port is free again one transmission time after
    // the device has taken a frame (see SendOnBridgePort()).
    m_bridgePortTxEnd.push_back(connected);
    if (!connected)
    {
        NS_LOG_INFO("AddBridgePort: " << bridgePort->GetInstanceTypeId().GetName()
                                      << " reports no end of transmission; the port is free "
                                         "again after the frame's transmission time");
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

    // Its first bit arrived its time on the wire earlier; a port device
    // without a data rate (SimpleNetDevice by default) delivers it at once
    Time lastBit = Simulator::Now();
    DataRate rate = GetPortDataRate(inPort);
    Time firstBit =
        rate.GetBitRate() > 0 ? lastBit - rate.CalculateBytesTxTime(frame->GetSize()) : lastBit;
    HandleArrival(frame, inPort, protocol, dst48, firstBit, lastBit);
}

bool
P4SwitchNetDevice::SendOnBridgePort(uint32_t port, Ptr<Packet> frame, Time* txTime)
{
    // The port device adds its own header, so hand it the frame's addresses
    // and EtherType without the Ethernet header. Every frame here has one:
    // SendNs3Packet() drops shorter frames, and Send() adds the header.
    Ptr<Packet> payload = frame->Copy();
    EthernetHeader eth;
    payload->RemoveHeader(eth);
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
        // With the port's framing, if its device has one (the P4 point-to-point
        // device; ns-3's CSMA device adds its FCS and gap itself)
        P4SIM_ENUM_VALUE(LinkFraming::Type) framing;
        LinkFraming::Type type = LinkFraming::NONE;
        if (m_bridgePorts[port]->GetAttributeFailSafe("Framing", framing))
        {
            type = static_cast<LinkFraming::Type>(framing.Get());
        }
        *txTime = GetPortDataRate(port).CalculateBytesTxTime(
            LinkFraming(type).GetWireBytes(frame->GetSize()));
    }
    if (!m_bridgePortTxEnd[port])
    {
        // The device will not report the end of the transmission: the port is
        // free again after the time the device needs for the frame at its data
        // rate (SimpleNetDevice: the size it was given), or at once without one.
        DataRate rate = GetPortDataRate(port);
        Time wait = (rate.GetBitRate() > 0) ? rate.CalculateBytesTxTime(payload->GetSize())
                                            : Time(0);
        Simulator::Schedule(wait,
                            &P4SwitchNetDevice::BridgePortTxEnd,
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
    // Find the port whose far end is `sender`. A host's slot has no P4 device,
    // so a null sender would match the first port that leads to a host.
    if (!sender)
    {
        return UINT32_MAX;
    }
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
    core.SetPipelineDelay(m_pipelineDelay);
    core.SetTransferBufferSize(m_transferBufferSize);
    core.SetTargetProfile(m_targetProfile);
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

P4SwitchCore*
P4SwitchNetDevice::GetCore() const
{
    if (m_v1modelSwitch)
    {
        return m_v1modelSwitch.get();
    }
    if (m_psaSwitch)
    {
        return m_psaSwitch.get();
    }
    if (m_pnaNic)
    {
        return m_pnaNic.get();
    }
    return m_p4Pipeline.get();
}

bool
P4SwitchNetDevice::AddMirroringSession(uint32_t sessionId, uint32_t egressPort)
{
    P4SwitchCore* core = GetCore();
    if (!core)
    {
        NS_LOG_WARN("Cannot add mirroring session " << sessionId
                                                    << ": the P4 core is not created yet");
        return false;
    }
    P4SwitchCore::MirroringSessionConfig config{};
    config.egress_port = egressPort;
    config.egress_port_valid = true;
    config.mgid_valid = false;
    return core->AddMirroringSession(static_cast<int>(sessionId), config);
}

bool
P4SwitchNetDevice::AddMulticastMirroringSession(uint32_t sessionId, uint32_t mgid)
{
    P4SwitchCore* core = GetCore();
    if (!core)
    {
        NS_LOG_WARN("Cannot add mirroring session " << sessionId
                                                    << ": the P4 core is not created yet");
        return false;
    }
    P4SwitchCore::MirroringSessionConfig config{};
    config.egress_port_valid = false;
    config.mgid = mgid;
    config.mgid_valid = true;
    return core->AddMirroringSession(static_cast<int>(sessionId), config);
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
P4SwitchNetDevice::NotifyDigest(const P4Digest& digest)
{
    NS_LOG_FUNCTION(this << digest.listId);
    Simulator::ScheduleNow(&P4SwitchNetDevice::FireDigest, Ptr<P4SwitchNetDevice>(this), digest);
}

void
P4SwitchNetDevice::FireDigest(const P4Digest& digest)
{
    NS_LOG_FUNCTION(this << digest.listId);
    m_digestTrace(digest);
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
