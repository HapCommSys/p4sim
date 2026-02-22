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
#include "ns3/channel.h"
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
#include "ns3/uinteger.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("P4SwitchNetDevice");

NS_OBJECT_ENSURE_REGISTERED(P4SwitchNetDevice);

TypeId P4SwitchNetDevice::GetTypeId() {
  static TypeId tid =
      TypeId("ns3::P4SwitchNetDevice")
          .SetParent<NetDevice>()
          .SetGroupName("Bridge")
          .AddConstructor<P4SwitchNetDevice>()
          .AddAttribute(
              "EnableTracing", "Enable tracing in the switch.",
              BooleanValue(false),
              MakeBooleanAccessor(&P4SwitchNetDevice::m_enableTracing),
              MakeBooleanChecker())

          .AddAttribute("EnableSwap", "Enable swapping in the switch.",
                        BooleanValue(false),
                        MakeBooleanAccessor(&P4SwitchNetDevice::m_enableSwap),
                        MakeBooleanChecker())

          .AddAttribute(
              "P4SwitchArch",
              "P4 switch architecture, v1model with 0, psa with 1, pna with 2.",
              UintegerValue(P4SWITCH_ARCH_V1MODEL),
              MakeUintegerAccessor(&P4SwitchNetDevice::m_switchArch),
              MakeUintegerChecker<uint32_t>())

          .AddAttribute("JsonPath", "Path to the P4 JSON configuration file.",
                        StringValue("/path/to/default.json"),
                        MakeStringAccessor(&P4SwitchNetDevice::GetJsonPath,
                                           &P4SwitchNetDevice::SetJsonPath),
                        MakeStringChecker())

          .AddAttribute(
              "FlowTablePath", "Path to the flow table file.",
              StringValue("/path/to/flow_table.txt"),
              MakeStringAccessor(&P4SwitchNetDevice::GetFlowTablePath,
                                 &P4SwitchNetDevice::SetFlowTablePath),
              MakeStringChecker())

          .AddAttribute(
              "InputBufferSizeLow",
              "Low input buffer size for the switch queue.", UintegerValue(128),
              MakeUintegerAccessor(&P4SwitchNetDevice::m_InputBufferSizeLow),
              MakeUintegerChecker<size_t>())

          .AddAttribute(
              "InputBufferSizeHigh",
              "High input buffer size for the switch queue.",
              UintegerValue(128),
              MakeUintegerAccessor(&P4SwitchNetDevice::m_InputBufferSizeHigh),
              MakeUintegerChecker<size_t>())

          .AddAttribute(
              "QueueBufferSize", "Total buffer size for the switch queue.",
              UintegerValue(128),
              MakeUintegerAccessor(&P4SwitchNetDevice::m_queueBufferSize),
              MakeUintegerChecker<size_t>())

          .AddAttribute("SwitchRate",
                        "Packet processing speed in switch (unit: pps)",
                        UintegerValue(1000),
                        MakeUintegerAccessor(&P4SwitchNetDevice::m_switchRate),
                        MakeUintegerChecker<uint64_t>())

          .AddAttribute("ChannelType",
                        "Channel type for the switch, csma with 0, p2p with 1.",
                        UintegerValue(0),
                        MakeUintegerAccessor(&P4SwitchNetDevice::m_channelType),
                        MakeUintegerChecker<uint32_t>())

          .AddAttribute("Mtu", "The MAC-level Maximum Transmission Unit",
                        UintegerValue(1500),
                        MakeUintegerAccessor(&P4SwitchNetDevice::SetMtu,
                                             &P4SwitchNetDevice::GetMtu),
                        MakeUintegerChecker<uint16_t>())

          .AddTraceSource(
              "SwitchEvent", "Emitted when a switch event occurs",
              MakeTraceSourceAccessor(&P4SwitchNetDevice::m_switchEvent),
              "ns3::TracedCallback::Uint32String");

  return tid;
}

P4SwitchNetDevice::P4SwitchNetDevice() : m_node(nullptr), m_ifIndex(0) {
  NS_LOG_FUNCTION_NOARGS();
  m_channel = CreateObject<P4BridgeChannel>();
}

P4SwitchNetDevice::~P4SwitchNetDevice() { NS_LOG_FUNCTION_NOARGS(); }

void P4SwitchNetDevice::DoInitialize() {
  NS_LOG_FUNCTION(this);
  NS_LOG_DEBUG("P4 architecture: v1model");

  switch (m_switchArch) {
  case P4SWITCH_ARCH_V1MODEL:
    NS_LOG_DEBUG("P4 architecture: v1model");
    m_v1modelSwitch = new P4CoreV1model(
        this, m_enableSwap, m_enableTracing, m_switchRate, m_InputBufferSizeLow,
        m_InputBufferSizeHigh, m_queueBufferSize);
    m_v1modelSwitch->InitializeSwitchFromP4Json(m_jsonPath);
    m_v1modelSwitch->LoadFlowTableToSwitch(m_flowTablePath);
    m_v1modelSwitch->start_and_return_();
    break;

  case P4SWITCH_ARCH_PSA:
    NS_LOG_DEBUG("P4 architecture: PSA");
    m_psaSwitch =
        new P4CorePsa(this, m_enableSwap, m_enableTracing, m_switchRate,
                      m_InputBufferSizeLow, // normal input queue size
                      m_queueBufferSize);
    m_psaSwitch->InitializeSwitchFromP4Json(m_jsonPath);
    m_psaSwitch->LoadFlowTableToSwitch(m_flowTablePath);
    m_psaSwitch->start_and_return_();
    break;

  case P4NIC_ARCH_PNA:
    NS_LOG_DEBUG("P4 architecture: PNA");
    m_pnaNic = new P4PnaNic(this, m_enableSwap);
    m_pnaNic->InitializeSwitchFromP4Json(m_jsonPath);
    // m_pnaNic->LoadFlowTableToSwitch(m_flowTablePath); // Now not supported
    m_pnaNic->start_and_return_();
    break;

  case P4SWITCH_ARCH_PIPELINE:

    NS_LOG_DEBUG("P4 architecture: Pipeline");
    m_p4Pipeline = new P4CorePipeline(this, m_enableSwap, m_enableTracing);
    m_p4Pipeline->InitializeSwitchFromP4Json(m_jsonPath);
    m_p4Pipeline->LoadFlowTableToSwitch(m_flowTablePath);
    // m_p4Pipeline->InitSwitchWithP4(m_jsonPath, m_flowTablePath);
    m_p4Pipeline->start_and_return_();
    break;
  }
  NetDevice::DoInitialize();
}

void P4SwitchNetDevice::DoDispose() {
  NS_LOG_FUNCTION_NOARGS();
  for (auto iter = m_ports.begin(); iter != m_ports.end(); iter++) {
    *iter = nullptr;
  }
  m_ports.clear();
  m_channel = nullptr;
  m_node = nullptr;
  NetDevice::DoDispose();
}

void P4SwitchNetDevice::ReceiveFromDevice(Ptr<NetDevice> incomingPort,
                                          Ptr<const Packet> packet,
                                          uint16_t protocol, const Address &src,
                                          const Address &dst,
                                          PacketType packetType) {
  NS_LOG_FUNCTION_NOARGS();
  NS_LOG_DEBUG("UID is " << packet->GetUid());

  Mac48Address src48 = Mac48Address::ConvertFrom(src);
  Mac48Address dst48 = Mac48Address::ConvertFrom(dst);

  if (!m_promiscRxCallback.IsNull()) {
    m_promiscRxCallback(this, packet, protocol, src, dst, packetType);
  }

  if (dst48 == m_address) {
    m_rxCallback(this, packet, protocol, src);
  }

  int inPort = GetPortNumber(incomingPort);

  Ptr<ns3::Packet> ns3Packet((ns3::Packet *)PeekPointer(packet));

  if (m_channelType == P4CHANNELCSMA) {
    EthernetHeader eeh;
    eeh.SetDestination(dst48);
    eeh.SetSource(src48);
    eeh.SetLengthType(protocol);

    ns3Packet->AddHeader(eeh);
  } else if (m_channelType == P4CHANNELP2P) {
    // The P4 processing pipeline requires an Ethernet header at the front of
    // the packet so that the P4 parser can extract hdr.ethernet.  When the
    // P2P port device (CustomP2PNetDevice) delivers a packet to us via the
    // registered protocol handler it has already stripped the wire-level
    // Ethernet wrapper and passed its EtherType as the 'protocol' parameter.
    // We must therefore build a fresh Ethernet header from the metadata
    // (src, dst, protocol) rather than trying to re-parse packet bytes that
    // are NOT an Ethernet header.  The previous approach of calling
    // PeekHeader(eeh_1) here was incorrect: PeekHeader always succeeds on
    // any packet >= 14 bytes, so it was silently consuming the first 14 bytes
    // of the actual payload (IPv4 / tunnel header), corrupting the packet.
    EthernetHeader eeh_1;
    eeh_1.SetDestination(dst48);
    eeh_1.SetSource(src48);
    eeh_1.SetLengthType(protocol); // EtherType from the stripped wire header

    NS_LOG_DEBUG("* Reconstructed Ethernet header: Source MAC: "
                 << eeh_1.GetSource()
                 << ", Destination MAC: " << eeh_1.GetDestination()
                 << ", Protocol: 0x" << std::hex << eeh_1.GetLengthType()
                 << std::dec);

    ns3Packet->AddHeader(eeh_1);

    // @debug
    // std::cout << "* Switch Port *** Receive from Device: " << std::endl;
    // ns3Packet->Print(std::cout);
    // std::cout << ns3Packet->GetSize() << std::endl;
  } else {
    NS_LOG_ERROR("Unsupported channel type.");
  }

  switch (m_switchArch) {
  case P4SWITCH_ARCH_V1MODEL:
    // m_p4Switch->ReceivePacket(ns3Packet, inPort, protocol, dst48);
    m_v1modelSwitch->ReceivePacket(ns3Packet, inPort, protocol, dst48);
    break;

  case P4SWITCH_ARCH_PSA:
    m_psaSwitch->ReceivePacket(ns3Packet, inPort, protocol, dst48);
    break;

  case P4NIC_ARCH_PNA:
    m_pnaNic->ReceivePacket(ns3Packet, inPort, protocol, dst48);
    break;

  case P4SWITCH_ARCH_PIPELINE:
    m_p4Pipeline->ReceivePacket(ns3Packet, inPort, protocol, dst48);
    break;
  }
}

uint32_t P4SwitchNetDevice::GetNBridgePorts() const {
  NS_LOG_FUNCTION_NOARGS();
  return m_ports.size();
}

Ptr<NetDevice> P4SwitchNetDevice::GetBridgePort(uint32_t n) const {
  NS_LOG_FUNCTION_NOARGS();
  if (n >= m_ports.size())
    return NULL;
  return m_ports[n];
}

void P4SwitchNetDevice::AddBridgePort(Ptr<NetDevice> bridgePort) {
  NS_LOG_FUNCTION_NOARGS();
  NS_ASSERT(bridgePort != this);
  if (!Mac48Address::IsMatchingType(bridgePort->GetAddress())) {
    NS_FATAL_ERROR(
        "Device does not support eui 48 addresses: cannot be added to bridge.");
  }
  if (!bridgePort->SupportsSendFrom()) {
    NS_FATAL_ERROR(
        "Device does not support SendFrom: cannot be added to bridge.");
  }
  if (m_address == Mac48Address()) {
    m_address = Mac48Address::ConvertFrom(bridgePort->GetAddress());
  }

  NS_LOG_DEBUG("RegisterProtocolHandler for "
               << bridgePort->GetInstanceTypeId().GetName());

  m_node->RegisterProtocolHandler(
      MakeCallback(&P4SwitchNetDevice::ReceiveFromDevice, this), 0, bridgePort,
      true);
  m_ports.push_back(bridgePort);
  m_channel->AddChannel(bridgePort->GetChannel());
}

uint32_t P4SwitchNetDevice::GetPortNumber(Ptr<NetDevice> port) const {
  int portsNum = GetNBridgePorts();
  for (int i = 0; i < portsNum; i++) {
    if (GetBridgePort(i) == port)
      NS_LOG_DEBUG("Port found: " << i);
    return i;
  }
  NS_LOG_ERROR("Port not found");
  return -1;
}

void P4SwitchNetDevice::SetIfIndex(const uint32_t index) {
  NS_LOG_FUNCTION_NOARGS();
  m_ifIndex = index;
}

uint32_t P4SwitchNetDevice::GetIfIndex() const {
  NS_LOG_FUNCTION_NOARGS();
  return m_ifIndex;
}

Ptr<Channel> P4SwitchNetDevice::GetChannel() const {
  NS_LOG_FUNCTION_NOARGS();
  return m_channel;
}

void P4SwitchNetDevice::SetAddress(Address address) {
  NS_LOG_FUNCTION_NOARGS();
  m_address = Mac48Address::ConvertFrom(address);
}

Address P4SwitchNetDevice::GetAddress() const {
  NS_LOG_FUNCTION_NOARGS();
  return m_address;
}

bool P4SwitchNetDevice::SetMtu(const uint16_t mtu) {
  NS_LOG_FUNCTION_NOARGS();
  m_mtu = mtu;
  return true;
}

uint16_t P4SwitchNetDevice::GetMtu() const {
  NS_LOG_FUNCTION_NOARGS();
  return m_mtu;
}

void P4SwitchNetDevice::SetJsonPath(const std::string &jsonPath) {
  m_jsonPath = jsonPath;
}

std::string P4SwitchNetDevice::GetJsonPath(void) const { return m_jsonPath; }

void P4SwitchNetDevice::SetFlowTablePath(const std::string &flowTablePath) {
  m_flowTablePath = flowTablePath;
}

std::string P4SwitchNetDevice::GetFlowTablePath(void) const {
  return m_flowTablePath;
}

bool P4SwitchNetDevice::IsLinkUp() const {
  NS_LOG_FUNCTION_NOARGS();
  return true;
}

void P4SwitchNetDevice::AddLinkChangeCallback(Callback<void> callback) {}

bool P4SwitchNetDevice::IsBroadcast() const {
  NS_LOG_FUNCTION_NOARGS();
  return true;
}

Address P4SwitchNetDevice::GetBroadcast() const {
  NS_LOG_FUNCTION_NOARGS();
  return Mac48Address::GetBroadcast();
}

bool P4SwitchNetDevice::IsMulticast() const {
  NS_LOG_FUNCTION_NOARGS();
  return true;
}

Address P4SwitchNetDevice::GetMulticast(Ipv4Address multicastGroup) const {
  NS_LOG_FUNCTION(this << multicastGroup);
  Mac48Address multicast = Mac48Address::GetMulticast(multicastGroup);
  return multicast;
}

bool P4SwitchNetDevice::IsPointToPoint() const {
  NS_LOG_FUNCTION_NOARGS();
  return false;
}

bool P4SwitchNetDevice::IsBridge() const {
  NS_LOG_FUNCTION_NOARGS();
  return true;
}

bool P4SwitchNetDevice::Send(Ptr<Packet> packet, const Address &dest,
                             uint16_t protocolNumber) {
  NS_LOG_FUNCTION_NOARGS();
  return SendFrom(packet, m_address, dest, protocolNumber);
}

bool P4SwitchNetDevice::SendFrom(Ptr<Packet> packet, const Address &src,
                                 const Address &dest, uint16_t protocolNumber) {
  /*
   */
  NS_LOG_FUNCTION_NOARGS();
  Mac48Address dst = Mac48Address::ConvertFrom(dest);

  // try to use the learned state if data is unicast
  // if (!dst.IsGroup())
  // {
  //     Ptr<NetDevice> outPort = GetLearnedState(dst);
  //     if (outPort)
  //     {
  //         outPort->SendFrom(packet, src, dest, protocolNumber);
  //         return true;
  //     }
  // }

  // data was not unicast or no state has been learned for that mac
  // address => flood through all ports.
  Ptr<Packet> pktCopy;
  for (auto iter = m_ports.begin(); iter != m_ports.end(); iter++) {
    pktCopy = packet->Copy();
    Ptr<NetDevice> port = *iter;
    port->SendFrom(pktCopy, src, dst, protocolNumber);
  }

  return true;
}

void P4SwitchNetDevice::SendPacket(Ptr<Packet> packetOut, int outPort,
                                   uint16_t protocol,
                                   const Address &destination) {
  SendNs3Packet(packetOut, outPort, protocol, destination);
}

void P4SwitchNetDevice::SendNs3Packet(Ptr<Packet> packetOut, int outPort,
                                      uint16_t protocol,
                                      const Address &destination) {
  NS_LOG_DEBUG("Sending ns3 packet to port " << outPort);

  // std::cout << "* after p4 processing " << packetOut->GetSize() << "packet
  // length" << std::endl; packetOut->Print(std::cout); std::cout << std::endl;

  if (packetOut) {
    // Print the packet's header
    EthernetHeader eeh_1;

    if (packetOut->PeekHeader(eeh_1)) {
      NS_LOG_DEBUG("Ethernet packet");
      protocol = eeh_1.GetLengthType(); // recover the protocol number
    }

    packetOut->RemoveHeader(eeh_1); // keep the ethernet header

    // @debug
    // std::cout << "* Switch Port (out)*** Send from Device: " << std::endl;
    // packetOut->Print(std::cout);
    // std::cout << "packet length: " << packetOut->GetSize() << std::endl;

    if (outPort != 511) {
      NS_LOG_DEBUG("EgressPortNum: " << outPort);
      Ptr<NetDevice> outNetDevice = GetBridgePort(outPort);
      outNetDevice->Send(packetOut, destination, protocol);
    }
  } else
    NS_LOG_DEBUG("Null Packet!");
}

Ptr<Node> P4SwitchNetDevice::GetNode() const {
  NS_LOG_FUNCTION_NOARGS();
  return m_node;
}

void P4SwitchNetDevice::SetNode(Ptr<Node> node) {
  NS_LOG_FUNCTION_NOARGS();
  m_node = node;
}

bool P4SwitchNetDevice::NeedsArp() const {
  NS_LOG_FUNCTION_NOARGS();
  return true;
}

void P4SwitchNetDevice::SetReceiveCallback(NetDevice::ReceiveCallback cb) {
  NS_LOG_FUNCTION_NOARGS();
  m_rxCallback = cb;
}

void P4SwitchNetDevice::SetPromiscReceiveCallback(
    NetDevice::PromiscReceiveCallback cb) {
  NS_LOG_FUNCTION_NOARGS();
  m_promiscRxCallback = cb;
}

bool P4SwitchNetDevice::SupportsSendFrom() const {
  NS_LOG_FUNCTION_NOARGS();
  return true;
}

Address P4SwitchNetDevice::GetMulticast(Ipv6Address addr) const {
  NS_LOG_FUNCTION(this << addr);
  return Mac48Address::GetMulticast(addr);
}

P4CoreV1model *P4SwitchNetDevice::GetV1ModelCore() const {
  return m_v1modelSwitch;
}
void P4SwitchNetDevice::EmitSwitchEvent(uint32_t id, const std::string &msg) {
  m_switchEvent(id, msg);
}

} // namespace ns3
