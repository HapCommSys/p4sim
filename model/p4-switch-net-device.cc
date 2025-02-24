/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018 Stanford University
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

#include "ns3/arp-header.h"
#include "ns3/arp-l3-protocol.h"
#include "ns3/boolean.h"
#include "ns3/channel.h"
#include "ns3/ethernet-header.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/uinteger.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("P4SwitchNetDevice");

NS_OBJECT_ENSURE_REGISTERED(P4SwitchNetDevice);

TypeId
P4SwitchNetDevice::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::P4SwitchNetDevice")
            .SetParent<NetDevice>()
            .SetGroupName("Bridge")
            .AddConstructor<P4SwitchNetDevice>()
            .AddAttribute(
                "Mtu",
                "The MAC-level Maximum Transmission Unit",
                UintegerValue(1500),
                MakeUintegerAccessor(&P4SwitchNetDevice::SetMtu, &P4SwitchNetDevice::GetMtu),
                MakeUintegerChecker<uint16_t>())

            .AddAttribute("JsonPath",
                          "Path to the P4 JSON configuration file.",
                          StringValue("/path/to/default.json"),
                          MakeStringAccessor(&P4SwitchNetDevice::GetJsonPath,
                                             &P4SwitchNetDevice::SetJsonPath),
                          MakeStringChecker())

            .AddAttribute("EnableTracing",
                          "Enable tracing in the switch.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&P4SwitchNetDevice::m_enableTracing),
                          MakeBooleanChecker())

            .AddAttribute("FlowTablePath",
                          "Path to the flow table file.",
                          StringValue("/path/to/flow_table.txt"),
                          MakeStringAccessor(&P4SwitchNetDevice::GetFlowTablePath,
                                             &P4SwitchNetDevice::SetFlowTablePath),
                          MakeStringChecker())

            .AddAttribute("ChannelType",
                          "Channel type for the switch, csma with 0, p2p with 1.",
                          UintegerValue(0),
                          MakeUintegerAccessor(&P4SwitchNetDevice::m_channelType),
                          MakeUintegerChecker<uint32_t>())

            .AddAttribute("InputBufferSizeLow",
                          "Low input buffer size for the switch queue.",
                          UintegerValue(128),
                          MakeUintegerAccessor(&P4SwitchNetDevice::input_buffer_size_low),
                          MakeUintegerChecker<size_t>())

            .AddAttribute("InputBufferSizeHigh",
                          "High input buffer size for the switch queue.",
                          UintegerValue(128),
                          MakeUintegerAccessor(&P4SwitchNetDevice::input_buffer_size_high),
                          MakeUintegerChecker<size_t>())

            .AddAttribute("QueueBufferSize",
                          "Total buffer size for the switch queue.",
                          UintegerValue(128),
                          MakeUintegerAccessor(&P4SwitchNetDevice::queue_buffer_size),
                          MakeUintegerChecker<size_t>())

            .AddAttribute("PacketRate",
                          "Packet processing speed in switch (unit: pps)",
                          UintegerValue(1000),
                          MakeUintegerAccessor(&P4SwitchNetDevice::switch_rate),
                          MakeUintegerChecker<uint64_t>());
    return tid;
}

P4SwitchNetDevice::P4SwitchNetDevice()
    : m_node(nullptr),
      m_ifIndex(0)
{
    NS_LOG_FUNCTION_NOARGS();
    m_channel = CreateObject<P4BridgeChannel>();
}

P4SwitchNetDevice::~P4SwitchNetDevice()
{
    NS_LOG_FUNCTION_NOARGS();
}

void
P4SwitchNetDevice::DoInitialize()
{
    NS_LOG_FUNCTION(this);
    NS_LOG_DEBUG("P4 architecture: v1model");
    m_p4Switch = new P4CoreV1model(this,
                                   false,
                                   m_enableTracing,
                                   switch_rate,
                                   input_buffer_size_low,
                                   input_buffer_size_high,
                                   queue_buffer_size);
    m_p4Switch->InitSwitchWithP4(jsonPath_, flowTablePath_);
    m_p4Switch->start_and_return_();

    NetDevice::DoInitialize();
}

void
P4SwitchNetDevice::DoDispose()
{
    NS_LOG_FUNCTION_NOARGS();
    for (auto iter = m_ports.begin(); iter != m_ports.end(); iter++)
    {
        *iter = nullptr;
    }
    m_ports.clear();
    m_channel = nullptr;
    m_node = nullptr;
    NetDevice::DoDispose();
}

void
P4SwitchNetDevice::ReceiveFromDevice(Ptr<NetDevice> incomingPort,
                                     Ptr<const Packet> packet,
                                     uint16_t protocol,
                                     const Address& src,
                                     const Address& dst,
                                     PacketType packetType)
{
    NS_LOG_FUNCTION_NOARGS();
    NS_LOG_DEBUG("UID is " << packet->GetUid());

    Mac48Address src48 = Mac48Address::ConvertFrom(src);
    Mac48Address dst48 = Mac48Address::ConvertFrom(dst);

    if (!m_promiscRxCallback.IsNull())
    {
        m_promiscRxCallback(this, packet, protocol, src, dst, packetType);
    }

    if (dst48 == m_address)
    {
        m_rxCallback(this, packet, protocol, src);
    }

    int inPort = GetPortNumber(incomingPort);

    Ptr<ns3::Packet> ns3Packet((ns3::Packet*)PeekPointer(packet));

    if (m_channelType == P4CHANNELCSMA)
    {
        EthernetHeader eeh;
        eeh.SetDestination(dst48);
        eeh.SetSource(src48);
        eeh.SetLengthType(protocol);

        ns3Packet->AddHeader(eeh);
    }
    else if (m_channelType == P4CHANNELP2P)
    {
        // The P4 processing part need the Ethernet header.
        EthernetHeader eeh_1;
        if (ns3Packet->PeekHeader(eeh_1))
        {
            NS_LOG_DEBUG("Ethernet packet");
            ns3Packet->RemoveHeader(eeh_1);
        }
        else
        {
            eeh_1.SetLengthType(protocol);
        }
        eeh_1.SetDestination(dst48);
        eeh_1.SetSource(src48);
        // Here we don't modify the protocol number
        // eeh_1.SetLengthType (protocol);

        NS_LOG_DEBUG("* Modified Ethernet header: Source MAC: "
                     << eeh_1.GetSource() << ", Destination MAC: " << eeh_1.GetDestination()
                     << ", Protocol: " << eeh_1.GetLengthType());

        ns3Packet->AddHeader(eeh_1);

        // @debug
        // std::cout << "* Switch Port *** Receive from Device: " << std::endl;
        // ns3Packet->Print (std::cout);
        // std::cout << std::endl;
    }
    else
    {
        NS_LOG_ERROR("Unsupported channel type.");
    }

    m_p4Switch->ReceivePacket(ns3Packet, inPort, protocol, dst);
}

uint32_t
P4SwitchNetDevice::GetNBridgePorts() const
{
    NS_LOG_FUNCTION_NOARGS();
    return m_ports.size();
}

Ptr<NetDevice>
P4SwitchNetDevice::GetBridgePort(uint32_t n) const
{
    NS_LOG_FUNCTION_NOARGS();
    if (n >= m_ports.size())
        return NULL;
    return m_ports[n];
}

void
P4SwitchNetDevice::AddBridgePort(Ptr<NetDevice> bridgePort)
{
    NS_LOG_FUNCTION_NOARGS();
    NS_ASSERT(bridgePort != this);
    if (!Mac48Address::IsMatchingType(bridgePort->GetAddress()))
    {
        NS_FATAL_ERROR("Device does not support eui 48 addresses: cannot be added to bridge.");
    }
    if (!bridgePort->SupportsSendFrom())
    {
        NS_FATAL_ERROR("Device does not support SendFrom: cannot be added to bridge.");
    }
    if (m_address == Mac48Address())
    {
        m_address = Mac48Address::ConvertFrom(bridgePort->GetAddress());
    }

    NS_LOG_DEBUG("RegisterProtocolHandler for " << bridgePort->GetInstanceTypeId().GetName());

    m_node->RegisterProtocolHandler(MakeCallback(&P4SwitchNetDevice::ReceiveFromDevice, this),
                                    0,
                                    bridgePort,
                                    true);
    m_ports.push_back(bridgePort);
    m_channel->AddChannel(bridgePort->GetChannel());
}

uint32_t
P4SwitchNetDevice::GetPortNumber(Ptr<NetDevice> port) const
{
    int portsNum = GetNBridgePorts();
    for (int i = 0; i < portsNum; i++)
    {
        if (GetBridgePort(i) == port)
            NS_LOG_DEBUG("Port found: " << i);
        return i;
    }
    NS_LOG_ERROR("Port not found");
    return -1;
}

void
P4SwitchNetDevice::SetIfIndex(const uint32_t index)
{
    NS_LOG_FUNCTION_NOARGS();
    m_ifIndex = index;
}

uint32_t
P4SwitchNetDevice::GetIfIndex() const
{
    NS_LOG_FUNCTION_NOARGS();
    return m_ifIndex;
}

Ptr<Channel>
P4SwitchNetDevice::GetChannel() const
{
    NS_LOG_FUNCTION_NOARGS();
    return m_channel;
}

void
P4SwitchNetDevice::SetAddress(Address address)
{
    NS_LOG_FUNCTION_NOARGS();
    m_address = Mac48Address::ConvertFrom(address);
}

Address
P4SwitchNetDevice::GetAddress() const
{
    NS_LOG_FUNCTION_NOARGS();
    return m_address;
}

bool
P4SwitchNetDevice::SetMtu(const uint16_t mtu)
{
    NS_LOG_FUNCTION_NOARGS();
    m_mtu = mtu;
    return true;
}

uint16_t
P4SwitchNetDevice::GetMtu() const
{
    NS_LOG_FUNCTION_NOARGS();
    return m_mtu;
}

void
P4SwitchNetDevice::SetJsonPath(const std::string& jsonPath)
{
    jsonPath_ = jsonPath;
}

std::string
P4SwitchNetDevice::GetJsonPath(void) const
{
    return jsonPath_;
}

void
P4SwitchNetDevice::SetFlowTablePath(const std::string& flowTablePath)
{
    flowTablePath_ = flowTablePath;
}

std::string
P4SwitchNetDevice::GetFlowTablePath(void) const
{
    return flowTablePath_;
}

bool
P4SwitchNetDevice::IsLinkUp() const
{
    NS_LOG_FUNCTION_NOARGS();
    return true;
}

void
P4SwitchNetDevice::AddLinkChangeCallback(Callback<void> callback)
{
}

bool
P4SwitchNetDevice::IsBroadcast() const
{
    NS_LOG_FUNCTION_NOARGS();
    return true;
}

Address
P4SwitchNetDevice::GetBroadcast() const
{
    NS_LOG_FUNCTION_NOARGS();
    return Mac48Address::GetBroadcast();
}

bool
P4SwitchNetDevice::IsMulticast() const
{
    NS_LOG_FUNCTION_NOARGS();
    return true;
}

Address
P4SwitchNetDevice::GetMulticast(Ipv4Address multicastGroup) const
{
    NS_LOG_FUNCTION(this << multicastGroup);
    Mac48Address multicast = Mac48Address::GetMulticast(multicastGroup);
    return multicast;
}

bool
P4SwitchNetDevice::IsPointToPoint() const
{
    NS_LOG_FUNCTION_NOARGS();
    return false;
}

bool
P4SwitchNetDevice::IsBridge() const
{
    NS_LOG_FUNCTION_NOARGS();
    return true;
}

bool
P4SwitchNetDevice::Send(Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber)
{
    NS_LOG_FUNCTION_NOARGS();
    return SendFrom(packet, m_address, dest, protocolNumber);
}

bool
P4SwitchNetDevice::SendFrom(Ptr<Packet> packet,
                            const Address& src,
                            const Address& dest,
                            uint16_t protocolNumber)
{
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
    for (auto iter = m_ports.begin(); iter != m_ports.end(); iter++)
    {
        pktCopy = packet->Copy();
        Ptr<NetDevice> port = *iter;
        port->SendFrom(pktCopy, src, dst, protocolNumber);
    }

    return true;
}

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
                                 uint16_t protocol,
                                 const Address& destination)
{
    NS_LOG_DEBUG("Sending ns3 packet to port " << outPort);

    // packetOut->Print (std::cout);
    // std::cout << std::endl;

    if (packetOut)
    {
        // Print the packet's header
        // EthernetHeader eeh_1;
        // if (packetOut->PeekHeader (eeh_1))
        //   {
        //     NS_LOG_DEBUG ("Ethernet packet");
        //     // log the ethernet header information
        //     Mac48Address src_mac = eeh_1.GetSource ();
        //     Mac48Address dst_mac = eeh_1.GetDestination ();
        //     uint16_t protocol_eth = eeh_1.GetLengthType ();
        //     protocol = protocol_eth; // Keep the protocol number of the packet
        //     NS_LOG_DEBUG ("Source MAC: " << src_mac << ", Destination MAC: " << dst_mac
        //                                  << ", Protocol: " << protocol_eth);
        //   }

        EthernetHeader eeh;
        packetOut->RemoveHeader(eeh); // keep the ethernet header

        // @debug
        // std::cout << "* Switch Port *** Send from Device: " << std::endl;
        // packetOut->Print (std::cout);
        // std::cout << std::endl;

        if (outPort != 511)
        {
            NS_LOG_DEBUG("EgressPortNum: " << outPort);
            Ptr<NetDevice> outNetDevice = GetBridgePort(outPort);
            outNetDevice->Send(packetOut, destination, protocol);
        }
    }
    else
        NS_LOG_DEBUG("Null Packet!");
}

Ptr<Node>
P4SwitchNetDevice::GetNode() const
{
    NS_LOG_FUNCTION_NOARGS();
    return m_node;
}

void
P4SwitchNetDevice::SetNode(Ptr<Node> node)
{
    NS_LOG_FUNCTION_NOARGS();
    m_node = node;
}

bool
P4SwitchNetDevice::NeedsArp() const
{
    NS_LOG_FUNCTION_NOARGS();
    return true;
}

void
P4SwitchNetDevice::SetReceiveCallback(NetDevice::ReceiveCallback cb)
{
    NS_LOG_FUNCTION_NOARGS();
    m_rxCallback = cb;
}

void
P4SwitchNetDevice::SetPromiscReceiveCallback(NetDevice::PromiscReceiveCallback cb)
{
    NS_LOG_FUNCTION_NOARGS();
    m_promiscRxCallback = cb;
}

bool
P4SwitchNetDevice::SupportsSendFrom() const
{
    NS_LOG_FUNCTION_NOARGS();
    return true;
}

Address
P4SwitchNetDevice::GetMulticast(Ipv6Address addr) const
{
    NS_LOG_FUNCTION(this << addr);
    return Mac48Address::GetMulticast(addr);
}

} // namespace ns3
