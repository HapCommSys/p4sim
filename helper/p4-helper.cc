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

#include "p4-helper.h"

#include "ns3/config.h"
#include "ns3/log.h"
#include "ns3/mac48-address.h"
#include "ns3/names.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/packet.h"
#include "ns3/pcap-file-wrapper.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/trace-helper.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("P4Helper");

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

P4Helper::P4Helper()
{
    m_deviceFactory.SetTypeId("ns3::P4SwitchNetDevice");
    m_nicFactory.SetTypeId("ns3::P4SwitchNetDevice");
    m_channelFactory.SetTypeId("ns3::SwitchedEthernetChannel");
}

// ---------------------------------------------------------------------------
// Attribute configuration
// ---------------------------------------------------------------------------

void
P4Helper::SetDeviceAttribute(const std::string& name, const AttributeValue& value)
{
    m_deviceFactory.Set(name, value);
}

void
P4Helper::SetNicAttribute(const std::string& name, const AttributeValue& value)
{
    m_nicFactory.Set(name, value);
}

void
P4Helper::SetChannelAttribute(const std::string& name, const AttributeValue& value)
{
    m_channelFactory.Set(name, value);
}

// ---------------------------------------------------------------------------
// Install — switch device only
// ---------------------------------------------------------------------------

NetDeviceContainer
P4Helper::Install(Ptr<Node> switchNode) const
{
    NS_ASSERT_MSG(switchNode, "P4Helper::Install: null switch node");
    NS_LOG_FUNCTION(this << switchNode->GetId());
    return NetDeviceContainer(InstallSwitchPriv(switchNode));
}

NetDeviceContainer
P4Helper::Install(const std::string& switchNodeName) const
{
    Ptr<Node> node = Names::Find<Node>(switchNodeName);
    NS_ASSERT_MSG(node, "P4Helper::Install: node \"" << switchNodeName << "\" not found");
    return Install(node);
}

// ---------------------------------------------------------------------------
// Install — switch + ports in one call
// ---------------------------------------------------------------------------

NetDeviceContainer
P4Helper::Install(Ptr<Node> switchNode, const NodeContainer& hosts) const
{
    NS_ASSERT_MSG(switchNode, "P4Helper::Install: null switch node");
    NS_LOG_FUNCTION(this << switchNode->GetId() << hosts.GetN());

    // Create (or reuse if already installed) the switch device.
    Ptr<P4SwitchNetDevice> sw = InstallSwitchPriv(switchNode);

    NetDeviceContainer result;
    result.Add(sw);

    // For each host: create a channel + NIC and wire them to the switch.
    for (auto it = hosts.Begin(); it != hosts.End(); ++it)
    {
        Ptr<P4SwitchNetDevice> nic = InstallPortPriv(sw, *it);
        result.Add(nic);
    }

    NS_LOG_INFO("P4Helper: switch node " << switchNode->GetId()
                << " has " << sw->GetNPorts() << " port(s)");
    return result;
}

// ---------------------------------------------------------------------------
// Add a single port to an already-installed switch
// ---------------------------------------------------------------------------

NetDeviceContainer
P4Helper::ConnectHost(Ptr<P4SwitchNetDevice> switchDev, Ptr<Node> hostNode) const
{
    NS_ASSERT_MSG(switchDev, "P4Helper::ConnectHost: null switch device");
    NS_ASSERT_MSG(hostNode,  "P4Helper::ConnectHost: null host node");
    NS_LOG_FUNCTION(this << hostNode->GetId());

    Ptr<P4SwitchNetDevice> nic = InstallPortPriv(switchDev, hostNode);
    return NetDeviceContainer(nic);
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

Ptr<P4SwitchNetDevice>
P4Helper::InstallSwitchPriv(Ptr<Node> node) const
{
    Ptr<P4SwitchNetDevice> sw = m_deviceFactory.Create<P4SwitchNetDevice>();
    sw->SetAddress(Mac48Address::Allocate());
    node->AddDevice(sw);
    NS_LOG_DEBUG("Switch device installed on node " << node->GetId());
    return sw;
}

Ptr<P4SwitchNetDevice>
P4Helper::InstallPortPriv(Ptr<P4SwitchNetDevice> switchDev, Ptr<Node> hostNode) const
{
    // Create the point-to-point channel for this port.
    Ptr<SwitchedEthernetChannel> ch = m_channelFactory.Create<SwitchedEthernetChannel>();

    // Switch side: attach as the next port.
    switchDev->Attach(ch);

    // Host side: NIC device in passthrough mode (JsonPath left empty by default).
    Ptr<P4SwitchNetDevice> nic = m_nicFactory.Create<P4SwitchNetDevice>();
    nic->SetAddress(Mac48Address::Allocate());
    hostNode->AddDevice(nic);
    nic->Attach(ch);

    NS_LOG_DEBUG("Port " << (switchDev->GetNPorts() - 1)
                 << " connected to host node " << hostNode->GetId());
    return nic;
}

// ---------------------------------------------------------------------------
// Pcap tracing
// ---------------------------------------------------------------------------

void
P4Helper::EnablePcapInternal(std::string    prefix,
                              Ptr<NetDevice> nd,
                              bool           promiscuous,
                              bool           explicitFilename)
{
    Ptr<P4SwitchNetDevice> device = nd->GetObject<P4SwitchNetDevice>();
    if (!device)
    {
        NS_LOG_INFO("P4Helper::EnablePcapInternal: not a P4SwitchNetDevice — skipping");
        return;
    }

    PcapHelper pcapHelper;
    std::string filename = explicitFilename ? prefix
                                            : pcapHelper.GetFilenameFromDevice(prefix, device);

    Ptr<PcapFileWrapper> file =
        pcapHelper.CreateFile(filename, std::ios::out, PcapHelper::DLT_EN10MB);

    if (promiscuous)
    {
        pcapHelper.HookDefaultSink<P4SwitchNetDevice>(device, "PromiscSniffer", file);
    }
    else
    {
        pcapHelper.HookDefaultSink<P4SwitchNetDevice>(device, "Sniffer", file);
    }
}

// ---------------------------------------------------------------------------
// Ascii tracing
// ---------------------------------------------------------------------------

void
P4Helper::EnableAsciiInternal(Ptr<OutputStreamWrapper> stream,
                               std::string              prefix,
                               Ptr<NetDevice>           nd,
                               bool                     explicitFilename)
{
    Ptr<P4SwitchNetDevice> device = nd->GetObject<P4SwitchNetDevice>();
    if (!device)
    {
        NS_LOG_INFO("P4Helper::EnableAsciiInternal: not a P4SwitchNetDevice — skipping");
        return;
    }

    Packet::EnablePrinting();

    if (!stream)
    {
        AsciiTraceHelper asciiHelper;
        std::string filename = explicitFilename ? prefix
                                                : asciiHelper.GetFilenameFromDevice(prefix, device);
        Ptr<OutputStreamWrapper> theStream = asciiHelper.CreateFileStream(filename);
        asciiHelper.HookDefaultReceiveSinkWithoutContext<P4SwitchNetDevice>(
            device, "SwitchEvent", theStream);
        return;
    }

    // Shared stream: use Config::Connect to include node/device context.
    std::ostringstream oss;
    oss << "/NodeList/" << nd->GetNode()->GetId()
        << "/DeviceList/" << nd->GetIfIndex()
        << "/$ns3::P4SwitchNetDevice/SwitchEvent";
    Config::Connect(oss.str(),
                    MakeBoundCallback(&AsciiTraceHelper::DefaultReceiveSinkWithContext, stream));
}

} // namespace ns3
