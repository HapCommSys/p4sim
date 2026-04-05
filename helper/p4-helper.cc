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
#include "ns3/trace-helper.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("P4Helper");

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

P4Helper::P4Helper()
{
    m_deviceFactory.SetTypeId("ns3::P4SwitchNetDevice");
}

// ---------------------------------------------------------------------------
// Attribute configuration
// ---------------------------------------------------------------------------

void
P4Helper::SetDeviceAttribute(const std::string& name, const AttributeValue& value)
{
    m_deviceFactory.Set(name, value);
}

// ---------------------------------------------------------------------------
// Install
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

    std::ostringstream oss;
    oss << "/NodeList/" << nd->GetNode()->GetId()
        << "/DeviceList/" << nd->GetIfIndex()
        << "/$ns3::P4SwitchNetDevice/SwitchEvent";
    Config::Connect(oss.str(),
                    MakeBoundCallback(&AsciiTraceHelper::DefaultReceiveSinkWithContext, stream));
}

} // namespace ns3
