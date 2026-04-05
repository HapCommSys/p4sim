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

#include "switched-ethernet-helper.h"

#include "ns3/log.h"
#include "ns3/mac48-address.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/switched-ethernet-host-device.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("SwitchedEthernetHelper");

SwitchedEthernetHelper::SwitchedEthernetHelper()
{
    m_channelFactory.SetTypeId("ns3::SwitchedEthernetChannel");
}

void
SwitchedEthernetHelper::SetChannelAttribute(const std::string& name, const AttributeValue& value)
{
    m_channelFactory.Set(name, value);
}

NetDeviceContainer
SwitchedEthernetHelper::Install(Ptr<P4SwitchNetDevice> switchDev,
                                const NodeContainer& hosts) const
{
    NS_ASSERT_MSG(switchDev, "SwitchedEthernetHelper::Install: null switch device");
    NS_LOG_FUNCTION(this << hosts.GetN());

    NetDeviceContainer result;
    for (auto it = hosts.Begin(); it != hosts.End(); ++it)
    {
        result.Add(InstallPortPriv(switchDev, *it));
    }
    return result;
}

NetDeviceContainer
SwitchedEthernetHelper::ConnectHost(Ptr<P4SwitchNetDevice> switchDev, Ptr<Node> hostNode) const
{
    NS_ASSERT_MSG(switchDev, "SwitchedEthernetHelper::ConnectHost: null switch device");
    NS_ASSERT_MSG(hostNode,  "SwitchedEthernetHelper::ConnectHost: null host node");
    NS_LOG_FUNCTION(this << hostNode->GetId());

    return NetDeviceContainer(InstallPortPriv(switchDev, hostNode));
}

Ptr<SwitchedEthernetHostDevice>
SwitchedEthernetHelper::InstallPortPriv(Ptr<P4SwitchNetDevice> switchDev,
                                         Ptr<Node> hostNode) const
{
    // Create the channel for this port.
    Ptr<SwitchedEthernetChannel> ch = m_channelFactory.Create<SwitchedEthernetChannel>();

    // Switch side: attach as the next port.
    switchDev->Attach(ch);

    // Host side: plain Ethernet NIC.
    Ptr<SwitchedEthernetHostDevice> hostDev = CreateObject<SwitchedEthernetHostDevice>();
    hostDev->SetAddress(Mac48Address::Allocate());
    hostNode->AddDevice(hostDev);
    hostDev->Attach(ch);

    NS_LOG_DEBUG("Port " << (switchDev->GetNPorts() - 1)
                 << " connected to host node " << hostNode->GetId());
    return hostDev;
}

} // namespace ns3
