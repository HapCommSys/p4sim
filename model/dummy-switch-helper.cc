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

#include "ns3/dummy-switch-helper.h"

#include "ns3/log.h"
#include "ns3/names.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("DummySwitchHelper");

DummySwitchHelper::DummySwitchHelper()
{
    NS_LOG_FUNCTION(this);
    m_deviceFactory.SetTypeId("ns3::DummySwitchNetDevice");
}

void
DummySwitchHelper::SetDeviceAttribute(std::string n1, const AttributeValue& v1)
{
    NS_LOG_FUNCTION(this << n1);
    m_deviceFactory.Set(n1, v1);
}

Ptr<DummySwitchNetDevice>
DummySwitchHelper::Install(Ptr<Node> node, NetDeviceContainer portDevices)
{
    NS_LOG_FUNCTION(this << node);

    Ptr<DummySwitchNetDevice> dev = m_deviceFactory.Create<DummySwitchNetDevice>();
    node->AddDevice(dev);

    for (uint32_t i = 0; i < portDevices.GetN(); i++)
    {
        dev->AddPort(portDevices.Get(i));
    }

    NS_LOG_INFO("Installed DummySwitchNetDevice on node " << node->GetId()
                << " with " << portDevices.GetN() << " ports");
    return dev;
}

Ptr<DummySwitchNetDevice>
DummySwitchHelper::Install(std::string nodeName, NetDeviceContainer portDevices)
{
    NS_LOG_FUNCTION(this << nodeName);
    Ptr<Node> node = Names::Find<Node>(nodeName);
    return Install(node, portDevices);
}

} // namespace ns3
