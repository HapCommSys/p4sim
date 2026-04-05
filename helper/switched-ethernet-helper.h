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

#ifndef SWITCHED_ETHERNET_HELPER_H
#define SWITCHED_ETHERNET_HELPER_H

#include "ns3/attribute.h"
#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"
#include "ns3/p4-switch-net-device.h"

#include <string>

namespace ns3
{

class SwitchedEthernetHostDevice;

/**
 * \ingroup p4sim
 * \brief Helper for connecting plain (non-P4) host nodes to a P4SwitchNetDevice.
 *
 * SwitchedEthernetHelper creates one SwitchedEthernetChannel per host and
 * installs a SwitchedEthernetHostDevice on each host node.  It has no
 * knowledge of P4 programs or flow tables — those are configured through
 * P4Helper on the switch side.
 *
 * Typical usage:
 * \code
 *   // 1) Install the P4 switch with P4-specific parameters
 *   P4Helper p4;
 *   p4.SetDeviceAttribute("JsonPath",      StringValue("/path/switch.json"));
 *   p4.SetDeviceAttribute("FlowTablePath", StringValue("/path/rules.txt"));
 *   NetDeviceContainer swDevs = p4.Install(switchNode);
 *   Ptr<P4SwitchNetDevice> sw =
 *       DynamicCast<P4SwitchNetDevice>(swDevs.Get(0));
 *
 *   // 2) Connect hosts with channel-level parameters only
 *   SwitchedEthernetHelper eth;
 *   eth.SetChannelAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
 *   eth.SetChannelAttribute("Delay",    TimeValue(MicroSeconds(5)));
 *   NetDeviceContainer hostDevs = eth.Install(sw, hosts);
 * \endcode
 */
class SwitchedEthernetHelper
{
  public:
    SwitchedEthernetHelper();
    ~SwitchedEthernetHelper() = default;

    // -----------------------------------------------------------------------
    // Channel attribute configuration
    // -----------------------------------------------------------------------

    /**
     * \brief Set an attribute on every SwitchedEthernetChannel created by
     *        this helper (e.g. "DataRate", "Delay").
     */
    void SetChannelAttribute(const std::string& name, const AttributeValue& value);

    // -----------------------------------------------------------------------
    // Install
    // -----------------------------------------------------------------------

    /**
     * \brief Connect all nodes in \p hosts to \p switchDev.
     *
     * For each host node a new SwitchedEthernetChannel and a
     * SwitchedEthernetHostDevice are created.  The host device is assigned a
     * unique MAC address and added to the host node.
     *
     * \param switchDev An already-installed P4SwitchNetDevice.
     * \param hosts     Host nodes to connect as switch ports.
     * \return Container holding the SwitchedEthernetHostDevice for each host,
     *         in the same order as \p hosts.
     */
    NetDeviceContainer Install(Ptr<P4SwitchNetDevice> switchDev,
                               const NodeContainer& hosts) const;

    /**
     * \brief Connect a single host node to \p switchDev.
     *
     * \param switchDev An already-installed P4SwitchNetDevice.
     * \param hostNode  The host node to connect.
     * \return Container holding the SwitchedEthernetHostDevice on \p hostNode.
     */
    NetDeviceContainer ConnectHost(Ptr<P4SwitchNetDevice> switchDev,
                                   Ptr<Node> hostNode) const;

  private:
    Ptr<SwitchedEthernetHostDevice> InstallPortPriv(Ptr<P4SwitchNetDevice> switchDev,
                                                     Ptr<Node> hostNode) const;

    ObjectFactory m_channelFactory; ///< SwitchedEthernetChannel factory
};

} // namespace ns3

#endif /* SWITCHED_ETHERNET_HELPER_H */
