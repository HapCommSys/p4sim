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

#ifndef P4_HELPER_H
#define P4_HELPER_H

#include "ns3/attribute.h"
#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/trace-helper.h"

#include <string>

namespace ns3
{

/**
 * \ingroup p4sim
 * \brief Helper for installing a P4SwitchNetDevice on a switch node.
 *
 * P4Helper manages a single object factory for the P4SwitchNetDevice.
 * Use SetDeviceAttribute() to configure P4-specific parameters (JsonPath,
 * FlowTablePath, P4SwitchArch, SwitchRate, …) before calling Install().
 *
 * To connect host nodes use SwitchedEthernetHelper, which owns the channel
 * factory and the SwitchedEthernetHostDevice installation:
 *
 * \code
 *   // Switch setup — P4 parameters only
 *   P4Helper p4;
 *   p4.SetDeviceAttribute("JsonPath",      StringValue("/path/switch.json"));
 *   p4.SetDeviceAttribute("FlowTablePath", StringValue("/path/rules.txt"));
 *   p4.SetDeviceAttribute("P4SwitchArch",  UintegerValue(0)); // V1Model
 *   p4.SetDeviceAttribute("SwitchRate",    UintegerValue(10000));
 *   NetDeviceContainer swDevs = p4.Install(switchNode);
 *   Ptr<P4SwitchNetDevice> sw =
 *       DynamicCast<P4SwitchNetDevice>(swDevs.Get(0));
 *
 *   // Host setup — channel / NIC parameters only
 *   SwitchedEthernetHelper eth;
 *   eth.SetChannelAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
 *   eth.SetChannelAttribute("Delay",    TimeValue(MicroSeconds(5)));
 *   NetDeviceContainer hostDevs = eth.Install(sw, hosts);
 * \endcode
 */
class P4Helper : public PcapHelperForDevice, public AsciiTraceHelperForDevice
{
  public:
    P4Helper();
    ~P4Helper() override = default;

    // -----------------------------------------------------------------------
    // Attribute configuration
    // -----------------------------------------------------------------------

    /**
     * \brief Set an attribute on the P4SwitchNetDevice created by Install().
     *
     * Typical attributes: JsonPath, FlowTablePath, P4SwitchArch, SwitchRate.
     */
    void SetDeviceAttribute(const std::string& name, const AttributeValue& value);

    // -----------------------------------------------------------------------
    // Install
    // -----------------------------------------------------------------------

    /**
     * \brief Install a P4SwitchNetDevice on \p switchNode.
     *
     * Assigns a unique MAC address and adds the device to the node.
     * No channels or NIC devices are created — use SwitchedEthernetHelper
     * to connect host nodes.
     *
     * \param switchNode The switch node.
     * \return Container holding the created P4SwitchNetDevice.
     */
    NetDeviceContainer Install(Ptr<Node> switchNode) const;

    /**
     * \brief Install a P4SwitchNetDevice on the named node.
     */
    NetDeviceContainer Install(const std::string& switchNodeName) const;

  private:
    Ptr<P4SwitchNetDevice> InstallSwitchPriv(Ptr<Node> node) const;

    // PcapHelperForDevice
    void EnablePcapInternal(std::string prefix,
                            Ptr<NetDevice> nd,
                            bool promiscuous,
                            bool explicitFilename) override;

    // AsciiTraceHelperForDevice
    void EnableAsciiInternal(Ptr<OutputStreamWrapper> stream,
                             std::string prefix,
                             Ptr<NetDevice> nd,
                             bool explicitFilename) override;

    ObjectFactory m_deviceFactory; ///< P4SwitchNetDevice factory
};

} // namespace ns3

#endif /* P4_HELPER_H */
