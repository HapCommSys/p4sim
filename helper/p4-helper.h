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

class SwitchedEthernetChannel;
class P4SwitchNetDevice;

/**
 * \ingroup p4sim
 * \brief Helper for building P4-programmable switch topologies.
 *
 * P4Helper manages three object factories:
 *  - **switch device** (P4SwitchNetDevice with P4 pipeline, installed on the switch node)
 *  - **NIC device**    (P4SwitchNetDevice in passthrough mode, installed on each host node)
 *  - **channel**       (SwitchedEthernetChannel, one per switch-port / host pair)
 *
 * Each switch port is a dedicated full-duplex point-to-point channel, so the
 * channel attributes (DataRate, Delay) apply to every link created by this
 * helper.  Use SetChannelAttribute() to configure them before calling Install.
 *
 * Typical usage:
 * \code
 *   NodeContainer hosts;  hosts.Create(3);
 *   Ptr<Node>     sw;     sw = CreateObject<Node>();
 *
 *   P4Helper p4;
 *   p4.SetDeviceAttribute("JsonPath",      StringValue("/path/switch.json"));
 *   p4.SetDeviceAttribute("FlowTablePath", StringValue("/path/rules.txt"));
 *   p4.SetChannelAttribute("DataRate",     DataRateValue(DataRate("1Gbps")));
 *   p4.SetChannelAttribute("Delay",        TimeValue(MicroSeconds(5)));
 *
 *   // Creates: one P4SwitchNetDevice on sw, one NIC on each host,
 *   //          and three SwitchedEthernetChannels.
 *   NetDeviceContainer devs = p4.Install(sw, hosts);
 *   // devs[0]  = switch device
 *   // devs[1..3] = host NIC devices
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
     * \brief Set an attribute on the P4SwitchNetDevice created for the
     *        switch node (pipeline mode).
     */
    void SetDeviceAttribute(const std::string& name, const AttributeValue& value);

    /**
     * \brief Set an attribute on the P4SwitchNetDevice created for each
     *        host node (NIC / passthrough mode).
     */
    void SetNicAttribute(const std::string& name, const AttributeValue& value);

    /**
     * \brief Set an attribute on every SwitchedEthernetChannel created by
     *        this helper (e.g. "DataRate", "Delay").
     */
    void SetChannelAttribute(const std::string& name, const AttributeValue& value);

    // -----------------------------------------------------------------------
    // Install — switch device only
    // -----------------------------------------------------------------------

    /**
     * \brief Install a P4SwitchNetDevice (switch mode) on \p switchNode.
     *
     * No channels or NIC devices are created.  Call ConnectHost() afterward
     * to add individual ports.
     *
     * \param switchNode The switch node.
     * \return Container holding the created switch device.
     */
    NetDeviceContainer Install(Ptr<Node> switchNode) const;

    /**
     * \brief Install a P4SwitchNetDevice (switch mode) on the named node.
     */
    NetDeviceContainer Install(const std::string& switchNodeName) const;

    // -----------------------------------------------------------------------
    // Install — switch + ports in one call
    // -----------------------------------------------------------------------

    /**
     * \brief Install a P4 switch on \p switchNode and connect it to every
     *        node in \p hosts via individual SwitchedEthernetChannels.
     *
     * For each host a new channel is created (using the channel factory
     * attributes), the switch device acquires a new port, and a NIC device
     * is installed on the host node.
     *
     * Return value layout:
     *  - index 0   : the P4SwitchNetDevice on \p switchNode
     *  - index 1…N : the NIC P4SwitchNetDevice on hosts[0…N-1]
     *
     * \param switchNode The P4 switch node.
     * \param hosts      Host nodes to connect as switch ports.
     * \return Container with switch device + all host NIC devices.
     */
    NetDeviceContainer Install(Ptr<Node> switchNode, const NodeContainer& hosts) const;

    // -----------------------------------------------------------------------
    // Add a single port to an already-installed switch
    // -----------------------------------------------------------------------

    /**
     * \brief Connect \p hostNode to the switch device \p switchDev via a
     *        new SwitchedEthernetChannel.
     *
     * A NIC device is created on \p hostNode and both ends are attached to
     * a freshly created channel.  Use this to incrementally add ports to a
     * switch after the initial Install() call.
     *
     * \param switchDev Existing switch device (already on its node).
     * \param hostNode  Node to connect as the new port's far end.
     * \return Container holding the NIC device created on \p hostNode.
     */
    NetDeviceContainer ConnectHost(Ptr<P4SwitchNetDevice> switchDev, Ptr<Node> hostNode) const;

  private:
    /**
     * \brief Create and configure the P4SwitchNetDevice for the switch node.
     *        Assigns a unique MAC address and adds the device to the node.
     */
    Ptr<P4SwitchNetDevice> InstallSwitchPriv(Ptr<Node> node) const;

    /**
     * \brief Create a NIC P4SwitchNetDevice on \p hostNode, attach both it
     *        and \p switchDev to a new channel, and return the NIC device.
     */
    Ptr<P4SwitchNetDevice> InstallPortPriv(Ptr<P4SwitchNetDevice> switchDev,
                                           Ptr<Node> hostNode) const;

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

    ObjectFactory m_deviceFactory;  ///< P4SwitchNetDevice (switch / pipeline mode)
    ObjectFactory m_nicFactory;     ///< P4SwitchNetDevice (NIC / passthrough mode)
    ObjectFactory m_channelFactory; ///< SwitchedEthernetChannel
};

} // namespace ns3

#endif /* P4_HELPER_H */
