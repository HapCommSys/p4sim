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
#include "ns3/queue.h"
#include "ns3/trace-helper.h"

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
 *
 * Like PointToPointHelper and CsmaHelper, the helper enables flow control on
 * the host devices by default: a host device tells the traffic control layer
 * when its transmit queue is full, so that the packets wait in the queue disc
 * installed on it (FqCoDelQueueDisc by default, see Ipv4AddressHelper) and the
 * queue disc decides which packet is sent next. Choose another queue disc with
 * TrafficControlHelper, the device queue with SetQueue(), or disable flow
 * control with DisableFlowControl().
 */
class SwitchedEthernetHelper : public PcapHelperForDevice, public AsciiTraceHelperForDevice
{
  public:
    SwitchedEthernetHelper();
    ~SwitchedEthernetHelper() override = default;

    // -----------------------------------------------------------------------
    // Channel attribute configuration
    // -----------------------------------------------------------------------

    /**
     * \brief Set an attribute on every SwitchedEthernetChannel created by
     *        this helper (e.g. "DataRate", "Delay").
     */
    void SetChannelAttribute(const std::string& name, const AttributeValue& value);

    /**
     * \brief Set the type and attributes of the transmit queue of every host
     *        device created by this helper. The default is a
     *        DropTailQueue<Packet> of 100 packets.
     *
     * With flow control, packets wait in the queue disc only once this queue
     * is full, so a small queue gives the queue disc more to schedule.
     *
     * \tparam Ts \deduced Argument types
     * \param type the type of queue
     * \param [in] args Name and AttributeValue pairs to set.
     */
    template <typename... Ts>
    void SetQueue(std::string type, Ts&&... args);

    /**
     * \brief Disable flow control on the host devices created by this helper.
     *
     * Without flow control, the host device never tells the traffic control
     * layer that its queue is full: a queue disc then passes every packet on
     * at once and never schedules anything, and Ipv4AddressHelper installs no
     * queue disc. This was the behaviour before flow control was added.
     */
    void DisableFlowControl();

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

    ObjectFactory m_channelFactory; ///< SwitchedEthernetChannel factory
    ObjectFactory m_queueFactory;   ///< factory for the transmit queues of the host devices
    bool m_enableFlowControl{true}; ///< whether to enable flow control
};

/***************************************************************
 *  Implementation of the templates declared above.
 ***************************************************************/

template <typename... Ts>
void
SwitchedEthernetHelper::SetQueue(std::string type, Ts&&... args)
{
    QueueBase::AppendItemTypeIfNotPresent(type, "Packet");
    m_queueFactory.SetTypeId(type);
    m_queueFactory.Set(std::forward<Ts>(args)...);
}

} // namespace ns3

#endif /* SWITCHED_ETHERNET_HELPER_H */
