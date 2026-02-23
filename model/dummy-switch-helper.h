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
 * Authors: P4sim Contributors
 */

#ifndef DUMMY_SWITCH_HELPER_H
#define DUMMY_SWITCH_HELPER_H

#include "ns3/dummy-switch-net-device.h"
#include "ns3/net-device-container.h"
#include "ns3/node.h"
#include "ns3/object-factory.h"

namespace ns3
{

/**
 * \ingroup p4sim
 * \brief Helper to install DummySwitchNetDevice on nodes.
 *
 * DummySwitchHelper simplifies creating and configuring a DummySwitchNetDevice.
 * It follows the same pattern as P4Helper and BridgeHelper.
 */
class DummySwitchHelper
{
  public:
    DummySwitchHelper();

    /**
     * \brief Set an attribute on the DummySwitchNetDevice.
     * \param n1 attribute name
     * \param v1 attribute value
     */
    void SetDeviceAttribute(std::string n1, const AttributeValue& v1);

    /**
     * \brief Install a DummySwitchNetDevice on a node.
     *
     * Creates a DummySwitchNetDevice, adds each NetDevice in the container
     * as a port, and installs the switch on the node.
     *
     * \param node the node to install on
     * \param portDevices the NetDevices to add as switch ports
     * \return the created DummySwitchNetDevice
     */
    Ptr<DummySwitchNetDevice> Install(Ptr<Node> node,
                                      NetDeviceContainer portDevices);

    /**
     * \brief Install a DummySwitchNetDevice on a node (by name).
     * \param nodeName the name of the node
     * \param portDevices the NetDevices to add as switch ports
     * \return the created DummySwitchNetDevice
     */
    Ptr<DummySwitchNetDevice> Install(std::string nodeName,
                                      NetDeviceContainer portDevices);

  private:
    ObjectFactory m_deviceFactory; //!< Factory for creating DummySwitchNetDevice
};

} // namespace ns3

#endif /* DUMMY_SWITCH_HELPER_H */
