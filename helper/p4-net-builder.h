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
 * Author: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#ifndef P4_NET_BUILDER_H
#define P4_NET_BUILDER_H

#include "ns3/abort.h"
#include "ns3/ipv4-interface-container.h"
#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/p4-topology-reader.h"

#include <string>
#include <vector>

namespace ns3
{

/**
 * \ingroup p4sim
 *
 * \brief Per-switch bookkeeping used when building a P4 network from a topology file.
 *
 * Holds the NetDeviceContainer for the switch's ports and a human-readable
 * description of each port's peer (e.g. "h2" or "s1_0").
 */
struct SwitchNodeC_t
{
    NetDeviceContainer switchDevices;
    std::vector<std::string> switchPortInfos;
};

/**
 * \ingroup p4sim
 *
 * \brief Per-host bookkeeping used when building a P4 network from a topology file.
 *
 * Records the single NetDevice attached to the host, the switch it connects to,
 * and the port number on that switch.
 */
struct HostNodeC_t
{
    NetDeviceContainer hostDevice;
    Ipv4InterfaceContainer hostIpv4;
    unsigned int linkSwitchIndex;
    unsigned int linkSwitchPort;
    std::string hostIpv4Str;
};

/**
 * \brief Install CSMA or P2P links from a topology file and populate switch/host bookkeeping.
 *
 * Iterates over every link in \p topoReader, calls \p channelHelper.Install() for each
 * one, and fills \p switchNodes and \p hostNodes with the resulting NetDevices and
 * port-adjacency information.  All channel attributes (DataRate, Delay, etc.) are
 * expected to be pre-configured on \p channelHelper before calling this function;
 * per-link attribute overrides from the topology file are not applied here, because
 * DataRate and Delay semantics differ between CsmaHelper and P4PointToPointHelper.
 *
 * \tparam ChannelHelper  Any helper that exposes SetChannelAttribute() and
 *                        Install(NodeContainer), e.g. CsmaHelper or P4PointToPointHelper.
 *
 * \param topoReader   Topology reader whose links have already been loaded.
 * \param channelHelper Channel/link helper, pre-configured with the default DataRate.
 * \param switchNodes  Output vector, must be pre-sized to switchNum entries.
 * \param hostNodes    Output vector, must be pre-sized to hostNum entries.
 */
template <typename ChannelHelper>
void
BuildNetworkFromTopology(Ptr<P4TopologyReader> topoReader,
                         ChannelHelper& channelHelper,
                         std::vector<SwitchNodeC_t>& switchNodes,
                         std::vector<HostNodeC_t>& hostNodes)
{
    const unsigned int switchNum = topoReader->GetSwitchNodeContainer().GetN();

    for (auto iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); ++iter)
    {
        const unsigned int fromIndex = iter->GetFromIndex();
        const unsigned int toIndex = iter->GetToIndex();
        NetDeviceContainer link =
            channelHelper.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

        if (iter->GetFromType() == 's' && iter->GetToType() == 's')
        {
            unsigned int fromPort = switchNodes[fromIndex].switchDevices.GetN();
            unsigned int toPort = switchNodes[toIndex].switchDevices.GetN();
            switchNodes[fromIndex].switchDevices.Add(link.Get(0));
            switchNodes[fromIndex].switchPortInfos.push_back(
                "s" + std::to_string(toIndex) + "_" + std::to_string(toPort));
            switchNodes[toIndex].switchDevices.Add(link.Get(1));
            switchNodes[toIndex].switchPortInfos.push_back(
                "s" + std::to_string(fromIndex) + "_" + std::to_string(fromPort));
        }
        else if (iter->GetFromType() == 's' && iter->GetToType() == 'h')
        {
            unsigned int fromPort = switchNodes[fromIndex].switchDevices.GetN();
            switchNodes[fromIndex].switchDevices.Add(link.Get(0));
            switchNodes[fromIndex].switchPortInfos.push_back(
                "h" + std::to_string(toIndex - switchNum));
            hostNodes[toIndex - switchNum].hostDevice.Add(link.Get(1));
            hostNodes[toIndex - switchNum].linkSwitchIndex = fromIndex;
            hostNodes[toIndex - switchNum].linkSwitchPort = fromPort;
        }
        else if (iter->GetFromType() == 'h' && iter->GetToType() == 's')
        {
            unsigned int toPort = switchNodes[toIndex].switchDevices.GetN();
            switchNodes[toIndex].switchDevices.Add(link.Get(1));
            switchNodes[toIndex].switchPortInfos.push_back(
                "h" + std::to_string(fromIndex - switchNum));
            hostNodes[fromIndex - switchNum].hostDevice.Add(link.Get(0));
            hostNodes[fromIndex - switchNum].linkSwitchIndex = toIndex;
            hostNodes[fromIndex - switchNum].linkSwitchPort = toPort;
        }
        else
        {
            NS_ABORT_MSG("BuildNetworkFromTopology: unsupported link type '"
                         << iter->GetFromType() << "' -> '" << iter->GetToType() << "'");
        }
    }
}

} // namespace ns3

#endif /* P4_NET_BUILDER_H */
