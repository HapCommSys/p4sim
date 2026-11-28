/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#include "ns3/log.h"
#include "ns3/p4-bridge-channel.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("P4BridgeChannel");

NS_OBJECT_ENSURE_REGISTERED(P4BridgeChannel);

TypeId
P4BridgeChannel::GetTypeId()
{
    static TypeId tid = TypeId("ns3::P4BridgeChannel")
                            .SetParent<BridgeChannel>()
                            .SetGroupName("Bridge")
                            .AddConstructor<P4BridgeChannel>();
    return tid;
}

P4BridgeChannel::P4BridgeChannel()
    : BridgeChannel() // Initialize base class
{
    NS_LOG_INFO("P4BridgeChannel created.");
}

P4BridgeChannel::~P4BridgeChannel()
{
    NS_LOG_INFO("P4BridgeChannel destroyed.");
}

std::size_t
P4BridgeChannel::GetNDevices() const
{
    return BridgeChannel::GetNDevices(); // Use base class functionality
}

Ptr<NetDevice>
P4BridgeChannel::GetDevice(std::size_t i) const
{
    return BridgeChannel::GetDevice(i); // Use base class functionality
}

// void P4BridgeChannel::InstallP4Rule(uint32_t ruleId, const std::string& ruleData)
// {
//     m_p4Rules[ruleId] = ruleData;
//     NS_LOG_INFO("Installed P4 rule with ID " << ruleId << ": " << ruleData);
// }

// void P4BridgeChannel::RemoveP4Rule(uint32_t ruleId)
// {
//     if (m_p4Rules.erase(ruleId) > 0)
//     {
//         NS_LOG_INFO("Removed P4 rule with ID " << ruleId);
//     }
//     else
//     {
//         NS_LOG_WARN("P4 rule with ID " << ruleId << " not found.");
//     }
// }

// std::map<std::string, uint64_t> P4BridgeChannel::GetP4Statistics() const
// {
//     return m_p4Stats; // Return collected statistics
// }

} // namespace ns3