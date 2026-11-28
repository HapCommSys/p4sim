/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#ifndef P4_BRIDGE_CHANNEL_H
#define P4_BRIDGE_CHANNEL_H

#include "ns3/bridge-channel.h"
#include "ns3/packet.h"

#include <map>
#include <vector>

namespace ns3
{

/**
 * \brief P4BridgeChannel: A specialized channel for P4-based bridges.
 *
 * Extends BridgeChannel to implement custom behavior for P4 devices.
 */
class P4BridgeChannel : public BridgeChannel
{
  public:
    static TypeId GetTypeId();

    P4BridgeChannel();
    ~P4BridgeChannel() override;

    // Override Channel methods
    std::size_t GetNDevices() const override;
    Ptr<NetDevice> GetDevice(std::size_t i) const override;

    // Additional methods for P4BridgeChannel
    // void InstallP4Rule(uint32_t ruleId, const std::string& ruleData);
    // void RemoveP4Rule(uint32_t ruleId);
    // std::map<std::string, uint64_t> GetP4Statistics() const;

  private:
    // std::map<uint32_t, std::string> m_p4Rules; //!< P4 flow table rules
    // std::map<std::string, uint64_t> m_p4Stats; //!< P4 statistics
};

} // namespace ns3

#endif // P4_BRIDGE_CHANNEL_H