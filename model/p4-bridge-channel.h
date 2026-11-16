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