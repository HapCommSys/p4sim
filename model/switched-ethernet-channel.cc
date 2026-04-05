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
 *          Based on switched-ethernet-channel by Jeff Young <jyoung9@gatech.edu>
 */

#include "switched-ethernet-channel.h"

#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE("SwitchedEthernetChannel");

namespace ns3
{

NS_OBJECT_ENSURE_REGISTERED(SwitchedEthernetChannel);

// ---------------------------------------------------------------------------
// P4SwitchDeviceRec
// ---------------------------------------------------------------------------

P4SwitchDeviceRec::P4SwitchDeviceRec()
    : active(false)
{
}

P4SwitchDeviceRec::P4SwitchDeviceRec(Ptr<P4SwitchNetDevice> device)
    : devicePtr(device),
      active(true)
{
}

bool
P4SwitchDeviceRec::IsActive() const
{
    return active;
}

// ---------------------------------------------------------------------------
// SwitchedEthernetChannel
// ---------------------------------------------------------------------------

TypeId
SwitchedEthernetChannel::GetTypeId()
{
    static TypeId tid = TypeId("ns3::SwitchedEthernetChannel")
                            .SetParent<Channel>()
                            .AddConstructor<SwitchedEthernetChannel>()
                            .AddAttribute("DataRate",
                                          "Transmission data rate of the channel.",
                                          DataRateValue(DataRate(0xffffffff)),
                                          MakeDataRateAccessor(&SwitchedEthernetChannel::m_bps),
                                          MakeDataRateChecker())
                            .AddAttribute("Delay",
                                          "Propagation delay through the channel.",
                                          TimeValue(Seconds(0)),
                                          MakeTimeAccessor(&SwitchedEthernetChannel::m_delay),
                                          MakeTimeChecker());
    return tid;
}

SwitchedEthernetChannel::SwitchedEthernetChannel()
    : Channel()
{
    NS_LOG_FUNCTION_NOARGS();
    m_State[0] = IDLE_STATE;
    m_State[1] = IDLE_STATE;
    m_currentSrc[0] = 0;
    m_currentSrc[1] = 0;
    m_deviceList.clear();
}

// ---------------------------------------------------------------------------
// Device management
// ---------------------------------------------------------------------------

int32_t
SwitchedEthernetChannel::Attach(Ptr<P4SwitchNetDevice> device)
{
    NS_LOG_FUNCTION(this << device);
    NS_ASSERT(device);
    // Full-duplex point-to-point: exactly two slots.
    NS_ASSERT_MSG(m_deviceList.size() < 2,
                  "SwitchedEthernetChannel: cannot attach more than 2 devices");

    m_deviceList.emplace_back(device);
    return static_cast<int32_t>(m_deviceList.size() - 1);
}

bool
SwitchedEthernetChannel::Detach(Ptr<P4SwitchNetDevice> device)
{
    NS_LOG_FUNCTION(this << device);
    NS_ASSERT(device);

    for (auto& rec : m_deviceList)
    {
        if (rec.devicePtr == device && rec.active)
        {
            rec.active = false;
            return true;
        }
    }
    return false;
}

bool
SwitchedEthernetChannel::Detach(uint32_t deviceId)
{
    NS_LOG_FUNCTION(this << deviceId);

    if (deviceId >= m_deviceList.size())
    {
        return false;
    }
    if (!m_deviceList[deviceId].active)
    {
        NS_LOG_WARN("Device " << deviceId << " is already detached");
        return false;
    }
    m_deviceList[deviceId].active = false;
    return true;
}

bool
SwitchedEthernetChannel::Reattach(uint32_t deviceId)
{
    NS_LOG_FUNCTION(this << deviceId);

    if (deviceId >= m_deviceList.size())
    {
        return false;
    }
    if (m_deviceList[deviceId].active)
    {
        return false; // already active
    }
    m_deviceList[deviceId].active = true;
    return true;
}

bool
SwitchedEthernetChannel::Reattach(Ptr<P4SwitchNetDevice> device)
{
    NS_LOG_FUNCTION(this << device);
    NS_ASSERT(device);

    for (auto& rec : m_deviceList)
    {
        if (rec.devicePtr == device)
        {
            if (rec.active)
            {
                return false; // already active
            }
            rec.active = true;
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Transmission
// ---------------------------------------------------------------------------

bool
SwitchedEthernetChannel::TransmitStart(Ptr<Packet> p, uint32_t srcId)
{
    NS_LOG_FUNCTION(this << p << srcId);
    NS_LOG_INFO("UID=" << p->GetUid());

    if (m_State[srcId] != IDLE_STATE)
    {
        NS_LOG_WARN("TransmitStart: wire not IDLE for slot " << srcId);
        return false;
    }
    if (!IsActive(srcId))
    {
        NS_LOG_ERROR("TransmitStart: source slot " << srcId << " is not active");
        return false;
    }

    m_currentPkt[srcId] = p;
    m_currentSrc[srcId] = srcId;
    m_State[srcId] = TRANSMITTING_STATE;
    NS_LOG_LOGIC("Slot " << srcId << " -> TRANSMITTING_STATE");
    return true;
}

bool
SwitchedEthernetChannel::TransmitEnd(uint32_t srcId)
{
    NS_LOG_FUNCTION(this << srcId);
    NS_ASSERT(m_State[srcId] == TRANSMITTING_STATE);

    m_State[srcId] = PROPAGATING_STATE;
    NS_LOG_LOGIC("Slot " << srcId << " -> PROPAGATING_STATE");

    if (!IsActive(m_currentSrc[srcId]))
    {
        NS_LOG_ERROR("TransmitEnd: source slot " << srcId << " was detached before TX completed");
        return false;
    }

    // Schedule delivery to every active device that is NOT the sender.
    for (uint32_t i = 0; i < m_deviceList.size(); ++i)
    {
        if (m_deviceList[i].IsActive() && i != m_currentSrc[srcId])
        {
            Ptr<P4SwitchNetDevice> dst = m_deviceList[i].devicePtr;
            Ptr<P4SwitchNetDevice> sender = m_deviceList[m_currentSrc[srcId]].devicePtr;

            Simulator::ScheduleWithContext(dst->GetNode()->GetId(),
                                           m_delay,
                                           &P4SwitchNetDevice::Receive,
                                           dst,
                                           m_currentPkt[srcId]->Copy(),
                                           sender);
        }
    }

    // Release the wire after propagation.
    Simulator::Schedule(m_delay, &SwitchedEthernetChannel::PropagationCompleteEvent, this, srcId);
    return true;
}

void
SwitchedEthernetChannel::PropagationCompleteEvent(uint32_t srcId)
{
    NS_LOG_FUNCTION(this << srcId);
    NS_ASSERT(m_State[srcId] == PROPAGATING_STATE);
    m_State[srcId] = IDLE_STATE;
    NS_LOG_LOGIC("Slot " << srcId << " -> IDLE_STATE");
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

bool
SwitchedEthernetChannel::IsBusy(uint32_t deviceId) const
{
    return m_State[deviceId] != IDLE_STATE;
}

bool
SwitchedEthernetChannel::IsActive(uint32_t deviceId) const
{
    if (deviceId >= m_deviceList.size())
    {
        return false;
    }
    return m_deviceList[deviceId].active;
}

FullDuplexWireState
SwitchedEthernetChannel::GetState(uint32_t deviceId) const
{
    return m_State[deviceId];
}

int32_t
SwitchedEthernetChannel::GetDeviceNum(Ptr<P4SwitchNetDevice> device) const
{
    for (uint32_t i = 0; i < m_deviceList.size(); ++i)
    {
        if (m_deviceList[i].devicePtr == device)
        {
            return m_deviceList[i].active ? static_cast<int32_t>(i) : -2;
        }
    }
    return -1; // not found
}

uint32_t
SwitchedEthernetChannel::GetNumActDevices() const
{
    uint32_t n = 0;
    for (const auto& rec : m_deviceList)
    {
        if (rec.active)
        {
            ++n;
        }
    }
    return n;
}

std::size_t
SwitchedEthernetChannel::GetNDevices() const
{
    return static_cast<std::size_t>(m_deviceList.size());
}

Ptr<NetDevice>
SwitchedEthernetChannel::GetDevice(std::size_t i) const
{
    return GetP4SwitchDevice(i);
}

Ptr<P4SwitchNetDevice>
SwitchedEthernetChannel::GetP4SwitchDevice(std::size_t i) const
{
    NS_ASSERT(i < m_deviceList.size());
    return m_deviceList[i].devicePtr;
}

DataRate
SwitchedEthernetChannel::GetDataRate() const
{
    return m_bps;
}

Time
SwitchedEthernetChannel::GetDelay() const
{
    return m_delay;
}

} // namespace ns3
