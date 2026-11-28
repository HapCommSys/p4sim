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

#include "eth-net-device.h"

#include "ns3/enum.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4sim-ns3-compat.h"
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

P4SwitchDeviceRec::P4SwitchDeviceRec(Ptr<SwitchedEthernetHostDevice> device)
    : hostDevicePtr(device),
      active(true)
{
}

bool
P4SwitchDeviceRec::IsActive() const
{
    return active;
}

bool
P4SwitchDeviceRec::IsHost() const
{
    return hostDevicePtr != nullptr;
}

Ptr<NetDevice>
P4SwitchDeviceRec::GetNetDevice() const
{
    if (IsHost())
    {
        return hostDevicePtr;
    }
    return devicePtr;
}

// ---------------------------------------------------------------------------
// SwitchedEthernetChannel
// ---------------------------------------------------------------------------

TypeId
SwitchedEthernetChannel::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::SwitchedEthernetChannel")
            .SetParent<Channel>()
            .AddConstructor<SwitchedEthernetChannel>()
            .AddAttribute("DataRate",
                          "Transmission data rate of the channel. The default, 10 Gbps, "
                          "is a common Ethernet rate; set the rate of the link you model.",
                          DataRateValue(DataRate("10Gbps")),
                          MakeDataRateAccessor(&SwitchedEthernetChannel::m_bps),
                          MakeDataRateChecker())
            .AddAttribute("Delay",
                          "Propagation delay through the channel.",
                          TimeValue(Seconds(0)),
                          MakeTimeAccessor(&SwitchedEthernetChannel::m_delay),
                          MakeTimeChecker())
            .AddAttribute(
                "Framing",
                "What the link puts on the wire around each frame. None (the "
                "default): the frame alone. Ethernet: IEEE 802.3, the same for "
                "all data rates: 8 bytes of preamble and start-of-frame "
                "delimiter, a 4-byte FCS, padding up to the 64-byte minimum "
                "frame, and a 12-byte interframe gap before the next frame. "
                "They only take time on the wire; the far end receives the "
                "frame as it was sent.",
                EnumValue(LinkFraming::NONE),
                P4SIM_MAKE_ENUM_ACCESSOR(LinkFraming::Type, &SwitchedEthernetChannel::m_framing),
                MakeEnumChecker(LinkFraming::NONE, "None", LinkFraming::ETHERNET, "Ethernet"));
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
    m_propCount[0] = 0;
    m_propCount[1] = 0;
    m_txEnd[0] = 0;
    m_txEnd[1] = 0;
    m_framing = LinkFraming::NONE;
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
    NS_ASSERT_MSG(m_deviceList.size() < 2,
                  "SwitchedEthernetChannel: cannot attach more than 2 devices");

    m_deviceList.emplace_back(device);
    return static_cast<int32_t>(m_deviceList.size() - 1);
}

int32_t
SwitchedEthernetChannel::AttachHost(Ptr<SwitchedEthernetHostDevice> device)
{
    NS_LOG_FUNCTION(this << device);
    NS_ASSERT(device);
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
SwitchedEthernetChannel::TransmitStart(Ptr<Packet> p, uint32_t srcId, Time* txTime)
{
    NS_LOG_FUNCTION(this << p << srcId);
    NS_LOG_INFO("UID=" << p->GetUid());

    // Refused only while the slot is still serialising a frame.  A slot that is
    // merely propagating earlier frames may start a new one (full-duplex serial
    // link: bits keep flowing behind the frames already on the wire).
    if (m_State[srcId] == TRANSMITTING_STATE)
    {
        NS_LOG_WARN("TransmitStart: slot " << srcId << " still serialising a frame");
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

    // Exact times in seconds. A frame that follows the previous one back to
    // back (it starts no later than the rounded end of that frame and its gap)
    // starts at their exact end, which may lie up to half a time step before
    // or after now. After an idle time, a frame starts now.
    bool backToBack = Time::From(m_txEnd[srcId], Time::S) >= Simulator::Now();
    int64x64_t start = backToBack ? m_txEnd[srcId] : Simulator::Now().To(Time::S);
    // The frame takes its bytes on the wire; the interframe gap after it only
    // delays the next frame, not the delivery of this one
    LinkFraming framing(m_framing);
    int64x64_t bitRate(m_bps.GetBitRate());
    int64x64_t frameEnd = start + int64x64_t(framing.GetWireBytes(p->GetSize()) * 8) / bitRate;
    m_txEnd[srcId] = frameEnd + int64x64_t(framing.GetGapBytes() * 8) / bitRate;
    if (txTime)
    {
        *txTime = Time::From(frameEnd, Time::S) - Simulator::Now();
    }

    // A switch that forwards cut-through gets the frame as soon as the bytes it
    // decides on have arrived; TransmitEnd() does not deliver it again
    uint32_t wireBytes = framing.GetWireBytes(p->GetSize());
    for (uint32_t i = 0; i < m_deviceList.size(); ++i)
    {
        if (!m_deviceList[i].IsActive() || i == srcId || m_deviceList[i].IsHost())
        {
            continue;
        }
        Ptr<P4SwitchNetDevice> dst = m_deviceList[i].devicePtr;
        uint32_t decisionBytes = std::min(dst->GetCutThroughBytes(), wireBytes);
        if (decisionBytes == 0)
        {
            continue;
        }
        Time firstBit = Time::From(start, Time::S) + m_delay;
        Time headers =
            Time::From(start + int64x64_t(decisionBytes * 8) / bitRate, Time::S) + m_delay;
        Time wait = headers > Simulator::Now() ? headers - Simulator::Now() : Time(0);
        Simulator::ScheduleWithContext(dst->GetNode()->GetId(),
                                       wait,
                                       &P4SwitchNetDevice::ReceiveHeaders,
                                       dst,
                                       p->Copy(),
                                       Ptr<SwitchedEthernetChannel>(this),
                                       i,
                                       firstBit);
    }
    return true;
}

bool
SwitchedEthernetChannel::TransmitEnd(uint32_t srcId)
{
    NS_LOG_FUNCTION(this << srcId);
    NS_ASSERT(m_State[srcId] == TRANSMITTING_STATE);

    // Serialisation is complete: the sender is free to start the next frame
    // right away, even though this frame is still propagating to the far end.
    m_State[srcId] = IDLE_STATE;

    if (!IsActive(m_currentSrc[srcId]))
    {
        NS_LOG_ERROR("TransmitEnd: source slot " << srcId << " was detached before TX completed");
        return false;
    }

    // This frame is now in flight (one more outstanding propagation on the slot).
    m_propCount[srcId]++;
    NS_LOG_LOGIC("Slot " << srcId << " serialisation complete; in-flight frames="
                         << m_propCount[srcId]);

    // Schedule delivery to every active device that is NOT the sender.
    for (uint32_t i = 0; i < m_deviceList.size(); ++i)
    {
        if (!m_deviceList[i].IsActive() || i == m_currentSrc[srcId])
        {
            continue;
        }

        Ptr<Packet> pktCopy = m_currentPkt[srcId]->Copy();

        if (m_deviceList[i].IsHost())
        {
            // Plain host device: deliver the full Ethernet frame directly.
            Ptr<SwitchedEthernetHostDevice> dst = m_deviceList[i].hostDevicePtr;
            Simulator::ScheduleWithContext(dst->GetNode()->GetId(),
                                           m_delay,
                                           &SwitchedEthernetHostDevice::ReceiveFrame,
                                           dst,
                                           pktCopy);
        }
        else
        {
            // P4 switch device: its port is the one attached to this channel in
            // slot i (the sender may be a host, which has no P4 device)
            Ptr<P4SwitchNetDevice> dst = m_deviceList[i].devicePtr;
            Simulator::ScheduleWithContext(dst->GetNode()->GetId(),
                                           m_delay,
                                           &P4SwitchNetDevice::Receive,
                                           dst,
                                           pktCopy,
                                           Ptr<SwitchedEthernetChannel>(this),
                                           i);
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
    // Retire one in-flight frame.  We do NOT touch m_State here: the slot may
    // already be serialising a newer frame (TRANSMITTING_STATE), and that must
    // not be reset by an earlier frame finishing its propagation.
    NS_ASSERT(m_propCount[srcId] > 0);
    m_propCount[srcId]--;
    NS_LOG_LOGIC("Slot " << srcId << " propagation complete; in-flight frames="
                         << m_propCount[srcId]);
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

bool
SwitchedEthernetChannel::IsBusy(uint32_t deviceId) const
{
    // Only serialisation blocks a new frame; propagation does not.
    return m_State[deviceId] == TRANSMITTING_STATE;
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
    // m_State only tracks serialisation; PROPAGATING is derived from the count
    // of frames still in flight on the slot.
    if (m_State[deviceId] == TRANSMITTING_STATE)
    {
        return TRANSMITTING_STATE;
    }
    if (m_propCount[deviceId] > 0)
    {
        return PROPAGATING_STATE;
    }
    return IDLE_STATE;
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
    NS_ASSERT(i < m_deviceList.size());
    return m_deviceList[i].GetNetDevice();
}

Ptr<P4SwitchNetDevice>
SwitchedEthernetChannel::GetP4SwitchDevice(std::size_t i) const
{
    NS_ASSERT(i < m_deviceList.size());
    return m_deviceList[i].devicePtr; // null if slot is a host device
}

DataRate
SwitchedEthernetChannel::GetDataRate() const
{
    return m_bps;
}

LinkFraming::Type
SwitchedEthernetChannel::GetFraming() const
{
    return m_framing;
}

Time
SwitchedEthernetChannel::GetDelay() const
{
    return m_delay;
}

} // namespace ns3
