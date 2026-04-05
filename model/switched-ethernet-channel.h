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
 *          which was based on csma-channel by
 *          Emmanuelle Laprise <emmanuelle.laprise@bluekazoo.ca>
 */

#ifndef SWITCHED_ETHERNET_CHANNEL_H
#define SWITCHED_ETHERNET_CHANNEL_H

#include "ns3/channel.h"
#include "ns3/data-rate.h"
#include "ns3/nstime.h"
#include "ns3/ptr.h"

#include <vector>

namespace ns3
{

class Packet;
class P4SwitchNetDevice;
class SwitchedEthernetHostDevice;

// ---------------------------------------------------------------------------
// Per-endpoint record
// ---------------------------------------------------------------------------

/**
 * \brief Bookkeeping for one end of a SwitchedEthernetChannel.
 *
 * Slot 0 is always a P4SwitchNetDevice (the switch).
 * Slot 1 may be either a P4SwitchNetDevice or a SwitchedEthernetHostDevice
 * (a plain host NIC).  Exactly one of the two device pointers is non-null.
 */
struct P4SwitchDeviceRec
{
    Ptr<P4SwitchNetDevice>          devicePtr;     ///< Non-null for P4 switch devices
    Ptr<SwitchedEthernetHostDevice> hostDevicePtr; ///< Non-null for plain host devices
    bool active;

    P4SwitchDeviceRec();
    explicit P4SwitchDeviceRec(Ptr<P4SwitchNetDevice> device);
    explicit P4SwitchDeviceRec(Ptr<SwitchedEthernetHostDevice> device);

    bool IsActive() const;
    /** \return true if this slot holds a plain host device (not a P4 device). */
    bool IsHost() const;
    /** \return the underlying NetDevice pointer regardless of type. */
    Ptr<NetDevice> GetNetDevice() const;
};

// ---------------------------------------------------------------------------
// Channel wire state
// ---------------------------------------------------------------------------

/**
 * \brief State of one direction of a full-duplex channel.
 */
enum FullDuplexWireState
{
    IDLE_STATE,         ///< No packet is being transmitted.
    TRANSMITTING_STATE, ///< A packet is being written onto the wire.
    PROPAGATING_STATE   ///< Packet is propagating to the far end.
};

// ---------------------------------------------------------------------------
// Channel class
// ---------------------------------------------------------------------------

/**
 * \ingroup p4sim
 *
 * \brief Full-duplex point-to-point channel for P4SwitchNetDevice.
 *
 * SwitchedEthernetChannel models a simple full-duplex link between exactly
 * two P4SwitchNetDevice instances.  It carries complete Ethernet frames
 * (packets already include the Ethernet header when passed to TransmitStart).
 *
 * The two channel slots (device IDs 0 and 1) each have independent wire
 * state so that both ends can transmit simultaneously.
 *
 * Typical usage via P4SwitchNetDevice::Attach():
 * \code
 *   Ptr<SwitchedEthernetChannel> ch = CreateObject<SwitchedEthernetChannel>();
 *   switchDev->Attach(ch);   // takes slot 0
 *   hostDev->Attach(ch);     // takes slot 1
 * \endcode
 */
class SwitchedEthernetChannel : public Channel
{
  public:
    static TypeId GetTypeId();

    SwitchedEthernetChannel();

    // -----------------------------------------------------------------------
    // Device management
    // -----------------------------------------------------------------------

    /**
     * \brief Attach a P4SwitchNetDevice to this channel.
     *
     * At most two devices may be attached (full-duplex point-to-point).
     * \return The device slot ID (0 or 1) assigned to this device.
     */
    int32_t Attach(Ptr<P4SwitchNetDevice> device);

    /**
     * \brief Attach a plain host device to this channel (slot 1).
     *
     * Called by SwitchedEthernetHostDevice::Attach().
     * \return The device slot ID assigned to this device.
     */
    int32_t AttachHost(Ptr<SwitchedEthernetHostDevice> device);

    /**
     * \brief Mark a device as inactive (detached).
     * \param device Device to detach.
     * \return true if the device was found and is now inactive.
     */
    bool Detach(Ptr<P4SwitchNetDevice> device);

    /**
     * \brief Mark a device slot as inactive.
     * \param deviceId Slot ID assigned at Attach() time.
     * \return true if the slot exists and was active.
     */
    bool Detach(uint32_t deviceId);

    /**
     * \brief Re-activate a previously detached device slot.
     * \param deviceId Slot ID to reactivate.
     * \return true if the slot exists and was inactive.
     */
    bool Reattach(uint32_t deviceId);

    /**
     * \brief Re-activate a previously detached device.
     * \param device Device to reactivate.
     * \return true if found and was inactive.
     */
    bool Reattach(Ptr<P4SwitchNetDevice> device);

    // -----------------------------------------------------------------------
    // Transmission
    // -----------------------------------------------------------------------

    /**
     * \brief Start transmitting packet \p p from slot \p srcId.
     *
     * Marks the wire as TRANSMITTING_STATE for slot \p srcId.  The caller
     * must schedule TransmitEnd() after the appropriate serialisation delay.
     *
     * \param p     Packet to transmit (full Ethernet frame).
     * \param srcId Slot ID of the transmitting device.
     * \return true if the wire was idle and the device is active.
     */
    bool TransmitStart(Ptr<Packet> p, uint32_t srcId);

    /**
     * \brief Signal end of serialisation for slot \p srcId.
     *
     * Switches the wire to PROPAGATING_STATE and schedules delivery of the
     * packet to the far-end device after the propagation delay.
     *
     * \param srcId Slot ID of the transmitting device.
     * \return true unless the source was detached before completion.
     */
    bool TransmitEnd(uint32_t srcId);

    /**
     * \brief Called after propagation delay; frees the wire and delivers the
     *        packet to the far-end P4SwitchNetDevice via its Receive() method.
     * \param srcId Slot ID that originated the transmission.
     */
    void PropagationCompleteEvent(uint32_t srcId);

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /** \return true if slot \p deviceId is currently transmitting or propagating. */
    bool IsBusy(uint32_t deviceId) const;

    /** \return true if slot \p deviceId is active. */
    bool IsActive(uint32_t deviceId) const;

    /** \return Wire state for slot \p deviceId. */
    FullDuplexWireState GetState(uint32_t deviceId) const;

    /** \return Slot ID of \p device, or -1 if not found / -2 if inactive. */
    int32_t GetDeviceNum(Ptr<P4SwitchNetDevice> device) const;

    /** \return Number of active devices. */
    uint32_t GetNumActDevices() const;

    // Channel base-class overrides
    std::size_t GetNDevices() const override;
    Ptr<NetDevice> GetDevice(std::size_t i) const override;

    /** \return The P4SwitchNetDevice at slot \p i. */
    Ptr<P4SwitchNetDevice> GetP4SwitchDevice(std::size_t i) const;

    /** \return Configured data rate. */
    DataRate GetDataRate() const;

    /** \return Configured propagation delay. */
    Time GetDelay() const;

  private:
    DataRate m_bps; ///< Link data rate
    Time m_delay;   ///< Propagation delay

    std::vector<P4SwitchDeviceRec> m_deviceList; ///< Attached device records (max 2)

    Ptr<Packet> m_currentPkt[2];    ///< Packet currently on the wire for each slot
    uint32_t m_currentSrc[2];       ///< Source slot ID for each wire
    FullDuplexWireState m_State[2]; ///< Wire state for each slot
};

} // namespace ns3

#endif /* SWITCHED_ETHERNET_CHANNEL_H */
