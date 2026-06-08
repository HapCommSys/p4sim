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

#ifndef P4_SWITCH_QUEUE_ITEM_H
#define P4_SWITCH_QUEUE_ITEM_H

#include "ns3/queue-item.h"

namespace ns3
{

/**
 * \ingroup p4sim
 *
 * \brief QueueDiscItem for packets emitted by the P4 egress pipeline.
 *
 * The P4 pipeline produces complete Ethernet frames, so AddHeader() is a
 * no-op.  The item stores the egress port index so that the switch can
 * route the dequeued packet to the correct channel.
 */
class P4SwitchQueueItem : public QueueDiscItem
{
  public:
    /**
     * \brief Construct a P4SwitchQueueItem.
     *
     * \param p        The packet (complete Ethernet frame from P4 pipeline).
     * \param addr     Destination MAC address.
     * \param protocol L3 protocol number.
     * \param portIndex  Egress port index on the P4SwitchNetDevice.
     */
    P4SwitchQueueItem(Ptr<Packet> p,
                      const Address& addr,
                      uint16_t protocol,
                      uint32_t portIndex);

    ~P4SwitchQueueItem() override;

    // Delete copy constructor and assignment to match base class.
    P4SwitchQueueItem(const P4SwitchQueueItem&) = delete;
    P4SwitchQueueItem& operator=(const P4SwitchQueueItem&) = delete;

    /**
     * \brief No-op: the P4 pipeline already attached the Ethernet header.
     */
    void AddHeader() override;

    /**
     * \brief ECN marking is not supported at this stage.
     * \return always false.
     */
    bool Mark() override;

    /**
     * \brief Get the egress port index stored at enqueue time.
     * \return the port index.
     */
    uint32_t GetPortIndex() const;

  private:
    uint32_t m_portIndex; //!< Egress port on the P4SwitchNetDevice.
};

} // namespace ns3

#endif /* P4_SWITCH_QUEUE_ITEM_H */
