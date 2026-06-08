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

#include "p4-switch-queue-item.h"

#include "ns3/log.h"
#include "ns3/packet.h"

NS_LOG_COMPONENT_DEFINE("P4SwitchQueueItem");

namespace ns3
{

P4SwitchQueueItem::P4SwitchQueueItem(Ptr<Packet> p,
                                     const Address& addr,
                                     uint16_t protocol,
                                     uint32_t portIndex)
    : QueueDiscItem(p, addr, protocol),
      m_portIndex(portIndex)
{
    NS_LOG_FUNCTION(this << p << addr << protocol << portIndex);
}

P4SwitchQueueItem::~P4SwitchQueueItem()
{
    NS_LOG_FUNCTION(this);
}

void
P4SwitchQueueItem::AddHeader()
{
    // The P4 deparser already constructed the complete Ethernet frame.
    // Nothing to do here.
}

bool
P4SwitchQueueItem::Mark()
{
    // ECN marking is not supported at this stage.
    return false;
}

uint32_t
P4SwitchQueueItem::GetPortIndex() const
{
    return m_portIndex;
}

} // namespace ns3
