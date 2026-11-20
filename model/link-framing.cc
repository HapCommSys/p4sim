// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

#include "ns3/link-framing.h"

#include <algorithm>

namespace ns3
{

LinkFraming::LinkFraming(Type type)
    : m_type(type),
      m_preambleBytes(0),
      m_fcsBytes(0),
      m_minFrameBytes(0),
      m_gapBytes(0)
{
    if (type == ETHERNET)
    {
        // IEEE 802.3, the same for all data rates: 7 bytes of preamble and a
        // 1-byte start-of-frame delimiter; a 4-byte FCS; a frame of at least
        // 64 bytes with its FCS; at least 96 bit times between two frames
        m_preambleBytes = 8;
        m_fcsBytes = 4;
        m_minFrameBytes = 60;
        m_gapBytes = 12;
    }
}

LinkFraming::Type
LinkFraming::GetType() const
{
    return m_type;
}

uint32_t
LinkFraming::GetWireBytes(uint32_t frameBytes) const
{
    return m_preambleBytes + std::max(frameBytes, m_minFrameBytes) + m_fcsBytes;
}

uint32_t
LinkFraming::GetGapBytes() const
{
    return m_gapBytes;
}

} // namespace ns3
