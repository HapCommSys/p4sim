// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

#ifndef LINK_FRAMING_H
#define LINK_FRAMING_H

#include <cstdint>

namespace ns3
{

/**
 * \ingroup p4sim
 * \brief The bytes that a link puts on the wire around each frame
 *
 * An ns-3 frame holds the MAC header and the payload. A real link sends more:
 * on Ethernet, a preamble before the frame, a frame check sequence (FCS) after
 * it, padding up to the minimum frame size, and an idle interframe gap before
 * the next frame. LinkFraming gives these numbers for one kind of link, so that
 * every device that times frames on such a link uses the same ones.
 *
 * The line coding and the FEC of the physical layer (8b/10b, 64b/66b, RS-FEC)
 * are not part of it: Ethernet runs the line faster to absorb them, so the MAC
 * sees the nominal data rate on copper and fibre alike.
 */
class LinkFraming
{
  public:
    /// The kind of link
    enum Type
    {
        NONE,     ///< the frame alone, nothing around it
        ETHERNET, ///< IEEE 802.3: preamble and SFD, FCS, minimum frame, interframe gap
    };

    /**
     * \brief The framing of a kind of link
     * \param type the kind of link
     */
    explicit LinkFraming(Type type = NONE);

    /// \return the kind of link
    Type GetType() const;

    /**
     * \brief The bytes that a frame occupies on the wire
     * \param frameBytes the size of the ns-3 frame: MAC header and payload, no FCS
     * \return frameBytes, padded up to the minimum frame, plus the preamble and
     *         the FCS
     */
    uint32_t GetWireBytes(uint32_t frameBytes) const;

    /// \return the idle bytes after a frame, before the next one (interframe gap)
    uint32_t GetGapBytes() const;

  private:
    Type m_type;              ///< the kind of link
    uint32_t m_preambleBytes; ///< preamble and start-of-frame delimiter
    uint32_t m_fcsBytes;      ///< frame check sequence
    uint32_t m_minFrameBytes; ///< minimum frame without the FCS (shorter ones are padded)
    uint32_t m_gapBytes;      ///< interframe gap
};

} // namespace ns3

#endif // LINK_FRAMING_H
