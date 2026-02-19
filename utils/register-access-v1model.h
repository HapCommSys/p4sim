/* Copyright 2019-present Cisco Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Andy Fingerhut <jafinger@cisco.com>
 * Modified: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#ifndef SIMPLE_SWITCH_REGISTER_ACCESS_H_
#define SIMPLE_SWITCH_REGISTER_ACCESS_H_

#include <bm/bm_sim/packet.h>

#include <cstdint>

/**
 * \brief Sideband metadata transport between ns-3 and the BMv2 packet pipeline.
 *
 * ## Background
 *
 * In P4Sim, packets live in two different worlds:
 *
 *  1. **ns-3 domain** — packets are `ns3::Packet` objects that carry ns-3
 *     metadata such as the EtherType-like protocol number and the destination
 *     `ns3::Address` used by `NetDevice::Send()`.
 *
 *  2. **BMv2 domain** — when a packet enters the P4 switch it is converted to
 *     a `bm::Packet` so the BMv2 behavioral-model library can parse, match,
 *     and apply actions defined by the user's P4 program.
 *
 * The BMv2 `bm::Packet` has no notion of ns-3 metadata.  However, after the
 * P4 pipeline finishes processing the packet, we must convert it back to an
 * `ns3::Packet` and forward it through ns-3's networking stack.  At that point
 * we need the **original ns-3 protocol number and destination address** so
 * that `P4SwitchNetDevice::SendNs3Packet()` can deliver the packet correctly.
 *
 * ## Solution — per-packet registers
 *
 * BMv2 provides a small set of per-packet 64-bit "registers" (indexed 0–4)
 * that travel with every `bm::Packet` and survive the entire pipeline.  The
 * upstream `simple_switch` already uses registers 0–2 for internal bookkeeping
 * (packet length, clone session, resubmit flag, etc.).
 *
 * We pack the ns-3 metadata into the **unused upper bits of register 2**,
 * which is safe because those bit positions are not used by any BMv2 feature.
 *
 * ### Register layout
 *
 * | Register | Bits 63-48         | Bits 47-32       | Bits 31-16          | Bits 15-0                    |
 * |----------|--------------------|------------------|---------------------|------------------------------|
 * | 0        | —                  | —                | —                   | packet_length                |
 * | 1        | resubmit_flag      | lf_field_list    | clone_field_list    | clone_mirror_session_id      |
 * | 2        | (unused)           | **ns_address**   | **ns_protocol**     | recirculate_flag             |
 *
 * ### Lifecycle
 *
 *  1. **Ingress (ns-3 → BMv2):** Before the packet enters the P4 pipeline,
 *     `clear_all()` zeros registers 1–2, then `set_ns_protocol()` and
 *     `set_ns_address()` store the ns-3 metadata.
 *
 *  2. **P4 processing:** The BMv2 pipeline executes normally.  The packed
 *     metadata bits are invisible to the P4 program since they live outside
 *     of PHV fields.
 *
 *  3. **Egress (BMv2 → ns-3):** After the pipeline completes,
 *     `get_ns_protocol()` and `get_ns_address()` retrieve the saved values so
 *     the packet can be forwarded with the correct ns-3 protocol number and
 *     destination address.
 */
class RegisterAccess
{
  public:
    // ── Register 0: packet length ──────────────────────────────────────
    static constexpr int PACKET_LENGTH_REG_IDX = 0;

    // ── Register 1: BMv2 internal flags (from upstream simple_switch) ──
    static constexpr int CLONE_MIRROR_SESSION_ID_REG_IDX = 1;
    static constexpr uint64_t CLONE_MIRROR_SESSION_ID_MASK = 0x000000000000ffff;
    static constexpr uint64_t CLONE_MIRROR_SESSION_ID_SHIFT = 0;
    static constexpr int CLONE_FIELD_LIST_REG_IDX = 1;
    static constexpr uint64_t CLONE_FIELD_LIST_MASK = 0x00000000ffff0000;
    static constexpr uint64_t CLONE_FIELD_LIST_SHIFT = 16;
    static constexpr int LF_FIELD_LIST_REG_IDX = 1;
    static constexpr uint64_t LF_FIELD_LIST_MASK = 0x0000ffff00000000;
    static constexpr uint64_t LF_FIELD_LIST_SHIFT = 32;
    static constexpr int RESUBMIT_FLAG_REG_IDX = 1;
    static constexpr uint64_t RESUBMIT_FLAG_MASK = 0xffff000000000000;
    static constexpr uint64_t RESUBMIT_FLAG_SHIFT = 48;

    // ── Register 2: recirculate flag (BMv2) + ns-3 sideband metadata ───
    //
    // Bits [15:0]  — recirculate_flag (BMv2 internal)
    // Bits [31:16] — ns-3 protocol number (e.g. 0x0800 for IPv4)
    // Bits [47:32] — ns-3 destination address index (lookup into
    //                P4SwitchNetDevice's address table; max 65535 entries)
    // Bits [63:48] — currently unused / reserved

    static constexpr int RECIRCULATE_FLAG_REG_IDX = 2;
    static constexpr uint64_t RECIRCULATE_FLAG_MASK = 0x000000000000ffff;
    static constexpr uint64_t RECIRCULATE_FLAG_SHIFT = 0;

    /// ns-3 protocol number stored in register 2, bits [31:16].
    /// Preserves the EtherType / protocol identifier so that the packet can
    /// be handed back to ns-3 with the correct protocol after P4 processing.
    static constexpr int NS_PROTOCOL_REG_IDX = 2;
    static constexpr uint64_t NS_PROTOCOL_MASK = 0x00000000ffff0000;
    static constexpr uint64_t NS_PROTOCOL_SHIFT = 16;

    /// ns-3 destination address index stored in register 2, bits [47:32].
    /// This is an index into the switch's destination address list, allowing
    /// up to 65535 distinct destination addresses.  The actual ns3::Address is
    /// recovered via the index when the packet exits the P4 pipeline.
    static constexpr int NS_ADDRESS_REG_IDX = 2;
    static constexpr uint64_t NS_ADDRESS_MASK = 0x0000ffff00000000;
    static constexpr uint64_t NS_ADDRESS_SHIFT = 32;

    // ── Mirror session helpers ─────────────────────────────────────────
    static constexpr uint16_t MAX_MIRROR_SESSION_ID = (1u << 15) - 1;
    static constexpr uint16_t MIRROR_SESSION_ID_VALID_MASK = (1u << 15);
    static constexpr uint16_t MIRROR_SESSION_ID_MASK = 0x7FFFu;

    /**
     * \brief Reset registers 1 and 2 to zero.
     *
     * Called at ingress before storing new metadata.  Register 0 (packet
     * length) is intentionally left untouched.
     */
    static void clear_all(bm::Packet* pkt)
    {
        // except do not clear packet length
        pkt->set_register(1, 0);
        pkt->set_register(2, 0);
    }

    // ── BMv2 clone / mirror helpers ────────────────────────────────────

    static uint16_t get_clone_mirror_session_id(bm::Packet* pkt)
    {
        uint64_t rv = pkt->get_register(CLONE_MIRROR_SESSION_ID_REG_IDX);
        return static_cast<uint16_t>((rv & CLONE_MIRROR_SESSION_ID_MASK) >>
                                     CLONE_MIRROR_SESSION_ID_SHIFT);
    }

    static void set_clone_mirror_session_id(bm::Packet* pkt, uint16_t mirror_session_id)
    {
        uint64_t rv = pkt->get_register(CLONE_MIRROR_SESSION_ID_REG_IDX);
        rv = ((rv & ~CLONE_MIRROR_SESSION_ID_MASK) |
              ((static_cast<uint64_t>(mirror_session_id)) << CLONE_MIRROR_SESSION_ID_SHIFT));
        pkt->set_register(CLONE_MIRROR_SESSION_ID_REG_IDX, rv);
    }

    static uint16_t get_clone_field_list(bm::Packet* pkt)
    {
        uint64_t rv = pkt->get_register(CLONE_FIELD_LIST_REG_IDX);
        return static_cast<uint16_t>((rv & CLONE_FIELD_LIST_MASK) >> CLONE_FIELD_LIST_SHIFT);
    }

    static void set_clone_field_list(bm::Packet* pkt, uint16_t field_list_id)
    {
        uint64_t rv = pkt->get_register(CLONE_FIELD_LIST_REG_IDX);
        rv = ((rv & ~CLONE_FIELD_LIST_MASK) |
              ((static_cast<uint64_t>(field_list_id)) << CLONE_FIELD_LIST_SHIFT));
        pkt->set_register(CLONE_FIELD_LIST_REG_IDX, rv);
    }

    static uint16_t get_lf_field_list(bm::Packet* pkt)
    {
        uint64_t rv = pkt->get_register(LF_FIELD_LIST_REG_IDX);
        return static_cast<uint16_t>((rv & LF_FIELD_LIST_MASK) >> LF_FIELD_LIST_SHIFT);
    }

    static void set_lf_field_list(bm::Packet* pkt, uint16_t field_list_id)
    {
        uint64_t rv = pkt->get_register(LF_FIELD_LIST_REG_IDX);
        rv = ((rv & ~LF_FIELD_LIST_MASK) |
              ((static_cast<uint64_t>(field_list_id)) << LF_FIELD_LIST_SHIFT));
        pkt->set_register(LF_FIELD_LIST_REG_IDX, rv);
    }

    static uint16_t get_resubmit_flag(bm::Packet* pkt)
    {
        uint64_t rv = pkt->get_register(RESUBMIT_FLAG_REG_IDX);
        return static_cast<uint16_t>((rv & RESUBMIT_FLAG_MASK) >> RESUBMIT_FLAG_SHIFT);
    }

    static void set_resubmit_flag(bm::Packet* pkt, uint16_t field_list_id)
    {
        uint64_t rv = pkt->get_register(RESUBMIT_FLAG_REG_IDX);
        rv = ((rv & ~RESUBMIT_FLAG_MASK) |
              ((static_cast<uint64_t>(field_list_id)) << RESUBMIT_FLAG_SHIFT));
        pkt->set_register(RESUBMIT_FLAG_REG_IDX, rv);
    }

    // ── BMv2 recirculate flag ────────────────────────────────────────

    static uint16_t get_recirculate_flag(bm::Packet* pkt)
    {
        uint64_t rv = pkt->get_register(RECIRCULATE_FLAG_REG_IDX);
        return static_cast<uint16_t>((rv & RECIRCULATE_FLAG_MASK) >> RECIRCULATE_FLAG_SHIFT);
    }

    static void set_recirculate_flag(bm::Packet* pkt, uint16_t field_list_id)
    {
        uint64_t rv = pkt->get_register(RECIRCULATE_FLAG_REG_IDX);
        rv = ((rv & ~RECIRCULATE_FLAG_MASK) |
              ((static_cast<uint64_t>(field_list_id)) << RECIRCULATE_FLAG_SHIFT));
        pkt->set_register(RECIRCULATE_FLAG_REG_IDX, rv);
    }

    // ── ns-3 sideband: protocol number ───────────────────────────────
    //
    // When an ns3::Packet enters the P4 switch, ns-3 passes a protocol
    // number (e.g. 0x0800 for IPv4, 0x0806 for ARP).  BMv2 knows nothing
    // about this value, so we stash it in a per-packet register before the
    // pipeline runs and retrieve it afterwards to hand the packet back to
    // ns-3 with the correct protocol.

    /// Retrieve the saved ns-3 protocol number from the BMv2 packet.
    static uint16_t get_ns_protocol(bm::Packet* pkt)
    {
        uint64_t rv = pkt->get_register(NS_PROTOCOL_REG_IDX);
        return static_cast<uint16_t>((rv & NS_PROTOCOL_MASK) >> NS_PROTOCOL_SHIFT);
    }

    /// Save the ns-3 protocol number into the BMv2 packet register.
    static void set_ns_protocol(bm::Packet* pkt, uint16_t protocol)
    {
        uint64_t rv = pkt->get_register(NS_PROTOCOL_REG_IDX);
        rv = ((rv & ~NS_PROTOCOL_MASK) |
              ((static_cast<uint64_t>(protocol)) << NS_PROTOCOL_SHIFT));
        pkt->set_register(NS_PROTOCOL_REG_IDX, rv);
    }

    // ── ns-3 sideband: destination address index ────────────────────
    //
    // ns-3 destination addresses (ns3::Address) cannot be stored directly
    // in a 16-bit register field.  Instead, the switch maintains a lookup
    // table (m_destinationList) that maps a uint16_t index to the actual
    // ns3::Address.  We store the index here and resolve it back to an
    // address after the P4 pipeline finishes.  This supports up to 65535
    // distinct destination addresses per switch.

    /// Retrieve the saved ns-3 destination address index.
    static uint16_t get_ns_address(bm::Packet* pkt)
    {
        uint64_t rv = pkt->get_register(NS_ADDRESS_REG_IDX);
        return static_cast<uint16_t>((rv & NS_ADDRESS_MASK) >> NS_ADDRESS_SHIFT);
    }

    /// Save the ns-3 destination address index into the BMv2 packet register.
    static void set_ns_address(bm::Packet* pkt, uint16_t addr_index)
    {
        uint64_t rv = pkt->get_register(NS_ADDRESS_REG_IDX);
        rv = ((rv & ~NS_ADDRESS_MASK) |
              ((static_cast<uint64_t>(addr_index)) << NS_ADDRESS_SHIFT));
        pkt->set_register(NS_ADDRESS_REG_IDX, rv);
    }
};

#endif // SIMPLE_SWITCH_REGISTER_ACCESS_H_