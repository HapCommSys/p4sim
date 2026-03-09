/* Copyright 2024 Marvell Technology, Inc.
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
 * Original author: Rupesh Chiluka <rchiluka@marvell.com>
 * Adapted for ns-3 p4sim by: Mingyu Ma <mingyu.ma@tu-dresden.de>
 *
 * Description:
 *   PNA (Portable NIC Architecture) action primitives for the ns-3 p4sim
 *   P4PnaNic target.
 *
 *   Since p4sim compiles v1model, PSA, and PNA into a single shared library,
 *   only primitives that are UNIQUE to PNA (not already registered by
 *   primitives-v1model.h) are defined here.  The v1model file already
 *   covers: add_header, remove_header, assign, drop, truncate, etc.
 *
 *   PNA-specific additions:
 *     - send_to_port(PortId_t)  : set the packet's egress port.
 *     - drop_packet()           : mark the packet for dropping by routing
 *                                 it to the well-known drop port (511).
 *
 *   Note: the upstream bmv2 pna_nic/primitives.cpp registers send_to_port
 *   inside "namespace bm { namespace pna { ... } }".  Thanks to the
 *   REGISTER_PRIMITIVE macro using the stringified class name (#primitive_name),
 *   the registration key is just "send_to_port" regardless of namespace.
 *   We therefore define our classes at global scope for clarity.
 *   drop_packet is absent from the upstream implementation; this file
 *   provides the missing registration.
 */

#ifndef PRIMITIVES_PNA_H
#define PRIMITIVES_PNA_H

#include <bm/bm_sim/actions.h>
#include <bm/bm_sim/packet.h>

// ---------------------------------------------------------------------------
// send_to_port(PortId_t dest_port)
//
// PNA extern function: sets the egress port of the current packet.
// This is the primary forwarding action in the PNA architecture.
// ---------------------------------------------------------------------------
class send_to_port : public bm::ActionPrimitive<const bm::Data&>
{
    void operator()(const bm::Data& dest_port)
    {
        get_packet().set_egress_port(dest_port.get<uint32_t>());
    }
};

REGISTER_PRIMITIVE(send_to_port);

// ---------------------------------------------------------------------------
// drop_packet()
//
// PNA extern function: marks the packet for dropping.
//
// The upstream bmv2 pna_nic/primitives.cpp does NOT implement this function.
// In p4sim we follow the same convention as v1model/PSA: set the egress port
// to the "drop port" (511 = SSWITCH_DROP_PORT).  main_processing_pipeline()
// in p4-nic-pna.cc detects this port and discards the packet.
// ---------------------------------------------------------------------------
class drop_packet : public bm::ActionPrimitive<>
{
    void operator()()
    {
        get_packet().set_egress_port(511); // SSWITCH_DROP_PORT
    }
};

REGISTER_PRIMITIVE(drop_packet);

// ---------------------------------------------------------------------------
// Linker-anchor (same pattern as primitives-v1model.h / import_primitives())
// Call this from P4PnaNic constructor to prevent the linker from discarding
// this translation unit.
// ---------------------------------------------------------------------------
int
import_pna_primitives()
{
    return 0;
}

#endif // PRIMITIVES_PNA_H
