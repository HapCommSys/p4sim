/*
 * Copyright (c) 2025 TU Dresden
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
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 *
 * Description:
 *   Simple PNA (Portable NIC Architecture) IPv4 forwarding program.
 *   Mirrors the PSA simple_psa.p4 functionality but using PNA APIs.
 *
 *   NOTE: The PNA NIC in this simulator does not support loading flow-table
 *   entries from an external file via the Thrift CLI (m_thriftCommand is
 *   empty for PNA).  Therefore forwarding decisions are encoded directly in
 *   the P4 source using "const entries" so no external flowtable file is
 *   needed at runtime.
 *
 *   Tables and const entries (2-host, 1-switch topology, subnet 10.1.1.0/24):
 *     ipv4_nhop:
 *       0x0a010101 (10.1.1.1) → ipv4_forward(00:00:00:00:00:01, port 0)
 *       0x0a010102 (10.1.1.2) → ipv4_forward(00:00:00:00:00:03, port 1)
 *     arp_simple:
 *       0x0a010101 (10.1.1.1) → set_arp_nhop(port 0)
 *       0x0a010102 (10.1.1.2) → set_arp_nhop(port 1)
 */

#include <core.p4>
#include <pna.p4>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const bit<16> TYPE_ARP  = 0x0806;
const bit<16> TYPE_IPV4 = 0x0800;

// ---------------------------------------------------------------------------
// Header definitions
// ---------------------------------------------------------------------------
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
    bit<16>   hw_type;
    bit<16>   protocol_type;
    bit<8>    hw_size;
    bit<8>    protocol_size;
    bit<16>   opcode;
    macAddr_t srcMac;
    ip4Addr_t srcIp;
    macAddr_t dstMac;
    ip4Addr_t dstIp;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata_t {
    // empty – no user-defined metadata needed
}

struct headers_t {
    ethernet_t ethernet;
    arp_t      arp;
    ipv4_t     ipv4;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------
parser MainParserImpl(
    packet_in pkt,
    out   headers_t  hdr,
    inout metadata_t meta,
    in    pna_main_parser_input_metadata_t istd)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP : parse_arp;
            default  : accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Pre-control (pass-through)
// ---------------------------------------------------------------------------
control PreControlImpl(
    in    headers_t  hdr,
    inout metadata_t meta,
    in    pna_pre_input_metadata_t  istd,
    inout pna_pre_output_metadata_t ostd)
{
    apply { /* no pre-processing */ }
}

// ---------------------------------------------------------------------------
// Main control – IPv4 / ARP forwarding (const entries, no external flow table)
// ---------------------------------------------------------------------------
control MainControlImpl(
    inout headers_t  hdr,
    inout metadata_t meta,
    in    pna_main_input_metadata_t  istd,
    inout pna_main_output_metadata_t ostd)
{
    // --- actions ---

    action drop() {
        drop_packet();
    }

    /**
     * ipv4_forward: set egress port, rewrite MACs, decrement TTL.
     * 'dstMac' and 'port' are supplied by the const table entries below.
     */
    action ipv4_forward(macAddr_t dstMac, PortId_t port) {
        send_to_port(port);
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMac;
        hdr.ipv4.ttl         = hdr.ipv4.ttl - 1;
    }

    /**
     * set_arp_nhop: forward ARP to the correct egress port.
     * 'port' is supplied by the const table entries below.
     */
    action set_arp_nhop(PortId_t port) {
        send_to_port(port);
    }

    // --- tables with compile-time (const) entries ---
    // NOTE: The PNA NIC in this simulator does not support loading flow-table
    // entries via the Thrift CLI (m_thriftCommand is empty for PNA).
    // Const entries are used instead so no external flowtable file is needed.
    //
    // Topology (see topo.txt):  Host0 (10.1.1.1) -- Switch -- Host1 (10.1.1.2)
    //   Switch port 0 faces Host0 (MAC 00:00:00:00:00:01 on the switch side)
    //   Switch port 1 faces Host1 (MAC 00:00:00:00:00:03 on the switch side)

    table ipv4_nhop {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        default_action = drop();
        const entries = {
            // dst IP 10.1.1.1 → port 0, dst MAC 00:00:00:00:00:01
            0x0a010101: ipv4_forward(0x000000000001, (PortId_t) 0);
            // dst IP 10.1.1.2 → port 1, dst MAC 00:00:00:00:00:03
            0x0a010102: ipv4_forward(0x000000000003, (PortId_t) 1);
        }
    }

    table arp_simple {
        key = {
            hdr.arp.dstIp: exact;
        }
        actions = {
            set_arp_nhop;
            drop;
        }
        default_action = drop();
        const entries = {
            0x0a010101: set_arp_nhop((PortId_t) 0);
            0x0a010102: set_arp_nhop((PortId_t) 1);
        }
    }

    // --- pipeline ---
    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            ipv4_nhop.apply();
        } else if (hdr.arp.isValid()) {
            arp_simple.apply();
        } else {
            drop();
        }
    }
}

// ---------------------------------------------------------------------------
// Deparser
// ---------------------------------------------------------------------------
control MainDeparserImpl(
    packet_out pkt,
    in    headers_t  hdr,
    in    metadata_t meta,
    in    pna_main_output_metadata_t ostd)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.arp);
        pkt.emit(hdr.ipv4);
    }
}

// ---------------------------------------------------------------------------
// Top-level instantiation
// ---------------------------------------------------------------------------
PNA_NIC(
    MainParserImpl(),
    PreControlImpl(),
    MainControlImpl(),
    MainDeparserImpl()
) main;
