// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Test program for p4-pna. Forwards a frame by destination MAC:
// 00:00:00:00:00:01 to port 1, 00:00:00:00:00:02 to port 2. For other frames
// the main control calls neither send_to_port() nor drop_packet(), and PNA
// drops a packet unless send_to_port() was called.

#include <core.p4>
#include <pna.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

struct headers_t {
    ethernet_t ethernet;
}

struct metadata_t {
}

parser MainParserImpl(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                      in pna_main_parser_input_metadata_t istd) {
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control PreControlImpl(in headers_t hdr, inout metadata_t meta,
                       in pna_pre_input_metadata_t istd,
                       inout pna_pre_output_metadata_t ostd) {
    apply { }
}

control MainControlImpl(inout headers_t hdr, inout metadata_t meta,
                        in pna_main_input_metadata_t istd,
                        inout pna_main_output_metadata_t ostd) {
    action to_port(PortId_t port) {
        send_to_port(port);
    }
    table mac_port {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { to_port; NoAction; }
        const entries = {
            0x000000000001: to_port((PortId_t) 1);
            0x000000000002: to_port((PortId_t) 2);
        }
        default_action = NoAction();
    }
    apply {
        mac_port.apply();
    }
}

control MainDeparserImpl(packet_out pkt, in headers_t hdr, in metadata_t meta,
                         in pna_main_output_metadata_t ostd) {
    apply {
        pkt.emit(hdr.ethernet);
    }
}

PNA_NIC(MainParserImpl(), PreControlImpl(), MainControlImpl(), MainDeparserImpl()) main;
