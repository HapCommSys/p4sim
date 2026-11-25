// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Control-plane test program, PNA version of controller_v1model.p4: the same
// table mac_port, without the meters.

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
    action drop() {
        drop_packet();
    }
    action to_port(PortId_t port) {
        send_to_port(port);
    }
    table mac_port {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { to_port; drop; }
        default_action = drop();
        size = 16;
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
