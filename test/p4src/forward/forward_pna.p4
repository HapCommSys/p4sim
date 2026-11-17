// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Packet test program, PNA version of forward_v1model.p4 (same behaviour).

#include <core.p4>
#include <pna.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

struct metadata_t {
}

parser MainParserImpl(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                      in pna_main_parser_input_metadata_t istd) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
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
    action route(bit<48> nextHop, PortId_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = nextHop;
        send_to_port(port);
    }
    action to_port(PortId_t port) {
        send_to_port(port);
    }
    table ipv4_route {
        key = { hdr.ipv4.dstAddr: exact; }
        actions = { route; drop; }
        const entries = {
            0x0a000001: route(0x000000000010, (PortId_t) 32w0); // 10.0.0.1
            0x0a000101: route(0x000000000011, (PortId_t) 32w1); // 10.0.1.1
            0x0a000201: route(0x000000000012, (PortId_t) 32w2); // 10.0.2.1
            0x0a000901: route(0x000000000019, (PortId_t) 32w7); // 10.0.9.1: no port 7
        }
        default_action = drop();
    }
    table port_map {
        key = { istd.input_port: exact; }
        actions = { to_port; drop; }
        const entries = {
            (PortId_t) 32w0: to_port((PortId_t) 32w1);
            (PortId_t) 32w1: to_port((PortId_t) 32w2);
            (PortId_t) 32w2: to_port((PortId_t) 32w0);
        }
        default_action = drop();
    }
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_route.apply();
        } else {
            port_map.apply();
        }
    }
}

control MainDeparserImpl(packet_out pkt, in headers_t hdr, in metadata_t meta,
                         in pna_main_output_metadata_t ostd) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

PNA_NIC(MainParserImpl(), PreControlImpl(), MainControlImpl(), MainDeparserImpl()) main;
