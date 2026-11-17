// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Packet test program. forward_v1model.p4, forward_psa.p4 and forward_pna.p4 behave
// the same, so the .stf files in this directory apply to all three:
// - IPv4 is forwarded by destination address. The destination MAC becomes the next
//   hop's, the source MAC the old destination MAC. Without a route it is dropped.
// - Any other frame is forwarded unchanged by its ingress port: 0 -> 1 -> 2 -> 0.

#include <core.p4>
#include <v1model.p4>

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

parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t smeta) {
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

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyIngress(inout headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t smeta) {
    action drop() {
        mark_to_drop(smeta);
    }
    action route(bit<48> nextHop, bit<9> port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = nextHop;
        smeta.egress_spec = port;
    }
    action to_port(bit<9> port) {
        smeta.egress_spec = port;
    }
    table ipv4_route {
        key = { hdr.ipv4.dstAddr: exact; }
        actions = { route; drop; }
        const entries = {
            0x0a000001: route(0x000000000010, 0); // 10.0.0.1
            0x0a000101: route(0x000000000011, 1); // 10.0.1.1
            0x0a000201: route(0x000000000012, 2); // 10.0.2.1
            0x0a000901: route(0x000000000019, 7); // 10.0.9.1: the switch has no port 7
        }
        default_action = drop();
    }
    table port_map {
        key = { smeta.ingress_port: exact; }
        actions = { to_port; drop; }
        const entries = {
            0: to_port(1);
            1: to_port(2);
            2: to_port(0);
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

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t smeta) {
    apply { }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(),
         MyDeparser()) main;
