// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Test program for p4-egress. Forwards a frame by destination MAC:
// 00:00:00:00:00:01 to port 1, 00:00:00:00:00:02 to port 2; other frames are
// dropped. egress_ports_psa.p4 behaves the same.

#include <core.p4>
#include <v1model.p4>

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

parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t smeta) {
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyIngress(inout headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t smeta) {
    action to_port(bit<9> port) {
        smeta.egress_spec = port;
    }
    action drop() {
        smeta.egress_spec = 511;
    }
    table mac_port {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { to_port; drop; }
        const entries = {
            0x000000000001: to_port(1);
            0x000000000002: to_port(2);
        }
        default_action = drop();
    }
    apply {
        mac_port.apply();
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
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(),
         MyDeparser()) main;
