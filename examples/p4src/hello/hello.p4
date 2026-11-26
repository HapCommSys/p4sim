// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden

/*
 * The smallest useful switch: one table forwards a frame by its destination MAC
 * address. Frames to an address that is not in the table are dropped.
 *
 * Compile:  p4c-bm2-ss --p4v 16 -o hello.json hello.p4
 */

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

struct metadata_t { }

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
    action drop() {
        mark_to_drop(smeta);
    }
    action forward(bit<9> port) {
        smeta.egress_spec = port;
    }
    table dmac {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { forward; drop; }
        default_action = drop();
    }
    apply {
        dmac.apply();
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
