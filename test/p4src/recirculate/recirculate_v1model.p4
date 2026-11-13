// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Packet test program for recirculation (v1model). Every frame goes to port 1.
// The low 4 bits of the EtherType say how many more times a frame is
// recirculated: the egress decrements them and recirculates the frame until
// they are 0. The egress counts the passes in meta.passes, which recirculation
// preserves (@field_list(0)), and writes the count into the low byte of the
// source MAC. The ingress writes the instance type into bits 15:8 of the
// destination MAC (4 on a recirculated pass; as in BMv2, it is set back to 0
// before the egress). The .stf file can thus check how many passes a frame
// made and that the last one was a recirculated pass.

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
    @field_list(0)
    bit<8> passes;
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
    apply {
        hdr.ethernet.dstAddr[15:8] = (bit<8>) smeta.instance_type;
        smeta.egress_spec = 1;
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t smeta) {
    apply {
        meta.passes = meta.passes + 1;
        hdr.ethernet.srcAddr[7:0] = meta.passes;
        if (hdr.ethernet.etherType[3:0] != 0) {
            hdr.ethernet.etherType[3:0] = hdr.ethernet.etherType[3:0] - 1;
            recirculate_preserving_field_list(0);
        }
    }
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
