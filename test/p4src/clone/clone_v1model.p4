// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Packet test program for cloning (v1model). Every frame goes to port 1. The
// .stf file adds mirroring sessions 5 and 0, whose clones leave on port 2;
// session 6 does not exist. The low 4 bits of the EtherType select the operation:
//   1  clone(I2E, 5)                           clone at the end of the ingress
//   2  clone(E2E, 5)                           clone at the end of the egress
//   3  clone(I2E, 6)                           no clone, as the session does not exist
//   4  clone_preserving_field_list(I2E, 5, 1)  clone that keeps meta.tag
//   5  clone(I2E, 0)                           clone with session 0
// The ingress sets meta.tag to 0xab. The egress writes the instance type into
// bits 15:8 of the destination MAC (1 for an ingress clone, 2 for an egress
// clone) and meta.tag into the low byte of the source MAC: a clone has 0 there
// unless its field list keeps meta.tag (@field_list(1)).

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
    @field_list(1)
    bit<8> tag;
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
        smeta.egress_spec = 1;
        meta.tag = 0xab;
        if (hdr.ethernet.etherType[3:0] == 1) {
            clone(CloneType.I2E, 5);
        } else if (hdr.ethernet.etherType[3:0] == 3) {
            clone(CloneType.I2E, 6);
        } else if (hdr.ethernet.etherType[3:0] == 4) {
            clone_preserving_field_list(CloneType.I2E, 5, 1);
        } else if (hdr.ethernet.etherType[3:0] == 5) {
            clone(CloneType.I2E, 0);
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t smeta) {
    apply {
        hdr.ethernet.dstAddr[15:8] = (bit<8>) smeta.instance_type;
        hdr.ethernet.srcAddr[7:0] = meta.tag;
        if (smeta.instance_type == 0 && hdr.ethernet.etherType[3:0] == 2) {
            clone(CloneType.E2E, 5);
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
