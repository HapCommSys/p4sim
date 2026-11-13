// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Packet test program for v1model primitives with arguments that BMv2 stores
// outside the PHV or checks first. Every frame goes to port 1. The low 4 bits
// of the EtherType select the operation:
//   1  digest(): the frame leaves unchanged
//   2  hash() with max 0, which BMv2 treats as 1: the result is the base, 7,
//      which goes into the low 16 bits of the source MAC
//   3  random() with lo > hi, which BMv2 does not run: meta.r keeps its
//      initial value, 0, which goes into the low byte of the source MAC (p4c
//      drops an assignment to meta.r just before random(), whose result is an
//      out parameter)

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

struct learn_t {
    bit<48> srcAddr;
}

struct metadata_t {
    bit<16> h;
    bit<8> r;
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
        if (hdr.ethernet.etherType[3:0] == 1) {
            digest<learn_t>(1, { hdr.ethernet.srcAddr });
        } else if (hdr.ethernet.etherType[3:0] == 2) {
            hash(meta.h, HashAlgorithm.crc16, 16w7, { hdr.ethernet.srcAddr }, 32w0);
            hdr.ethernet.srcAddr[15:0] = meta.h;
        } else if (hdr.ethernet.etherType[3:0] == 3) {
            random(meta.r, 8w10, 8w5);
            hdr.ethernet.srcAddr[7:0] = meta.r;
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
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(),
         MyDeparser()) main;
