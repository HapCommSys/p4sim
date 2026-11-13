// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Packet test program for priority queueing (v1model). Every frame from port 0
// goes to port 1, with the priority taken from the low 3 bits of the EtherType;
// frames from other ports are dropped. The egress writes the queue depths into
// the source MAC, so that the .stf file can check them: the upper 24 bits hold
// enq_qdepth, the lower 24 bits deq_qdepth.

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
    apply {
        if (smeta.ingress_port == 0) {
            smeta.egress_spec = 1;
            smeta.priority = hdr.ethernet.etherType[2:0];
        } else {
            mark_to_drop(smeta);
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t smeta) {
    apply {
        hdr.ethernet.srcAddr = 5w0 ++ smeta.enq_qdepth ++ 5w0 ++ smeta.deq_qdepth;
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
