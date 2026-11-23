// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Packet test program for mark_to_drop() in the ingress and in the egress. The
// pipeline core (P4SwitchArch 3) runs it as well as v1model.
// - A frame is forwarded by its ingress port: 0 -> 1 -> 2 -> 0.
// - The ingress drops a frame to 00:00:00:00:00:dd, the egress a frame to
//   00:00:00:00:00:ee.
// - The register egress_frames counts the frames that the egress runs on. A frame
//   that the ingress drops never reaches the egress.

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
    action drop() {
        mark_to_drop(smeta);
    }
    action to_port(bit<9> port) {
        smeta.egress_spec = port;
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
        port_map.apply();
        if (hdr.ethernet.dstAddr == 0x0000000000dd) {
            mark_to_drop(smeta);
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t smeta) {
    register<bit<32>>(1) egress_frames;
    apply {
        bit<32> n;
        egress_frames.read(n, 0);
        egress_frames.write(0, n + 1);
        if (hdr.ethernet.dstAddr == 0x0000000000ee) {
            mark_to_drop(smeta);
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
