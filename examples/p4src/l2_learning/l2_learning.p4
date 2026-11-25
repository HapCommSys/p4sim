// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// L2 learning with a controller (example p4-l2-learning).
// - smac: a frame from an unknown source address sends a digest with that
//   address and the ingress port to the controller, which then adds the
//   address to smac and to dmac.
// - dmac: a frame to a known address goes to its port; any other frame
//   (broadcast, or an unknown address) is flooded: multicast group 1 has every
//   port, and the copy for the ingress port is dropped in the egress. The
//   counter "flooded" counts the flooded frames.

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

// The digest data: the controller gets these fields in this order
struct learn_t {
    bit<48> srcAddr;
    bit<9>  ingressPort;
}

struct metadata_t {
}

parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t std) {
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyIngress(inout headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t std) {
    counter(1, CounterType.packets) flooded;

    action learn() {
        digest<learn_t>(1, { hdr.ethernet.srcAddr, std.ingress_port });
    }
    action known() { }
    table smac {
        key = { hdr.ethernet.srcAddr: exact; }
        actions = { learn; known; }
        default_action = learn();
        size = 256;
    }

    action forward(bit<9> port) {
        std.egress_spec = port;
    }
    action flood() {
        std.mcast_grp = 1;
        flooded.count(0);
    }
    table dmac {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { forward; flood; }
        default_action = flood();
        size = 256;
    }

    apply {
        smac.apply();
        dmac.apply();
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t std) {
    apply {
        // A flooded frame does not go back to where it came from
        if (std.egress_port == std.ingress_port) {
            mark_to_drop(std);
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
