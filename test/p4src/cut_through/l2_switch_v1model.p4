// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Test program for the cut-through reference profile (Model C of
// doc/latency-model.md): the forwarding decision of a learning Ethernet switch.
// - A destination in the address table: the frame goes to its port only; if
//   that is the ingress port, the frame is not forwarded.
// - An unknown destination or a group address: the frame is flooded to every
//   port except the ingress port (multicast group ingress port + 1, which the
//   flow-table file creates).
// - Every frame teaches the switch its source address and port (a digest),
//   unless the source is a group address; the switch installs the entry into
//   dmac with the limits of the target profile (P4LearningTable).

#include <core.p4>
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

struct headers {
    ethernet_t ethernet;
}

struct metadata {
}

struct learn_t {
    bit<48> srcAddr;
    bit<9>  port;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action flood() {
        standard_metadata.mcast_grp = (bit<16>) standard_metadata.ingress_port + 1;
    }

    table dmac {
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            forward;
            flood;
        }
        default_action = flood();
        size = 4;
    }

    apply {
        if (hdr.ethernet.srcAddr[40:40] == 0) {
            digest<learn_t>(1, {hdr.ethernet.srcAddr, standard_metadata.ingress_port});
        }
        if (hdr.ethernet.dstAddr[40:40] == 1) {
            flood();
        } else {
            dmac.apply();
            if (standard_metadata.mcast_grp == 0 &&
                standard_metadata.egress_spec == standard_metadata.ingress_port) {
                mark_to_drop(standard_metadata);
            }
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
    }
}

V1Switch(MyParser(),
         MyVerifyChecksum(),
         MyIngress(),
         MyEgress(),
         MyComputeChecksum(),
         MyDeparser()) main;
