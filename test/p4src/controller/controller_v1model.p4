// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Control-plane test program. P4Controller adds, modifies and deletes the
// entries of mac_port, and sets the rates of the meters of port_meter;
// controller_psa.p4 and controller_pna.p4 have the same table. A frame leaves on
// the port that mac_port gives for its destination address, or is dropped. The
// meter of its ingress port colours it, and red frames are dropped.

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
    bit<2> color;
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
    meter(4, MeterType.packets) port_meter;

    action drop() {
        mark_to_drop(std);
    }
    action to_port(bit<9> port) {
        std.egress_spec = port;
    }
    table mac_port {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { to_port; drop; }
        default_action = drop();
        size = 16;
    }
    apply {
        mac_port.apply();
        port_meter.execute_meter((bit<32>) std.ingress_port, meta.color);
        if (meta.color == V1MODEL_METER_COLOR_RED) {
            mark_to_drop(std);
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t std) {
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
