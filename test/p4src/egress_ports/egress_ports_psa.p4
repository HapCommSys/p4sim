// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Test program for p4-egress, PSA version of egress_ports_v1model.p4 (same
// behaviour).

#include <core.p4>
#include <bmv2/psa.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

struct headers_t {
    ethernet_t ethernet;
}

struct empty_t {
}

parser IngressParserImpl(packet_in pkt, out headers_t hdr, inout empty_t meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta, in empty_t recirculate_meta) {
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control IngressImpl(inout headers_t hdr, inout empty_t meta,
                    in psa_ingress_input_metadata_t istd,
                    inout psa_ingress_output_metadata_t ostd) {
    action to_port(PortId_t port) {
        send_to_port(ostd, port);
    }
    action drop() {
        ingress_drop(ostd);
    }
    table mac_port {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { to_port; drop; }
        const entries = {
            0x000000000001: to_port((PortId_t) 32w1);
            0x000000000002: to_port((PortId_t) 32w2);
        }
        default_action = drop();
    }
    apply {
        mac_port.apply();
    }
}

control IngressDeparserImpl(packet_out pkt, out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta, out empty_t normal_meta,
                            inout headers_t hdr, in empty_t meta,
                            in psa_ingress_output_metadata_t istd) {
    apply {
        pkt.emit(hdr.ethernet);
    }
}

parser EgressParserImpl(packet_in pkt, out headers_t hdr, inout empty_t meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_t normal_meta, in empty_t clone_i2e_meta,
                        in empty_t clone_e2e_meta) {
    state start {
        transition accept;
    }
}

control EgressImpl(inout headers_t hdr, inout empty_t meta,
                   in psa_egress_input_metadata_t istd,
                   inout psa_egress_output_metadata_t ostd) {
    apply { }
}

control EgressDeparserImpl(packet_out pkt, out empty_t clone_e2e_meta,
                           out empty_t recirculate_meta, inout headers_t hdr,
                           in empty_t meta, in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd) {
    apply { }
}

IngressPipeline(IngressParserImpl(), IngressImpl(), IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(), EgressImpl(), EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
