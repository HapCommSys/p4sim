// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// ECMP for p4-psa-ecmp (PSA). A table entry either forwards to one port
// (forward) or spreads the flows over two ports (ecmp): the CRC-16 of the
// 5-tuple (Hash extern) picks port first_port or first_port + 1, so all
// packets of a flow take the same path. A counter counts the packets of each
// flow on each path, so that the control plane can check (ReadCounter): its
// index is 2 * (UDP source port mod 64) + path.

#include <core.p4>
#include <bmv2/psa.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
}

struct empty_t {
}

struct metadata_t {
}

parser IngressParserImpl(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta, in empty_t recirculate_meta) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            default: accept;
        }
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

control IngressImpl(inout headers_t hdr, inout metadata_t meta,
                    in psa_ingress_input_metadata_t istd,
                    inout psa_ingress_output_metadata_t ostd) {
    Hash<bit<16>>(PSA_HashAlgorithm_t.CRC16) flow_hash;
    Counter<bit<32>, bit<8>>(128, PSA_CounterType_t.PACKETS) flow_paths;

    action forward(PortId_t port) {
        send_to_port(ostd, port);
    }

    action ecmp(PortIdUint_t first_port) {
        bit<16> h = flow_hash.get_hash({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol,
                                        hdr.udp.srcPort, hdr.udp.dstPort});
        bit<1> path = h[0:0];
        send_to_port(ostd, (PortId_t) (first_port + (PortIdUint_t) path));
        flow_paths.count(((bit<8>) hdr.udp.srcPort & 0x3f) * 2 + (bit<8>) path);
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            forward;
            ecmp;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        // Only UDP is spread; a frame that no entry matches is dropped
        if (hdr.udp.isValid()) {
            ipv4_forward.apply();
        }
    }
}

control IngressDeparserImpl(packet_out pkt, out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta, out empty_t normal_meta,
                            inout headers_t hdr, in metadata_t meta,
                            in psa_ingress_output_metadata_t istd) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
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
