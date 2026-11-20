// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Packet test program for cloning (PSA). Every frame goes to port 1. In
// clone_psa.stf, mirroring sessions 5 and 0 send their clones to port 2;
// session 6 does not exist. The low 4 bits of the EtherType select the
// operation:
//   1  clone at the end of the ingress to session 5
//   2  clone at the end of the egress to session 5
//   3  clone at the end of the ingress to session 6: no clone
//   5  clone at the end of the ingress to session 0
//   6  as 1, and the ingress drops the frame: the clone is still made
//   7  as 2, and the egress drops the frame: the clone is still made
// The ingress writes ab into the low byte of the source MAC. An ingress clone
// is a copy of the frame as it entered the ingress parser, so it does not
// have ab there. The egress writes the packet path into bits 15:8 of the
// destination MAC (1: normal unicast, 3: ingress clone, 4: egress clone), and
// for a normal frame ee into bits 23:16: an egress clone is a copy of the
// frame as the egress deparser emitted it, so it has ee too.

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
    apply {
        send_to_port(ostd, (PortId_t) 32w1);
        hdr.ethernet.srcAddr[7:0] = 0xab;
        bit<4> op = hdr.ethernet.etherType[3:0];
        if (op == 1 || op == 6) {
            ostd.clone = true;
            ostd.clone_session_id = (CloneSessionId_t) 16w5;
        } else if (op == 3) {
            ostd.clone = true;
            ostd.clone_session_id = (CloneSessionId_t) 16w6;
        } else if (op == 5) {
            ostd.clone = true;
            ostd.clone_session_id = (CloneSessionId_t) 16w0;
        }
        if (op == 6) {
            ingress_drop(ostd);
        }
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
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control EgressImpl(inout headers_t hdr, inout empty_t meta,
                   in psa_egress_input_metadata_t istd,
                   inout psa_egress_output_metadata_t ostd) {
    apply {
        if (istd.packet_path == PSA_PacketPath_t.NORMAL_UNICAST) {
            hdr.ethernet.dstAddr[15:8] = 1;
            hdr.ethernet.dstAddr[23:16] = 0xee;
            bit<4> op = hdr.ethernet.etherType[3:0];
            if (op == 2 || op == 7) {
                ostd.clone = true;
                ostd.clone_session_id = (CloneSessionId_t) 16w5;
            }
            if (op == 7) {
                egress_drop(ostd);
            }
        } else if (istd.packet_path == PSA_PacketPath_t.CLONE_I2E) {
            hdr.ethernet.dstAddr[15:8] = 3;
        } else if (istd.packet_path == PSA_PacketPath_t.CLONE_E2E) {
            hdr.ethernet.dstAddr[15:8] = 4;
        }
    }
}

control EgressDeparserImpl(packet_out pkt, out empty_t clone_e2e_meta,
                           out empty_t recirculate_meta, inout headers_t hdr,
                           in empty_t meta, in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd) {
    apply {
        pkt.emit(hdr.ethernet);
    }
}

IngressPipeline(IngressParserImpl(), IngressImpl(), IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(), EgressImpl(), EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
