// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// A policer for p4-psa-meter (PSA). Every ingress port has a two-rate
// three-color meter (RFC 2698) that measures the bytes of the frames: a frame
// over the peak rate is red and dropped; one over the committed rate but within
// the peak rate is yellow and passes, as a green one does. A counter counts the
// frames of each port and color. The control plane sets the rates
// (P4RuntimeApi::SetMeterArrayRates) and reads the counter (ReadCounter).

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

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
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
        transition accept;
    }
}

control IngressImpl(inout headers_t hdr, inout metadata_t meta,
                    in psa_ingress_input_metadata_t istd,
                    inout psa_ingress_output_metadata_t ostd) {
    // One meter per ingress port. The meter and the counter are sized for ports 0
    // to 7: a higher port fails the index check of the meter, so its frames are red
    Meter<bit<8>>(8, PSA_MeterType_t.BYTES) port_meter;
    // Frames per ingress port and color: index 3 * port + 0 (green), 1 (yellow), 2 (red)
    Counter<bit<32>, bit<8>>(24, PSA_CounterType_t.PACKETS_AND_BYTES) colors;

    action forward(PortId_t port) {
        send_to_port(ostd, port);
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            forward;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (!hdr.ipv4.isValid()) {
            ingress_drop(ostd);
            return;
        }
        bit<8> port = (bit<8>) (PortIdUint_t) istd.ingress_port;
        PSA_MeterColor_t color = port_meter.execute(port);
        if (color == PSA_MeterColor_t.GREEN) {
            colors.count(3 * port);
        } else if (color == PSA_MeterColor_t.YELLOW) {
            colors.count(3 * port + 1);
        } else {
            colors.count(3 * port + 2);
            ingress_drop(ostd);
            return;
        }
        // A frame that no entry matches is dropped: PSA drops by default
        ipv4_forward.apply();
    }
}

control IngressDeparserImpl(packet_out pkt, out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta, out empty_t normal_meta,
                            inout headers_t hdr, in metadata_t meta,
                            in psa_ingress_output_metadata_t istd) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
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
