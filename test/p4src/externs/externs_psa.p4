// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Packet test program for the PSA externs Counter, Meter, Hash,
// InternetChecksum and Random (externs_pna.p4 is the PNA version).
// A frame with EtherType 0x88b5 carries an ext_t header: the program counts and
// meters the frame at index idx, writes the CRC-16 and the Internet checksum
// of a..d, the meter color and a random number into the header, and sends the
// frame to port 1. Other frames are dropped. The parser computes the checksum:
// p4c's BMv2 back end has InternetChecksum.get() in parsers and deparsers.

#include <core.p4>
#include <bmv2/psa.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ext_t {
    bit<8>  idx;    // counter and meter index
    bit<8>  color;  // out: meter color, 0 red, 1 green, 2 yellow
    bit<16> a;      // in: a..d, the data of the hash and the checksum
    bit<16> b;
    bit<16> c;
    bit<16> d;
    bit<16> crc;    // out: CRC-16 of a..d
    bit<16> csum;   // out: Internet checksum of a..d
    bit<16> rnd;    // out: random number from 100 to 200
    bit<8>  rnd_ok; // out: 1 if rnd is in that range
    bit<8>  pad;
}

struct headers_t {
    ethernet_t ethernet;
    ext_t      ext;
}

struct empty_t {
}

struct metadata_t {
    bit<16> csum;
}

parser IngressParserImpl(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta, in empty_t recirculate_meta) {
    InternetChecksum() checksum;

    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x88b5: parse_ext;
            default: accept;
        }
    }
    state parse_ext {
        pkt.extract(hdr.ext);
        checksum.clear();
        checksum.add({hdr.ext.a, hdr.ext.b, hdr.ext.c, hdr.ext.d});
        meta.csum = checksum.get();
        transition accept;
    }
}

control IngressImpl(inout headers_t hdr, inout metadata_t meta,
                    in psa_ingress_input_metadata_t istd,
                    inout psa_ingress_output_metadata_t ostd) {
    Counter<bit<32>, bit<8>>(4, PSA_CounterType_t.PACKETS) frames;
    Meter<bit<8>>(4, PSA_MeterType_t.PACKETS) meter;
    Hash<bit<16>>(PSA_HashAlgorithm_t.CRC16) crc16;
    Random<bit<16>>(16w100, 16w200) rand;

    apply {
        if (!hdr.ext.isValid()) {
            ingress_drop(ostd);
            return;
        }
        frames.count(hdr.ext.idx);
        PSA_MeterColor_t color = meter.execute(hdr.ext.idx);
        if (color == PSA_MeterColor_t.GREEN) {
            hdr.ext.color = 1;
        } else if (color == PSA_MeterColor_t.YELLOW) {
            hdr.ext.color = 2;
        } else {
            hdr.ext.color = 0;
        }
        hdr.ext.crc = crc16.get_hash({hdr.ext.a, hdr.ext.b, hdr.ext.c, hdr.ext.d});
        hdr.ext.csum = meta.csum;
        hdr.ext.rnd = rand.read();
        if (hdr.ext.rnd >= 100 && hdr.ext.rnd <= 200) {
            hdr.ext.rnd_ok = 1;
        } else {
            hdr.ext.rnd_ok = 0;
        }
        send_to_port(ostd, (PortId_t) 32w1);
    }
}

control IngressDeparserImpl(packet_out pkt, out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta, out empty_t normal_meta,
                            inout headers_t hdr, in metadata_t meta,
                            in psa_ingress_output_metadata_t istd) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ext);
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
