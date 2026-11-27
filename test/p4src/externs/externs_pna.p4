// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Packet test program, PNA version of externs_psa.p4 (same behaviour): the
// externs Meter, Hash, InternetChecksum and Random. Not Counter: p4c 1.2.5.17
// and 1.2.5.19 stop with a compiler bug on PNA_CounterType_t for BMv2. It
// includes bmv2/pna.p4, which has the hash algorithms of BMv2 (pna.p4 has none).

#include <core.p4>
#include <bmv2/pna.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ext_t {
    bit<8>  idx;    // meter index
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

struct metadata_t {
    bit<16> csum;
}

parser MainParserImpl(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                      in pna_main_parser_input_metadata_t istd) {
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

control MainControlImpl(inout headers_t hdr, inout metadata_t meta,
                        in pna_main_input_metadata_t istd,
                        inout pna_main_output_metadata_t ostd) {
    Meter<bit<8>>(4, PNA_MeterType_t.PACKETS) meter;
    Hash<bit<16>>(PNA_HashAlgorithm_t.CRC16) crc16;
    Random<bit<16>>(16w100, 16w200) rand;

    apply {
        if (!hdr.ext.isValid()) {
            drop_packet();
            return;
        }
        PNA_MeterColor_t color = meter.execute(hdr.ext.idx);
        if (color == PNA_MeterColor_t.GREEN) {
            hdr.ext.color = 1;
        } else if (color == PNA_MeterColor_t.YELLOW) {
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
        send_to_port((PortId_t) 32w1);
    }
}

control MainDeparserImpl(packet_out pkt, inout headers_t hdr, in metadata_t meta,
                         in pna_main_output_metadata_t ostd) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ext);
    }
}

PNA_NIC(MainParserImpl(), MainControlImpl(), MainDeparserImpl()) main;
