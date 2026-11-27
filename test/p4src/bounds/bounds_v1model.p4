// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Packet test program for arguments out of bounds: an index outside a
// register, counter or meter array, which BMv2 skips, and truncate() to fewer
// bytes than an Ethernet header, which P4sim drops. Every frame goes to port 1.
// After the Ethernet header, a data header selects the operation:
//   op 1  reg.read(data.old, data.index): out of bounds, data.old keeps the
//         value from the frame
//   op 2  reg.write(data.index, data.value): out of bounds, no element changes
//   op 3  cnt.count(data.index)
//   op 4  mtr.execute_meter(data.index, data.color): the meter has no rates,
//         so it gives green, 0; out of bounds, data.color keeps its value
//   op 5  truncate(10)
// The arrays have 4 elements.

#include <core.p4>
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header data_t {
    bit<8>  op;
    bit<32> index;
    bit<16> value;
    bit<16> old;
    bit<8>  color;
}

struct headers_t {
    ethernet_t ethernet;
    data_t     data;
}

struct metadata_t { }

parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t smeta) {
    state start {
        pkt.extract(hdr.ethernet);
        pkt.extract(hdr.data);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyIngress(inout headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t smeta) {
    register<bit<16>>(4) reg;
    counter(4, CounterType.packets) cnt;
    meter(4, MeterType.packets) mtr;

    apply {
        smeta.egress_spec = 1;
        if (hdr.data.op == 1) {
            reg.read(hdr.data.old, hdr.data.index);
        } else if (hdr.data.op == 2) {
            reg.write(hdr.data.index, hdr.data.value);
        } else if (hdr.data.op == 3) {
            cnt.count(hdr.data.index);
        } else if (hdr.data.op == 4) {
            mtr.execute_meter(hdr.data.index, hdr.data.color);
        } else if (hdr.data.op == 5) {
            truncate(32w10);
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t smeta) {
    apply { }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.data);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(),
         MyDeparser()) main;
