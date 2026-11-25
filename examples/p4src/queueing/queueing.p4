// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

// Queueing (examples p4-priority-queues and p4-latency).
// - ipv4_route forwards a packet by its IPv4 destination address.
// - udp_priority maps the UDP destination port to one of the 8 priority queues
//   of the egress port. The switch serves them in strict priority, 7 first, as
//   BMv2's simple_switch does; without an entry a packet goes to queue 0.
// - The egress keeps, per queue, the number of packets, their total and their
//   largest time in the queue (deq_timedelta; P4sim's timestamps are in
//   nanoseconds, BMv2's in microseconds) and the largest queue depth that a
//   packet found (enq_qdepth), in registers that the examples read at the end.

#include <core.p4>
#include <v1model.p4>

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

struct metadata_t {
}

parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t std) {
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

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyIngress(inout headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t std) {
    action drop() {
        mark_to_drop(std);
    }
    action forward(bit<9> port) {
        std.egress_spec = port;
    }
    table ipv4_route {
        key = { hdr.ipv4.dstAddr: exact; }
        actions = { forward; drop; }
        default_action = drop();
        size = 64;
    }

    action set_priority(bit<3> priority) {
        std.priority = priority;
    }
    table udp_priority {
        key = { hdr.udp.dstPort: exact; }
        actions = { set_priority; NoAction; }
        default_action = NoAction();
        size = 64;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_route.apply();
            if (hdr.udp.isValid()) {
                udp_priority.apply();
            }
        } else {
            drop();
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t std) {
    register<bit<32>>(8) packets;        // packets that left each queue
    register<bit<64>>(8) queue_time;     // their total time in the queue (ns)
    register<bit<32>>(8) max_queue_time; // the largest one (ns)
    register<bit<32>>(8) max_qdepth;     // the largest depth a packet found

    apply {
        bit<32> q = (bit<32>) std.priority; // the priority is the queue

        bit<32> n;
        packets.read(n, q);
        packets.write(q, n + 1);
        bit<64> total;
        queue_time.read(total, q);
        queue_time.write(q, total + (bit<64>) std.deq_timedelta);
        bit<32> longest;
        max_queue_time.read(longest, q);
        if (std.deq_timedelta > longest) {
            max_queue_time.write(q, std.deq_timedelta);
        }
        bit<32> deepest;
        max_qdepth.read(deepest, q);
        if ((bit<32>) std.enq_qdepth > deepest) {
            max_qdepth.write(q, (bit<32>) std.enq_qdepth);
        }
    }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(),
         MyDeparser()) main;
