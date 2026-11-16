// Copyright 2017 Andy Fingerhut
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Program of the p4-controller-action-profile example.
//
// Tables t0, t1 (action profile) and t2 (action selector) come from the p4c
// action-profile test program; the example's controller adds members to the action
// profile of t1 at runtime. The tables only match TCP ports and have no entries by
// default, so they leave the example's UDP traffic unchanged. The IPv4 and ARP
// forwarding (tables ipv4_nhop and arp_simple, filled from flowtable_<i>.txt) is the
// same as in p4_basic.

#include <core.p4>
#include <v1model.p4>

// check https://github.com/p4lang/p4c/issues/1828 for the reason of this
// we define "mark_to_drop2" for this
#define BMV2_V1MODEL_SPECIAL_DROP_PORT  511

const bit<16> TYPE_ARP = 0x806;
const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9>   egressSpec_t;
typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16>         hw_type;
    bit<16>         protocol_type;
    bit<8>          hw_size;
    bit<8>          protocol_size;
    bit<16>         opcode;
    EthernetAddress srcMac;
    IPv4Address     srcIp;
    EthernetAddress dstMac;
    IPv4Address     dstIp;
}

header ipv4_t {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      totalLen;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    IPv4Address  srcAddr;
    IPv4Address  dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers {
    ethernet_t    ethernet;
    arp_t         arp;
    ipv4_t        ipv4;
    tcp_t         tcp;
}

struct mystruct1_t {
    bit<4>  a;
    bit<4>  b;
}

struct metadata {
    mystruct1_t mystruct1;
    bit<16> hash1;
}

parser parserI(packet_in pkt,
               out headers hdr,
               inout metadata meta,
               inout standard_metadata_t stdmeta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select (hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

control cIngress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t stdmeta)
{
    action foo1(IPv4Address dstAddr) {
        hdr.ipv4.dstAddr = dstAddr;
    }
    action foo2(IPv4Address srcAddr) {
        hdr.ipv4.srcAddr = srcAddr;
    }
    // Only defined here so that there is an action name that isn't an
    // allowed action for table t1, so I can test whether
    // simple_switch_CLI's act_prof_create_member command checks
    // whether the action name is legal according to the P4 program.
    action foo3(bit<8> ttl) {
        hdr.ipv4.ttl = ttl;
    }
    table t0 {
        key = {
            hdr.tcp.dstPort : exact;
        }
        actions = {
            foo1;
            foo2;
        }
        size = 8;
    }
    table t1 {
        key = {
            hdr.tcp.dstPort : exact;
        }
        actions = {
            foo1;
            foo2;
        }
        size = 8;
        implementation = action_profile(4);
    }
    table t2 {
        actions = {
            foo1;
            foo2;
        }
        key = {
            hdr.tcp.srcPort : exact;
            meta.hash1      : selector;
        }
        size = 16;
        @mode("fair") implementation =
            action_selector(HashAlgorithm.identity, 16, 4);
    }

    // IPv4 and ARP forwarding, as in p4_basic
    action mark_to_drop2(inout standard_metadata_t stdmata) {
        stdmata.egress_spec = BMV2_V1MODEL_SPECIAL_DROP_PORT;
        stdmata.mcast_grp = 0;
    }
    action drop() {
        mark_to_drop2(stdmeta);
    }
    action ipv4_forward(EthernetAddress dstAddr, egressSpec_t port) {
        stdmeta.egress_spec = port;
        stdmeta.egress_port = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action set_arp_nhop(egressSpec_t port) {
        stdmeta.egress_spec = port;
        stdmeta.egress_port = port;
    }
    table ipv4_nhop {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table arp_simple {
        actions = {
            set_arp_nhop;
            drop;
        }
        key = {
            hdr.arp.dstIp: exact;
        }
        size = 1024;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            t0.apply();
            t1.apply();

            // The following assignment isn't really a good hash function
            // for calculating meta.hash1.  I wrote it this way simply to
            // make it easy to control and predict what its value will be
            // when sending in test packets.
            meta.hash1 = hdr.ipv4.dstAddr[15:0];
            t2.apply();

            if (hdr.ipv4.ttl > 8w0) {
                ipv4_nhop.apply();
            } else {
                drop();
            }
        } else if (hdr.arp.isValid()) {
            arp_simple.apply();
        } else {
            drop();
        }
    }
}

control cEgress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t stdmeta)
{
    apply { }
}

control vc(inout headers hdr,
           inout metadata meta)
{
    apply { }
}

control uc(inout headers hdr,
           inout metadata meta)
{
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control DeparserI(packet_out packet,
                  in headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch<headers, metadata>(parserI(),
                            vc(),
                            cIngress(),
                            cEgress(),
                            uc(),
                            DeparserI()) main;
