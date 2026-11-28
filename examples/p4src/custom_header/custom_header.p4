// SPDX-FileCopyrightText: 2018 Nate Foster
// SPDX-License-Identifier: Apache-2.0
// Based on exercises/basic_tunnel/solution/basic_tunnel.p4 of https://github.com/p4lang/tutorials.
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// check https://github.com/p4lang/p4c/issues/1828 for the reason of this
// we define "mark_to_drop2" for this
#define BMV2_V1MODEL_SPECIAL_DROP_PORT  511

const bit<16> TYPE_ARP = 0x806;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MYTUNNEL = 0x12;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header custom_header_t {
    bit<16> proto_id;
    bit<16> dst_id;
}

header arp_t {
    bit<16> hw_type;
    bit<16> protocol_type;
    bit<8>  hw_size;
    bit<8>  protocol_size;
    bit<16> opcode;
    macAddr_t srcMac;
    ip4Addr_t srcIp;
    macAddr_t dstMac;
    ip4Addr_t dstIp;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    custom_header_t   myheader;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP        :   parse_arp;
            TYPE_MYTUNNEL   :   parse_myHeader;
            TYPE_IPV4       :   parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
    
    state parse_myHeader {
        packet.extract(hdr.myheader);
        transition select(hdr.myheader.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action mark_to_drop2(inout standard_metadata_t stdmata) {
        stdmata.egress_spec = BMV2_V1MODEL_SPECIAL_DROP_PORT;
        stdmata.mcast_grp = 0;
    }
    
    action drop() {
        mark_to_drop2(standard_metadata);
    }

    // ========================

    // action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
    //     standard_metadata.egress_spec = port;
    //     standard_metadata.egress_port = port;
    //     hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    //     hdr.ethernet.dstAddr = dstAddr;
    //     hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    // }

    // table ipv4_nhop {
    //     key = {
    //         hdr.ipv4.dstAddr: exact;
    //     }
    //     actions = {
    //         ipv4_forward;
    //         drop;
    //         NoAction;
    //     }
    //     size = 1024;
    //     default_action = drop();
    // }

    // action set_arp_nhop(egressSpec_t port) {
    //     standard_metadata.egress_spec = port;
    //     standard_metadata.egress_port = port;
    // }
    
    // table arp_simple {
    //     actions = {
    //         set_arp_nhop;
    //         drop;
    //     }
    //     key = {
    //         hdr.arp.dstIp: exact;
    //     }
    //     size = 1024;
    // }

    action myheader_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        standard_metadata.egress_port = port;
    }

    table my_header_exact {
        key = {
            hdr.myheader.dst_id: exact;
        }
        actions = {
            myheader_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        // if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0 ) {
        //     ipv4_nhop.apply();
        // } 

        // if (hdr.arp.isValid()) {
        //     arp_simple.apply();
        // }

        if (hdr.myheader.isValid()) {
            // process tunneled packets
            my_header_exact.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        // packet.emit(hdr.myTunnel);
        packet.emit(hdr.myheader);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;