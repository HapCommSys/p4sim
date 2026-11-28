// SPDX-FileCopyrightText: 2018 Nate Foster
// SPDX-License-Identifier: Apache-2.0
// Based on exercises/basic/solution/basic.p4 of https://github.com/p4lang/tutorials.
#include <core.p4>
#include <v1model.p4>

// check https://github.com/p4lang/p4c/issues/1828 for the reason of this
// we define "mark_to_drop2" for this
#define BMV2_V1MODEL_SPECIAL_DROP_PORT  511

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;

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

struct routing_metadata_t {
    bit<32> nhop_ipv4;
}

struct metadata {
    routing_metadata_t      routing_metadata;
}

struct headers {
    ethernet_t      ethernet;
    arp_t           arp;
    ipv4_t          ipv4;
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
            TYPE_IPV4 : parse_ipv4;
            TYPE_ARP  : parse_arp;
            default   : accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }


    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            default: accept;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  
        verify_checksum(
            true, 
            { 
                hdr.ipv4.version, 
                hdr.ipv4.ihl, 
                hdr.ipv4.diffserv, 
                hdr.ipv4.totalLen, 
                hdr.ipv4.identification, 
                hdr.ipv4.flags, 
                hdr.ipv4.fragOffset, 
                hdr.ipv4.ttl, 
                hdr.ipv4.protocol, 
                hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr 
            }, 
            hdr.ipv4.hdrChecksum, 
            HashAlgorithm.csum16
        );
    }
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

    action ipv4_forward(ip4Addr_t nextHop, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        meta.routing_metadata.nhop_ipv4 = nextHop;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action arp_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    table arp_table {
        key = {
            hdr.arp.dstIp: exact;
        }
        actions = {
            arp_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0) {
            ipv4_lpm.apply();
        }
        else if (hdr.arp.isValid()) {
            // ARP packets are always allowed
            // (ns-3 need arp to work, just let all arp goes first, and test with ipv4 packets.
            // if arp not reach, there will not be any ipv4 packets for transmit.)
            arp_table.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) { 

    action mark_to_drop2(inout standard_metadata_t stdmata) {
        stdmata.egress_spec = BMV2_V1MODEL_SPECIAL_DROP_PORT;
        stdmata.mcast_grp = 0;
    }

    action drop() {
        mark_to_drop2(standard_metadata);
    }

    action set_dmac(macAddr_t dstAddr) {
        hdr.ethernet.dstAddr = dstAddr;
    }

    action set_smac(macAddr_t mac) {
        hdr.ethernet.srcAddr = mac;
    }


    table switching_table {
        key = {
            meta.routing_metadata.nhop_ipv4 : exact;
        }
        actions = {
            set_dmac;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }

    table mac_rewriting_table {

        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
                set_smac;
                drop;
                NoAction;
            }
            default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            switching_table.apply();
            mac_rewriting_table.apply();
        }
    }
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