/*
Copyright 2019 Cisco Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Taken from the P4 Language Consortium's P4_16 language specification
document, which is licensed under the Apache License, Version 2.0.
Org:https://github.com/p4lang/p4-spec/blob/main/p4-16/psa/examples/psa-example-hello-world.p4
*/

#include <core.p4>
/* In a normal PSA program the next line would be:

#include <psa.p4>

 * These examples use psa-for-bmv2.p4 instead so that it is convenient
 * to test compiling these PSA example programs with local changes to
 * the psa-for-bmv2.p4 file. */
#include "psa-for-bmv2.p4"


typedef bit<48>  EthernetAddress;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header arp_t {
    bit<16> hw_type;
    bit<16> protocol_type;
    bit<8>  hw_size;
    bit<8>  protocol_size;
    bit<16> opcode;
    bit<48> srcMac;
    bit<32> srcIp;
    bit<48> dstMac;
    bit<32> dstIp;
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

struct empty_metadata_t {
}

struct fwd_metadata_t {
}

struct metadata_t {
    fwd_metadata_t fwd_metadata;
}

struct headers_t {
    ethernet_t       ethernet;
    arp_t            arp;
    ipv4_t           ipv4;
}

parser IngressParserImpl(packet_in buffer,
                         out headers_t parsed_hdr,
                         inout metadata_t user_meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_metadata_t resubmit_meta,
                         in empty_metadata_t recirculate_meta)
{
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        buffer.extract(parsed_hdr.ethernet);
        transition select(parsed_hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            0x806 : parse_arp;
            default: accept;
        }
    }
    state parse_arp {
        buffer.extract(parsed_hdr.arp);
        transition accept;
    }
    state parse_ipv4 {
        buffer.extract(parsed_hdr.ipv4);
        transition accept;
    }
}

control ingress(inout headers_t hdr,
                inout metadata_t user_meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    apply {

        if (hdr.ipv4.isValid()) {
            // IPV4 packets
            // Get the last two digits
            PortIdUint_t port =  (PortIdUint_t) hdr.ipv4.dstAddr[1:0];
            if (port == 1) {
                // The last two digits of Node 0's IP are 01, mapped to port 0
                send_to_port(ostd, (PortId_t) 0);
            } else if (port == 2) {
                // The last two digits of Node 1's IP are 10, mapped to port 1
                send_to_port(ostd, (PortId_t) 1);
            } else {
                // Other cases are handled according to the original rules
                send_to_port(ostd, (PortId_t) port);
            }
        } else {
            if (hdr.arp.isValid()) {
                PortIdUint_t port = (PortIdUint_t) hdr.arp.dstIp[1:0];
                if (port == 1) {
                    send_to_port(ostd, (PortId_t) 0);
                } else if (port == 2) {
                    send_to_port(ostd, (PortId_t) 1);
                } else {
                    send_to_port(ostd, (PortId_t) port);
                }
            }
        }
    }
}

parser EgressParserImpl(packet_in buffer,
                        out headers_t parsed_hdr,
                        inout metadata_t user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_metadata_t normal_meta,
                        in empty_metadata_t clone_i2e_meta,
                        in empty_metadata_t clone_e2e_meta)
{
    state start {
        transition accept;
    }
}

control egress(inout headers_t hdr,
               inout metadata_t user_meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply { }
}

control CommonDeparserImpl(packet_out packet,
                           inout headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

control IngressDeparserImpl(packet_out buffer,
                            out empty_metadata_t clone_i2e_meta,
                            out empty_metadata_t resubmit_meta,
                            out empty_metadata_t normal_meta,
                            inout headers_t hdr,
                            in metadata_t meta,
                            in psa_ingress_output_metadata_t istd)
{
    CommonDeparserImpl() cp;
    apply {
        cp.apply(buffer, hdr);
    }
}

control EgressDeparserImpl(packet_out buffer,
                           out empty_metadata_t clone_e2e_meta,
                           out empty_metadata_t recirculate_meta,
                           inout headers_t hdr,
                           in metadata_t meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{
    CommonDeparserImpl() cp;
    apply {
        cp.apply(buffer, hdr);
    }
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;