/* Copyright 2024 Marvell Technology, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Rupesh Chiluka <rchiluka@marvell.com>
 * Modified: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#include "ns3/p4-nic-pna.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/register-access-v1model.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE("P4CorePna");

namespace ns3
{

P4PnaNic::P4PnaNic(P4SwitchNetDevice* net_device, bool enable_swap)
    : P4SwitchCore(net_device, enable_swap, false),
      m_packetId(0),
      input_buffer(1024)
{
    // configure for the switch pna
    m_thriftCommand = "";             // default thrift command for pna
    m_enableQueueingMetadata = false; // enable queueing metadata for pna

    add_required_field("pna_main_parser_input_metadata", "recirculated");
    add_required_field("pna_main_parser_input_metadata", "input_port");

    add_required_field("pna_main_input_metadata", "recirculated");
    add_required_field("pna_main_input_metadata", "timestamp");
    add_required_field("pna_main_input_metadata", "parser_error");
    add_required_field("pna_main_input_metadata", "class_of_service");
    add_required_field("pna_main_input_metadata", "input_port");

    add_required_field("pna_main_output_metadata", "class_of_service");

    force_arith_header("pna_main_parser_input_metadata");
    force_arith_header("pna_main_input_metadata");
    force_arith_header("pna_main_output_metadata");
}

P4PnaNic::~P4PnaNic()
{
    input_buffer.push_front(nullptr);
}

bool
P4PnaNic::main_processing_pipeline()
{
    NS_LOG_FUNCTION(this);

    std::unique_ptr<bm::Packet> bm_packet;
    input_buffer.pop_back(&bm_packet);
    if (bm_packet == nullptr)
        return false;

    bm::PHV* phv = bm_packet->get_phv();
    auto input_port = phv->get_field("pna_main_parser_input_metadata.input_port").get_uint();

    NS_LOG_DEBUG("Processing packet received on port " << input_port);

    phv->get_field("pna_main_input_metadata.timestamp").set(GetTimeStamp());

    bm::Parser* parser = this->get_parser("main_parser");
    parser->parse(bm_packet.get());

    // pass relevant values from main parser
    phv->get_field("pna_main_input_metadata.recirculated")
        .set(phv->get_field("pna_main_parser_input_metadata.recirculated"));
    phv->get_field("pna_main_input_metadata.parser_error").set(bm_packet->get_error_code().get());
    phv->get_field("pna_main_input_metadata.class_of_service").set(0);
    phv->get_field("pna_main_input_metadata.input_port")
        .set(phv->get_field("pna_main_parser_input_metadata.input_port"));

    bm::Pipeline* main_mau = this->get_pipeline("main_control");
    main_mau->apply(bm_packet.get());
    bm_packet->reset_exit();

    bm::Deparser* deparser = this->get_deparser("main_deparser");
    deparser->deparse(bm_packet.get());

    int port = bm_packet->get_egress_port();
    uint16_t protocol = RegisterAccess::get_ns_protocol(bm_packet.get());
    int addr_index = RegisterAccess::get_ns_address(bm_packet.get());

    Ptr<Packet> ns_packet = this->ConvertToNs3Packet(std::move(bm_packet));
    m_switchNetDevice->SendNs3Packet(ns_packet, port, protocol, m_destinationList[addr_index]);
    return true;
}

int
P4PnaNic::ReceivePacket(Ptr<Packet> packetIn,
                        int inPort,
                        uint16_t protocol,
                        const Address& destination)
{
    std::unique_ptr<bm::Packet> bm_packet = ConvertToBmPacket(packetIn, inPort);
    int len = bm_packet.get()->get_data_size();
    bm::PHV* phv = bm_packet->get_phv();

    // many current p4 programs assume this
    // from pna spec - PNA does not mandate initialization of user-defined
    // metadata to known values as given as input to the parser
    phv->reset_metadata();

    // setting ns3 specific metadata in packet register
    RegisterAccess::clear_all(bm_packet.get());
    RegisterAccess::set_ns_protocol(bm_packet.get(), protocol);
    int addr_index = GetAddressIndex(destination);
    RegisterAccess::set_ns_address(bm_packet.get(), addr_index);

    phv->get_field("pna_main_parser_input_metadata.recirculated").set(0);
    phv->get_field("pna_main_parser_input_metadata.input_port").set(inPort);

    // using packet register 0 to store length, this register will be updated for
    // each add_header / remove_header primitive call
    bm_packet->set_register(0, len);

    input_buffer.push_front(std::move(bm_packet));
    return 0;
}

int
P4PnaNic::receive_(port_t port_num, const char* buffer, int len)
{
    NS_LOG_FUNCTION(this << " Port: " << port_num << " Len: " << len);
    return 0;
}

void
P4PnaNic::start_and_return_()
{
    NS_LOG_FUNCTION(this);
}

void
P4PnaNic::reset_target_state_()
{
    NS_LOG_FUNCTION(this);
    get_component<bm::McSimplePreLAG>()->reset_state();
}

void
P4PnaNic::HandleIngressPipeline()
{
    NS_LOG_FUNCTION(this);
    NS_LOG_DEBUG(
        "Dummy functions for handling ingress pipeline, use main_processing_pipeline instead");
}

bool
P4PnaNic::HandleEgressPipeline(size_t workerId)
{
    NS_LOG_FUNCTION(this);
    NS_LOG_DEBUG(
        "Dummy functions for handling egress pipeline, use main_processing_pipeline instead");
    return false;
}

void
P4PnaNic::Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet)
{
    NS_LOG_WARN("NO inter queue buffer in PNA, use main_processing_pipeline instead");
}

} // namespace ns3
