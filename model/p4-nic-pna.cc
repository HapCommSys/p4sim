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

#include <bm/bm_sim/actions.h>

NS_LOG_COMPONENT_DEFINE("P4CorePna");

namespace
{

// PNA forwarding extern functions (pna.p4). p4c-bm2-pna emits them as BMv2
// primitives, but only the v1model primitives are registered in p4sim, so a
// PNA JSON failed to load with "Unknown primitive action: drop_packet".

// send_to_port(PortId_t dest_port)
class send_to_port : public bm::ActionPrimitive<const bm::Data&>
{
    void operator()(const bm::Data& dest_port)
    {
        get_packet().set_egress_port(dest_port.get<uint32_t>());
    }
};

REGISTER_PRIMITIVE(send_to_port);

// drop_packet(): the packet is dropped once the main control completes.
class drop_packet : public bm::ActionPrimitive<>
{
    void operator()()
    {
        get_packet().set_egress_port(SSWITCH_DROP_PORT);
    }
};

REGISTER_PRIMITIVE(drop_packet);

} // namespace

namespace ns3
{

P4PnaNic::P4PnaNic(P4SwitchNetDevice* net_device, bool enable_swap)
    : P4SwitchCore(net_device, enable_swap, false),
      m_packetId(0)
{
    // configure for the switch pna
    m_thriftCommand = "";             // default thrift command for pna
    m_enableQueueingMetadata = false; // enable queueing metadata for pna

    // used by reset_target_state_()
    add_component<bm::McSimplePreLAG>(m_pre);

    // The loopback flag is named "loopedback" in current p4c pna.p4 and
    // "recirculated" in older versions, so it is not a required field here;
    // the name actually present in the JSON is resolved in start_and_return_().
    add_required_field("pna_main_parser_input_metadata", "input_port");

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
}

bool
P4PnaNic::main_processing_pipeline(std::unique_ptr<bm::Packet> bm_packet)
{
    NS_LOG_FUNCTION(this);

    bm::PHV* phv = bm_packet->get_phv();
    auto input_port = phv->get_field("pna_main_parser_input_metadata.input_port").get_uint();

    NS_LOG_DEBUG("Processing packet received on port " << input_port);

    phv->get_field("pna_main_input_metadata.timestamp").set(GetTimeStamp());

    bm::Parser* parser = this->get_parser("main_parser");
    parser->parse(bm_packet.get());

    // pass relevant values from main parser
    phv->get_field("pna_main_input_metadata." + m_loopedbackField)
        .set(phv->get_field("pna_main_parser_input_metadata." + m_loopedbackField));
    phv->get_field("pna_main_input_metadata.parser_error").set(bm_packet->get_error_code().get());
    phv->get_field("pna_main_input_metadata.class_of_service").set(0);
    phv->get_field("pna_main_input_metadata.input_port")
        .set(phv->get_field("pna_main_parser_input_metadata.input_port"));

    // a packet is dropped unless the main control calls send_to_port().
    // Use the same constant as the drop_packet primitive above, which has no
    // access to this switch instance (and thus to m_dropPort).
    bm_packet->set_egress_port(SSWITCH_DROP_PORT);

    bm::Pipeline* main_mau = this->get_pipeline("main_control");
    main_mau->apply(bm_packet.get());
    bm_packet->reset_exit();

    int port = bm_packet->get_egress_port();
    if (port == SSWITCH_DROP_PORT)
    {
        NS_LOG_DEBUG("Dropping packet received on port " << input_port);
        return false;
    }

    bm::Deparser* deparser = this->get_deparser("main_deparser");
    deparser->deparse(bm_packet.get());

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

    phv->get_field("pna_main_parser_input_metadata." + m_loopedbackField).set(0);
    phv->get_field("pna_main_parser_input_metadata.input_port").set(inPort);

    // using packet register 0 to store length, this register will be updated for
    // each add_header / remove_header primitive call
    bm_packet->set_register(0, len);

    // The NIC has no internal queue: run the PNA pipeline synchronously, as
    // P4CorePipeline does. (Previously the packet was pushed into a queue
    // that nothing consumed.)
    main_processing_pipeline(std::move(bm_packet));
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

    for (const char* name : {"loopedback", "recirculated"})
    {
        if (field_exists("pna_main_parser_input_metadata", name) &&
            field_exists("pna_main_input_metadata", name))
        {
            m_loopedbackField = name;
            return;
        }
    }
    NS_FATAL_ERROR("PNA JSON defines neither 'loopedback' nor 'recirculated' in "
                   "pna_main_parser_input_metadata / pna_main_input_metadata");
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
