/*
 * Copyright (c)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Jiasong Bai
 * Modified: Mingyu Ma<mingyu.ma@tu-dresden.de>
 */

#include "ns3/p4-core-pipeline.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/register-access-v1model.h"
#include "ns3/simulator.h"

#undef LOG_INFO
#undef LOG_ERROR
#undef LOG_DEBUG
#undef LOG_WARN
#undef LOG_LOGIC

NS_LOG_COMPONENT_DEFINE("P4CoreV1modelPipeline");

namespace ns3
{

namespace
{

struct hash_ex_v1model_pipeline
{
    uint32_t operator()(const char* buf, size_t s) const
    {
        const uint32_t p = 16777619;
        uint32_t hash = 2166136261;

        for (size_t i = 0; i < s; i++)
            hash = (hash ^ buf[i]) * p;

        hash += hash << 13;
        hash ^= hash >> 7;
        hash += hash << 3;
        hash ^= hash >> 17;
        hash += hash << 5;
        return static_cast<uint32_t>(hash);
    }
};

struct bmv2_hash_v1model_pipeline
{
    uint64_t operator()(const char* buf, size_t s) const
    {
        return bm::hash::xxh64(buf, s);
    }
};

} // namespace

// if REGISTER_HASH calls placed in the anonymous namespace, some compiler can
// give an unused variable warning
REGISTER_HASH(hash_ex_v1model_pipeline);
REGISTER_HASH(bmv2_hash_v1model_pipeline);

P4CorePipeline::P4CorePipeline(P4SwitchNetDevice* netDevice, bool enableSwap, bool enableTracing)
    : P4SwitchCore(netDevice, enableSwap, enableTracing),
      m_packetId(0)
{
    // configure for the switch v1model
    m_thriftCommand = "simple_switch_CLI"; // default thrift command for v1model
    m_enableQueueingMetadata = false;      // disable queueing metadata for v1model

    add_required_field("standard_metadata", "ingress_port");
    add_required_field("standard_metadata", "packet_length");
    add_required_field("standard_metadata", "instance_type");
    add_required_field("standard_metadata", "egress_spec");
    add_required_field("standard_metadata", "egress_port");

    force_arith_header("standard_metadata");
    // force_arith_header("queueing_metadata"); // not supported queueing metadata
    force_arith_header("intrinsic_metadata");
}

P4CorePipeline::~P4CorePipeline()
{
    NS_LOG_FUNCTION(this);
    NS_LOG_INFO("Destroying P4CorePipeline.");
}

int
P4CorePipeline::ReceivePacket(Ptr<Packet> packetIn,
                              int inPort,
                              uint16_t protocol,
                              const Address& destination)
{
    NS_LOG_FUNCTION(this);

    std::unique_ptr<bm::Packet> bm_packet = ConvertToBmPacket(packetIn, inPort);

    bm::PHV* phv = bm_packet->get_phv();
    uint32_t len = bm_packet.get()->get_data_size();
    bm_packet.get()->set_ingress_port(inPort);

    phv->reset_metadata();
    phv->get_field("standard_metadata.ingress_port").set(inPort);
    bm_packet->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, len);
    phv->get_field("standard_metadata.packet_length").set(len);
    bm::Field& f_instance_type = phv->get_field("standard_metadata.instance_type");
    f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

    // === Parser and MAU processing
    bm::Parser* parser = this->get_parser("parser");
    bm::Pipeline* ingress_mau = this->get_pipeline("ingress");
    parser->parse(bm_packet.get());
    ingress_mau->apply(bm_packet.get());

    bm_packet->reset_exit();
    bm::Field& f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    uint32_t egress_spec = f_egress_spec.get_uint();

    // LEARNING
    int learn_id = RegisterAccess::get_lf_field_list(bm_packet.get());
    if (learn_id > 0)
    {
        get_learn_engine()->learn(learn_id, *bm_packet.get());
    }

    // === Egress
    bm::Pipeline* egress_mau = this->get_pipeline("egress");
    bm::Deparser* deparser = this->get_deparser("deparser");
    phv->get_field("standard_metadata.egress_port").set(egress_spec);
    f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    f_egress_spec.set(0);

    phv->get_field("standard_metadata.packet_length")
        .set(bm_packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX));

    egress_mau->apply(bm_packet.get());

    // === Deparser
    deparser->deparse(bm_packet.get());

    // === Send the packet to the destination
    Ptr<Packet> ns_packet = ConvertToNs3Packet(std::move(bm_packet));
    m_switchNetDevice->SendNs3Packet(ns_packet, egress_spec, protocol, destination);
    return 0;
}

int
P4CorePipeline::receive_(uint32_t port_num, const char* buffer, int len)
{
    NS_LOG_FUNCTION(this << " Port: " << port_num << " Len: " << len);
    return 0;
}

void
P4CorePipeline::start_and_return_()
{
    NS_LOG_FUNCTION(this);
}

void
P4CorePipeline::swap_notify_()
{
    NS_LOG_FUNCTION("p4_switch has been notified of a config swap");
}

void
P4CorePipeline::reset_target_state_()
{
    NS_LOG_DEBUG("Resetting target-specific state, not supported.");
}

void
P4CorePipeline::HandleIngressPipeline()
{
    NS_LOG_FUNCTION(this);
    NS_LOG_DEBUG("Dummy functions for handling ingress pipeline, use ReceivePacket instead");
}

bool
P4CorePipeline::HandleEgressPipeline(size_t workerId)
{
    NS_LOG_FUNCTION(this);
    NS_LOG_DEBUG("Dummy functions for handling egress pipeline, use ReceivePacket instead");
    return false;
}

void
P4CorePipeline::Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet)
{
    NS_LOG_WARN("NO inter queue buffer in this simple v1model, use ReceivePacket instead");
}

} // namespace ns3
