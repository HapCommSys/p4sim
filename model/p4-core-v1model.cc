/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
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
 * Authors: Antonin Bas <antonin@barefootnetworks.com>
 * Modified: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#include "ns3/p4-core-v1model.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/primitives-v1model.h"
#include "ns3/register-access-v1model.h"
#include "ns3/simulator.h"

#include <fstream> // tracing info to file
#include <sstream>

NS_LOG_COMPONENT_DEFINE("P4CoreV1model");

namespace ns3
{

namespace
{

struct hash_ex_v1model
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

struct bmv2_hash_v1model
{
    uint64_t operator()(const char* buf, size_t s) const
    {
        return bm::hash::xxh64(buf, s);
    }
};

} // namespace

// if REGISTER_HASH calls placed in the anonymous namespace, some compiler can
// give an unused variable warning
REGISTER_HASH(hash_ex_v1model);
REGISTER_HASH(bmv2_hash_v1model);

extern int import_primitives();

P4CoreV1model::P4CoreV1model(P4SwitchNetDevice* net_device,
                             bool enable_swap,
                             bool enableTracing,
                             uint64_t packet_rate,
                             size_t input_buffer_size_low,
                             size_t input_buffer_size_high,
                             size_t queue_buffer_size,
                             size_t nb_queues_per_port)
    : P4SwitchCore(net_device, enable_swap, enableTracing),
      m_packetId(0),
      m_switchRate(packet_rate),
      m_nbQueuesPerPort(nb_queues_per_port),
      input_buffer(std::make_unique<InputBuffer>(input_buffer_size_low, input_buffer_size_high)),
      egress_buffer(m_nbEgressThreads,
                    queue_buffer_size,
                    EgressThreadMapper(m_nbEgressThreads),
                    nb_queues_per_port),
      output_buffer(64),
      m_firstPacket(false)
{
    // configure for the switch v1model
    m_thriftCommand = "simple_switch_CLI"; // default thrift command for v1model
    m_enableQueueingMetadata = true;       // enable queueing metadata for v1model

    if (m_enableTracing)
    {
        m_inputBps = 0;                                 // bps
        m_inputBp = 0;                                  // bp
        m_inputPps = 0;                                 // pps
        m_inputPp = 0;                                  // pp
        m_egressBps = 0;                                // bps
        m_egressBp = 0;                                 // bp
        m_egressPps = 0;                                // pps
        m_egressPp = 0;                                 // pp
        m_timeInterval = Time::FromInteger(1, Time::S); // 1 second per interval
    }

    m_pre = std::make_shared<bm::McSimplePreLAG>();
    add_component<bm::McSimplePreLAG>(m_pre);

    add_required_field("standard_metadata", "ingress_port");
    add_required_field("standard_metadata", "packet_length");
    add_required_field("standard_metadata", "instance_type");
    add_required_field("standard_metadata", "egress_spec");
    add_required_field("standard_metadata", "egress_port");

    force_arith_header("standard_metadata");
    force_arith_header("queueing_metadata");
    force_arith_header("intrinsic_metadata");

    CalculateScheduleTime(); // calculate the time interval for processing one packet
}

P4CoreV1model::~P4CoreV1model()
{
    NS_LOG_FUNCTION(this << " Destructing P4CoreV1model...");

    if (input_buffer)
    {
        input_buffer->push_front(InputBuffer::PacketType::SENTINEL, nullptr);
    }

    for (size_t i = 0; i < m_nbEgressThreads; i++)
    {
        while (egress_buffer.push_front(i, 0, nullptr) == 0)
        {
            continue;
        }
    }

    output_buffer.push_front(nullptr);

    NS_LOG_INFO("P4CoreV1model destroyed successfully.");
}

void
P4CoreV1model::start_and_return_()
{
    NS_LOG_FUNCTION("Switch ID: " << m_p4SwitchId << " start");
    CheckQueueingMetadata();

    if (!m_egressTimeRef.IsZero())
    {
        NS_LOG_DEBUG("Switch ID: " << m_p4SwitchId
                                   << " Scheduling initial timer event using m_egressTimeRef = "
                                   << m_egressTimeRef.GetNanoSeconds() << " ns");
        m_egressTimeEvent =
            Simulator::Schedule(m_egressTimeRef, &P4CoreV1model::SetEgressTimerEvent, this);
    }

    if (m_enableTracing)
    {
        NS_LOG_INFO("Enabling tracing in P4 Switch ID: " << m_p4SwitchId);
        Simulator::Schedule(m_timeInterval, &P4CoreV1model::CalculatePacketsPerSecond, this);
    }
}

void
P4CoreV1model::swap_notify_()
{
    NS_LOG_FUNCTION("p4_switch has been notified of a config swap");
    CheckQueueingMetadata();
}

void
P4CoreV1model::reset_target_state_()
{
    NS_LOG_DEBUG("Resetting simple_switch target-specific state");
    get_component<bm::McSimplePreLAG>()->reset_state();
}

void
P4CoreV1model::SetEgressTimerEvent()
{
    NS_LOG_FUNCTION("p4_switch has been triggered by the egress timer event");
    bool checkflag = HandleEgressPipeline(0);
    m_egressTimeEvent =
        Simulator::Schedule(m_egressTimeRef, &P4CoreV1model::SetEgressTimerEvent, this);
    if (!m_firstPacket && checkflag)
    {
        m_firstPacket = true;
    }
    if (m_firstPacket && !checkflag)
    {
        NS_LOG_INFO("Egress timer event needs additional scheduling due to !checkflag.");
        Simulator::Schedule(Time(NanoSeconds(10)), &P4CoreV1model::HandleEgressPipeline, this, 0);
    }
}

int
P4CoreV1model::ReceivePacket(Ptr<Packet> packetIn,
                             int inPort,
                             uint16_t protocol,
                             const Address& destination)
{
    NS_LOG_FUNCTION(this);

    std::unique_ptr<bm::Packet> bm_packet = ConvertToBmPacket(packetIn, inPort);

    bm::PHV* phv = bm_packet->get_phv();
    int len = bm_packet.get()->get_data_size();

    if (m_enableTracing)
    {
        m_inputPps++;          // input pps
        m_inputBps += len * 8; // input bps, this may add the header in account.
    }

    bm_packet.get()->set_ingress_port(inPort);
    phv->reset_metadata();

    // setting ns3 specific metadata in packet register
    RegisterAccess::clear_all(bm_packet.get());
    RegisterAccess::set_ns_protocol(bm_packet.get(), protocol);
    int addr_index = GetAddressIndex(destination);
    RegisterAccess::set_ns_address(bm_packet.get(), addr_index);

    // setting standard metadata
    phv->get_field("standard_metadata.ingress_port").set(inPort);

    // using packet register 0 to store length, this register will be updated for
    // each add_header / remove_header primitive call
    bm_packet->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, len);
    phv->get_field("standard_metadata.packet_length").set(len);
    bm::Field& f_instance_type = phv->get_field("standard_metadata.instance_type");
    f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);
    if (phv->has_field("intrinsic_metadata.ingress_global_timestamp"))
    {
        phv->get_field("intrinsic_metadata.ingress_global_timestamp").set(GetTimeStamp());
    }

    input_buffer->push_front(InputBuffer::PacketType::NORMAL, std::move(bm_packet));
    HandleIngressPipeline();
    NS_LOG_DEBUG("Packet received by P4CoreV1model, Port: "
                 << inPort << ", Packet ID: " << m_packetId << ", Size: " << len << " bytes");
    return 0;
}

void
P4CoreV1model::HandleIngressPipeline()
{
    NS_LOG_FUNCTION(this);

    std::unique_ptr<bm::Packet> bm_packet;
    input_buffer->pop_back(&bm_packet);
    if (bm_packet == nullptr)
        return;

    bm::Parser* parser = this->get_parser("parser");
    bm::Pipeline* ingress_mau = this->get_pipeline("ingress");
    bm::PHV* phv = bm_packet->get_phv();

    uint32_t ingress_port = bm_packet->get_ingress_port();

    NS_LOG_INFO("Processing packet from port "
                << ingress_port << ", Packet ID: " << bm_packet->get_packet_id()
                << ", Size: " << bm_packet->get_data_size() << " bytes");

    auto ingress_packet_size = bm_packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);

    /* This looks like it comes out of the blue. However this is needed for
         ingress cloning. The parser updates the buffer state (pops the parsed
         headers) to make the deparser's job easier (the same buffer is
         re-used). But for ingress cloning, the original packet is needed. This
         kind of looks hacky though. Maybe a better solution would be to have the
         parser leave the buffer unchanged, and move the pop logic to the
         deparser. TODO? */
    const bm::Packet::buffer_state_t packet_in_state = bm_packet->save_buffer_state();

    parser->parse(bm_packet.get());

    if (phv->has_field("standard_metadata.parser_error"))
    {
        phv->get_field("standard_metadata.parser_error").set(bm_packet->get_error_code().get());
    }
    if (phv->has_field("standard_metadata.checksum_error"))
    {
        phv->get_field("standard_metadata.checksum_error")
            .set(bm_packet->get_checksum_error() ? 1 : 0);
    }

    ingress_mau->apply(bm_packet.get());

    bm_packet->reset_exit();

    bm::Field& f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    uint32_t egress_spec = f_egress_spec.get_uint();

    auto clone_mirror_session_id = RegisterAccess::get_clone_mirror_session_id(bm_packet.get());
    auto clone_field_list = RegisterAccess::get_clone_field_list(bm_packet.get());

    int learn_id = RegisterAccess::get_lf_field_list(bm_packet.get());
    unsigned int mgid = 0u;

    // detect mcast support, if this is true we assume that other fields needed
    // for mcast are also defined
    if (phv->has_field("intrinsic_metadata.mcast_grp"))
    {
        bm::Field& f_mgid = phv->get_field("intrinsic_metadata.mcast_grp");
        mgid = f_mgid.get_uint();
    }

    // INGRESS CLONING
    if (clone_mirror_session_id)
    {
        NS_LOG_INFO("Cloning packet at ingress, Packet ID: "
                    << bm_packet->get_packet_id() << ", Size: " << bm_packet->get_data_size()
                    << " bytes");

        RegisterAccess::set_clone_mirror_session_id(bm_packet.get(), 0);
        RegisterAccess::set_clone_field_list(bm_packet.get(), 0);
        MirroringSessionConfig config;
        // Extract the part of clone_mirror_session_id that contains the
        // actual session id.
        clone_mirror_session_id &= RegisterAccess::MIRROR_SESSION_ID_MASK;
        bool is_session_configured =
            GetMirroringSession(static_cast<int>(clone_mirror_session_id), &config);
        if (is_session_configured)
        {
            const bm::Packet::buffer_state_t packet_out_state = bm_packet->save_buffer_state();
            bm_packet->restore_buffer_state(packet_in_state);
            int field_list_id = clone_field_list;
            std::unique_ptr<bm::Packet> bm_packet_copy = bm_packet->clone_no_phv_ptr();
            RegisterAccess::clear_all(bm_packet_copy.get());
            bm_packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                                         ingress_packet_size);

            // We need to parse again.
            // The alternative would be to pay the (huge) price of PHV copy for
            // every ingress packet.
            // Since parsers can branch on the ingress port, we need to preserve it
            // to ensure re-parsing gives the same result as the original parse.
            // TODO(https://github.com/p4lang/behavioral-model/issues/795): other
            // standard metadata should be preserved as well.
            bm_packet_copy->get_phv()
                ->get_field("standard_metadata.ingress_port")
                .set(ingress_port);
            parser->parse(bm_packet_copy.get());
            CopyFieldList(bm_packet,
                          bm_packet_copy,
                          PKT_INSTANCE_TYPE_INGRESS_CLONE,
                          field_list_id);
            if (config.mgid_valid)
            {
                NS_LOG_DEBUG("Cloning packet to MGID {}" << config.mgid);
                MulticastPacket(bm_packet_copy.get(), config.mgid);
            }
            if (config.egress_port_valid)
            {
                NS_LOG_DEBUG("Cloning packet to egress port "
                             << config.egress_port << ", Packet ID: " << bm_packet->get_packet_id()
                             << ", Size: " << bm_packet->get_data_size() << " bytes");
                Enqueue(config.egress_port, std::move(bm_packet_copy));
            }
            bm_packet->restore_buffer_state(packet_out_state);
        }
    }

    // LEARNING
    if (learn_id > 0)
    {
        get_learn_engine()->learn(learn_id, *bm_packet.get());
    }

    // RESUBMIT
    auto resubmit_flag = RegisterAccess::get_resubmit_flag(bm_packet.get());
    if (resubmit_flag)
    {
        NS_LOG_DEBUG("Resubmitting packet");

        // get the packet ready for being parsed again at the beginning of
        // ingress
        bm_packet->restore_buffer_state(packet_in_state);
        int field_list_id = resubmit_flag;
        RegisterAccess::set_resubmit_flag(bm_packet.get(), 0);
        // TODO(antonin): a copy is not needed here, but I don't yet have an
        // optimized way of doing this
        std::unique_ptr<bm::Packet> bm_packet_copy = bm_packet->clone_no_phv_ptr();
        bm::PHV* phv_copy = bm_packet_copy->get_phv();
        CopyFieldList(bm_packet, bm_packet_copy, PKT_INSTANCE_TYPE_RESUBMIT, field_list_id);
        RegisterAccess::clear_all(bm_packet_copy.get());
        bm_packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, ingress_packet_size);
        phv_copy->get_field("standard_metadata.packet_length").set(ingress_packet_size);

        input_buffer->push_front(InputBuffer::PacketType::RESUBMIT, std::move(bm_packet_copy));
        HandleIngressPipeline();
        return;
    }

    // MULTICAST
    if (mgid != 0)
    {
        NS_LOG_DEBUG("Multicast requested for packet");
        auto& f_instance_type = phv->get_field("standard_metadata.instance_type");
        f_instance_type.set(PKT_INSTANCE_TYPE_REPLICATION);
        MulticastPacket(bm_packet.get(), mgid);
        // when doing MulticastPacket, we discard the original packet
        return;
    }

    uint32_t egress_port = egress_spec;
    NS_LOG_DEBUG("Egress port is " << egress_port);

    if (egress_port == m_dropPort)
    {
        // drop packet
        NS_LOG_DEBUG("Dropping packet at the end of ingress");
        return;
    }
    auto& f_instance_type = phv->get_field("standard_metadata.instance_type");
    f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

    NS_LOG_DEBUG("Packet ID: " << bm_packet->get_packet_id()
                               << ", Size: " << bm_packet->get_data_size()
                               << " bytes, Egress Port: " << egress_port);
    Enqueue(egress_port, std::move(bm_packet));
}

void
P4CoreV1model::Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet)
{
    packet->set_egress_port(egress_port);

    bm::PHV* phv = packet->get_phv();

    if (m_enableQueueingMetadata)
    {
        phv->get_field("queueing_metadata.enq_timestamp").set(GetTimeStamp());
        phv->get_field("queueing_metadata.enq_qdepth").set(egress_buffer.size(egress_port));
    }

    size_t priority = phv->has_field("intrinsic_metadata.priority")
                          ? phv->get_field("intrinsic_metadata.priority").get<size_t>()
                          : 0u;
    if (priority >= m_nbQueuesPerPort)
    {
        NS_LOG_ERROR("Priority out of range, dropping packet");
        return;
    }

    egress_buffer.push_front(egress_port, m_nbQueuesPerPort - 1 - priority, std::move(packet));

    NS_LOG_DEBUG("Packet enqueued in queue buffer with Port: " << egress_port
                                                               << ", Priority: " << priority);
}

bool
P4CoreV1model::HandleEgressPipeline(size_t workerId)
{
    NS_LOG_FUNCTION("HandleEgressPipeline");
    std::unique_ptr<bm::Packet> bm_packet;
    size_t port;
    size_t priority;

    int queue_number = SSWITCH_VIRTUAL_QUEUE_NUM_V1MODEL;

    for (int i = 0; i < queue_number; i++)
    {
        if (egress_buffer.size(i) > 0)
        {
            break;
        }
        if (i == queue_number - 1)
        {
            return false;
        }
    }

    egress_buffer.pop_back(workerId, &port, &priority, &bm_packet);
    if (bm_packet == nullptr)
        return false;

    if (m_enableTracing)
    {
        m_egressPps++; // egress pps
        int len = bm_packet->get_data_size();
        m_egressBps += len * 8; // egress bps, this may add the header in account.
    }

    NS_LOG_FUNCTION("Egress processing for the packet");
    bm::PHV* phv = bm_packet->get_phv();
    bm::Pipeline* egress_mau = this->get_pipeline("egress");
    bm::Deparser* deparser = this->get_deparser("deparser");

    if (phv->has_field("intrinsic_metadata.egress_global_timestamp"))
    {
        phv->get_field("intrinsic_metadata.egress_global_timestamp").set(GetTimeStamp());
    }

    if (m_enableQueueingMetadata)
    {
        uint64_t enq_timestamp = phv->get_field("queueing_metadata.enq_timestamp").get<uint64_t>();
        phv->get_field("queueing_metadata.deq_timedelta").set(GetTimeStamp() - enq_timestamp);

        size_t priority = phv->has_field("intrinsic_metadata.priority")
                              ? phv->get_field("intrinsic_metadata.priority").get<size_t>()
                              : 0u;
        if (priority >= m_nbQueuesPerPort)
        {
            NS_LOG_ERROR("Priority out of range (m_nbQueuesPerPort = " << m_nbQueuesPerPort
                                                                       << "), dropping packet");
            return true;
        }

        phv->get_field("queueing_metadata.deq_qdepth").set(egress_buffer.size(port));
        if (phv->has_field("queueing_metadata.qid"))
        {
            auto& qid_f = phv->get_field("queueing_metadata.qid");
            qid_f.set(m_nbQueuesPerPort - 1 - priority);
        }
    }

    phv->get_field("standard_metadata.egress_port").set(port);

    bm::Field& f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    f_egress_spec.set(0);

    phv->get_field("standard_metadata.packet_length")
        .set(bm_packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX));

    egress_mau->apply(bm_packet.get());

    auto clone_mirror_session_id = RegisterAccess::get_clone_mirror_session_id(bm_packet.get());
    auto clone_field_list = RegisterAccess::get_clone_field_list(bm_packet.get());

    // EGRESS CLONING
    if (clone_mirror_session_id)
    {
        NS_LOG_DEBUG("Cloning packet at egress, Packet ID: "
                     << bm_packet->get_packet_id() << ", Size: " << bm_packet->get_data_size()
                     << " bytes");
        RegisterAccess::set_clone_mirror_session_id(bm_packet.get(), 0);
        RegisterAccess::set_clone_field_list(bm_packet.get(), 0);
        MirroringSessionConfig config;
        // Extract the part of clone_mirror_session_id that contains the
        // actual session id.
        clone_mirror_session_id &= RegisterAccess::MIRROR_SESSION_ID_MASK;
        bool is_session_configured =
            GetMirroringSession(static_cast<int>(clone_mirror_session_id), &config);
        if (is_session_configured)
        {
            int field_list_id = clone_field_list;
            std::unique_ptr<bm::Packet> packet_copy =
                bm_packet->clone_with_phv_reset_metadata_ptr();
            bm::PHV* phv_copy = packet_copy->get_phv();
            bm::FieldList* field_list = this->get_field_list(field_list_id);
            field_list->copy_fields_between_phvs(phv_copy, phv);
            phv_copy->get_field("standard_metadata.instance_type")
                .set(PKT_INSTANCE_TYPE_EGRESS_CLONE);
            auto packet_size = bm_packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);
            RegisterAccess::clear_all(packet_copy.get());
            packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, packet_size);
            if (config.mgid_valid)
            {
                NS_LOG_DEBUG("Cloning packet to MGID " << config.mgid);
                MulticastPacket(packet_copy.get(), config.mgid);
            }
            if (config.egress_port_valid)
            {
                NS_LOG_DEBUG("Cloning packet to egress port " << config.egress_port);
                // TODO This create a copy packet(new bm packet), but the UID mapping
                // may need to be updated in map.
                Enqueue(config.egress_port, std::move(packet_copy));
            }
        }
    }

    // TODO(antonin): should not be done like this in egress pipeline
    uint32_t egress_spec = f_egress_spec.get_uint();
    if (egress_spec == m_dropPort)
    {
        // drop packet
        NS_LOG_DEBUG("Dropping packet at the end of egress");
        return true;
    }

    deparser->deparse(bm_packet.get());

    // RECIRCULATE
    auto recirculate_flag = RegisterAccess::get_recirculate_flag(bm_packet.get());
    if (recirculate_flag)
    {
        NS_LOG_DEBUG("Recirculating packet");

        int field_list_id = recirculate_flag;
        RegisterAccess::set_recirculate_flag(bm_packet.get(), 0);
        bm::FieldList* field_list = this->get_field_list(field_list_id);
        // TODO(antonin): just like for resubmit, there is no need for a copy
        // here, but it is more convenient for this first prototype
        std::unique_ptr<bm::Packet> packet_copy = bm_packet->clone_no_phv_ptr();
        bm::PHV* phv_copy = packet_copy->get_phv();
        phv_copy->reset_metadata();
        field_list->copy_fields_between_phvs(phv_copy, phv);
        phv_copy->get_field("standard_metadata.instance_type").set(PKT_INSTANCE_TYPE_RECIRC);
        size_t packet_size = packet_copy->get_data_size();
        RegisterAccess::clear_all(packet_copy.get());
        packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, packet_size);
        phv_copy->get_field("standard_metadata.packet_length").set(packet_size);
        // TODO(antonin): really it may be better to create a new packet here or
        // to fold this functionality into the Packet class?
        packet_copy->set_ingress_length(packet_size);
        input_buffer->push_front(InputBuffer::PacketType::RECIRCULATE, std::move(packet_copy));
        return true;
    }

    uint16_t protocol = RegisterAccess::get_ns_protocol(bm_packet.get());
    int addr_index = RegisterAccess::get_ns_address(bm_packet.get());

    Ptr<Packet> ns_packet = this->ConvertToNs3Packet(std::move(bm_packet));
    NS_LOG_DEBUG("Sending packet to NS-3 stack, Packet ID: " << ns_packet->GetUid() << ", Size: "
                                                             << ns_packet->GetSize() << " bytes");
    m_switchNetDevice->SendNs3Packet(ns_packet, port, protocol, m_destinationList[addr_index]);
    return true;
}

void
P4CoreV1model::CalculateScheduleTime()
{
    m_egressTimeEvent = EventId();

    // Now we can not set the dequeue rate for each queue, later we will add this feature
    // by p4 runtime controller.
    uint64_t bottleneck_ns = 1e9 / m_switchRate;
    egress_buffer.set_rate_for_all(m_switchRate);
    m_egressTimeRef = Time::FromDouble(bottleneck_ns, Time::NS);

    NS_LOG_DEBUG("Switch ID: " << m_p4SwitchId << " Egress time reference set to " << bottleneck_ns
                               << " ns (" << m_egressTimeRef.GetNanoSeconds() << " [ns])");
}

void
P4CoreV1model::MulticastPacket(bm::Packet* packet, unsigned int mgid)
{
    NS_LOG_FUNCTION(this);
    auto* phv = packet->get_phv();
    auto& f_rid = phv->get_field("intrinsic_metadata.egress_rid");
    const auto pre_out = m_pre->replicate({mgid});
    auto packet_size = packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);
    for (const auto& out : pre_out)
    {
        auto egress_port = out.egress_port;
        NS_LOG_DEBUG("Replicating packet on port " << egress_port);
        f_rid.set(out.rid);
        std::unique_ptr<bm::Packet> packet_copy = packet->clone_with_phv_ptr();
        RegisterAccess::clear_all(packet_copy.get());
        packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, packet_size);
        Enqueue(egress_port, std::move(packet_copy));
    }
}

void
P4CoreV1model::CalculatePacketsPerSecond()
{
    // Calculating P4 switch statistics
    m_inputBp += m_inputBps;
    m_inputPp += m_inputPps;
    m_egressBp += m_egressBp;
    m_egressPp += m_egressPps;

    // Construct log file path
    std::string log_filename = "/tmp/bmv2-" + std::to_string(m_p4SwitchId) + "-queue_info.log";
    static std::ofstream log_file(log_filename, std::ios::app);

    if (!log_file.is_open())
    {
        NS_LOG_ERROR("Failed to open log file: " << log_filename);
        return;
    }

    std::ostringstream log_stream;
    log_stream << "P4 switch ID: " << m_p4SwitchId << "\n";
    log_stream << "Time: " << Simulator::Now().GetSeconds() << " [s]\n";
    log_stream << "Input packets per time interval: " << m_inputPps << " [pps]\n";
    log_stream << "Input bits per time interval: " << m_inputBps << " [bps]\n";
    log_stream << "Egress packets per time interval: " << m_egressPps << " [pps]\n";
    log_stream << "Egress bits per time interval: " << m_egressBps << " [bps]\n";

    log_stream << "Total input packets: " << m_inputPp << " [pp]\n";
    log_stream << "Total input bits: " << m_inputBp << " [bp]\n";
    log_stream << "Total egress packets: " << m_egressPp << " [pp]\n";
    log_stream << "Total egress bits: " << m_egressBp << " [bp]\n";

    m_inputPps = 0;
    m_inputBps = 0;
    m_egressPps = 0;
    m_egressBps = 0;

    size_t input_buffer_size = input_buffer->get_size();
    log_stream << "Input buffer size: " << input_buffer_size << "\n";

    uint32_t port_number = m_switchNetDevice->GetNBridgePorts();

    for (size_t i = 0; i < static_cast<size_t>(port_number); i++)
    {
        size_t queue_size = egress_buffer.size(i);
        log_stream << "[TEST] Queue buffer for ports " << i << " size: " << queue_size << "\n";
    }

    for (size_t i = 0; i < static_cast<size_t>(port_number); i++)
    {
        for (size_t j = 0; j < m_nbQueuesPerPort; j++)
        {
            size_t queue_size = egress_buffer.size(i, j);
            log_stream << "Queue pipeline " << i << " priority " << j << " size: " << queue_size
                       << "\n";
        }
    }

    size_t output_buffer_size = output_buffer.size();
    log_stream << "Output buffer size: " << output_buffer_size << "\n";

    log_file << log_stream.str();
    log_file.flush();

    Simulator::Schedule(m_timeInterval, &P4CoreV1model::CalculatePacketsPerSecond, this);
}

void
P4CoreV1model::CopyFieldList(const std::unique_ptr<bm::Packet>& packet,
                             const std::unique_ptr<bm::Packet>& packetCopy,
                             PktInstanceTypeV1model copyType,
                             int fieldListId)
{
    bm::PHV* phv_copy = packetCopy->get_phv();
    phv_copy->reset_metadata();
    bm::FieldList* field_list = this->get_field_list(fieldListId);
    field_list->copy_fields_between_phvs(phv_copy, packet->get_phv());
    phv_copy->get_field("standard_metadata.instance_type").set(copyType);
}

int
P4CoreV1model::SetEgressPriorityQueueDepth(size_t port, size_t priority, const size_t depth_pkts)
{
    egress_buffer.set_capacity(port, priority, depth_pkts);
    return 0;
}

int
P4CoreV1model::SetEgressQueueDepth(size_t port, const size_t depth_pkts)
{
    egress_buffer.set_capacity(port, depth_pkts);
    return 0;
}

int
P4CoreV1model::SetAllEgressQueueDepths(const size_t depth_pkts)
{
    egress_buffer.set_capacity_for_all(depth_pkts);
    return 0;
}

int
P4CoreV1model::SetEgressPriorityQueueRate(size_t port, size_t priority, const uint64_t rate_pps)
{
    egress_buffer.set_rate(port, priority, rate_pps);
    return 0;
}

int
P4CoreV1model::SetEgressQueueRate(size_t port, const uint64_t rate_pps)
{
    egress_buffer.set_rate(port, rate_pps);
    return 0;
}

int
P4CoreV1model::SetAllEgressQueueRates(const uint64_t rate_pps)
{
    egress_buffer.set_rate_for_all(rate_pps);
    return 0;
}

} // namespace ns3