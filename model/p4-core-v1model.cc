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

    CalculateScheduleTime(); // calculate the time interval for processing one
                             // packet
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

static const char*
MatchErrorCodeToStr(bm::MatchErrorCode rcc)
{
    switch (rcc)
    {
    case bm::MatchErrorCode::SUCCESS:
        return "SUCCESS";
    case bm::MatchErrorCode::TABLE_FULL:
        return "TABLE_FULL";
    case bm::MatchErrorCode::INVALID_HANDLE:
        return "INVALID_HANDLE";
    case bm::MatchErrorCode::EXPIRED_HANDLE:
        return "EXPIRED_HANDLE";
    case bm::MatchErrorCode::COUNTERS_DISABLED:
        return "COUNTERS_DISABLED";
    case bm::MatchErrorCode::METERS_DISABLED:
        return "METERS_DISABLED";
    case bm::MatchErrorCode::AGEING_DISABLED:
        return "AGEING_DISABLED";
    case bm::MatchErrorCode::INVALID_TABLE_NAME:
        return "INVALID_TABLE_NAME";
    case bm::MatchErrorCode::INVALID_ACTION_NAME:
        return "INVALID_ACTION_NAME";
    case bm::MatchErrorCode::WRONG_TABLE_TYPE:
        return "WRONG_TABLE_TYPE";
    case bm::MatchErrorCode::INVALID_MBR_HANDLE:
        return "INVALID_MBR_HANDLE";
    case bm::MatchErrorCode::MBR_STILL_USED:
        return "MBR_STILL_USED";
    case bm::MatchErrorCode::MBR_ALREADY_IN_GRP:
        return "MBR_ALREADY_IN_GRP";
    case bm::MatchErrorCode::MBR_NOT_IN_GRP:
        return "MBR_NOT_IN_GRP";
    case bm::MatchErrorCode::INVALID_GRP_HANDLE:
        return "INVALID_GRP_HANDLE";
    case bm::MatchErrorCode::GRP_STILL_USED:
        return "GRP_STILL_USED";
    case bm::MatchErrorCode::EMPTY_GRP:
        return "EMPTY_GRP";
    case bm::MatchErrorCode::DUPLICATE_ENTRY:
        return "DUPLICATE_ENTRY";
    case bm::MatchErrorCode::BAD_MATCH_KEY:
        return "BAD_MATCH_KEY";
    case bm::MatchErrorCode::INVALID_METER_OPERATION:
        return "INVALID_METER_OPERATION";
    case bm::MatchErrorCode::DEFAULT_ACTION_IS_CONST:
        return "DEFAULT_ACTION_IS_CONST";
    case bm::MatchErrorCode::DEFAULT_ENTRY_IS_CONST:
        return "DEFAULT_ENTRY_IS_CONST";
    case bm::MatchErrorCode::NO_DEFAULT_ENTRY:
        return "NO_DEFAULT_ENTRY";
    case bm::MatchErrorCode::INVALID_ACTION_PROFILE_NAME:
        return "INVALID_ACTION_PROFILE_NAME";
    case bm::MatchErrorCode::NO_ACTION_PROFILE_SELECTION:
        return "NO_ACTION_PROFILE_SELECTION";
    case bm::MatchErrorCode::IMMUTABLE_TABLE_ENTRIES:
        return "IMMUTABLE_TABLE_ENTRIES";
    case bm::MatchErrorCode::BAD_ACTION_DATA:
        return "BAD_ACTION_DATA";
    case bm::MatchErrorCode::NO_TABLE_KEY:
        return "NO_TABLE_KEY";
    case bm::MatchErrorCode::ERROR:
        return "GENERIC_ERROR";
    default:
        return "UNKNOWN_ERROR_CODE";
    }
}

static const char*
CounterErrorCodeToStr(bm::Counter::CounterErrorCode code)
{
    switch (code)
    {
    case bm::Counter::CounterErrorCode::SUCCESS:
        return "SUCCESS";
    case bm::Counter::CounterErrorCode::INVALID_COUNTER_NAME:
        return "INVALID_COUNTER_NAME";
    case bm::Counter::CounterErrorCode::INVALID_INDEX:
        return "INVALID_INDEX";
    case bm::Counter::CounterErrorCode::ERROR:
        return "GENERIC_ERROR";
    default:
        return "UNKNOWN_ERROR_CODE";
    }
}

static const char*
MeterErrorCodeToStr(bm::Meter::MeterErrorCode code)
{
    switch (code)
    {
    case bm::Meter::MeterErrorCode::SUCCESS:
        return "SUCCESS";
    case bm::Meter::MeterErrorCode::INVALID_METER_NAME:
        return "INVALID_METER_NAME";
    case bm::Meter::MeterErrorCode::INVALID_INDEX:
        return "INVALID_INDEX";
    case bm::Meter::MeterErrorCode::BAD_RATES_LIST:
        return "BAD_RATES_LIST";
    case bm::Meter::MeterErrorCode::INVALID_INFO_RATE_VALUE:
        return "INVALID_INFO_RATE_VALUE";
    case bm::Meter::MeterErrorCode::INVALID_BURST_SIZE_VALUE:
        return "INVALID_BURST_SIZE_VALUE";
    case bm::Meter::MeterErrorCode::ERROR:
        return "GENERIC_ERROR";
    default:
        return "UNKNOWN_ERROR_CODE";
    }
}

static const char*
RegisterErrorCodeToStr(bm::Register::RegisterErrorCode rc)
{
    switch (rc)
    {
    case bm::Register::RegisterErrorCode::SUCCESS:
        return "SUCCESS";
    case bm::Register::RegisterErrorCode::INVALID_REGISTER_NAME:
        return "INVALID_REGISTER_NAME";
    case bm::Register::RegisterErrorCode::INVALID_INDEX:
        return "INVALID_INDEX";
    case bm::Register::RegisterErrorCode::ERROR:
        return "ERROR";
    default:
        return "UNKNOWN_REGISTER_ERROR_CODE";
    }
}

static const char*
RuntimeErrorCodeToStr(bm::RuntimeInterface::ErrorCode rc)
{
    switch (rc)
    {
    case bm::RuntimeInterface::SUCCESS:
        return "SUCCESS";
    case bm::RuntimeInterface::CONFIG_SWAP_DISABLED:
        return "CONFIG_SWAP_DISABLED";
    case bm::RuntimeInterface::ONGOING_SWAP:
        return "ONGOING_SWAP";
    case bm::RuntimeInterface::NO_ONGOING_SWAP:
        return "NO_ONGOING_SWAP";
    default:
        return "UNKNOWN_RUNTIME_ERROR_CODE";
    }
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

    // Now we can not set the dequeue rate for each queue, later we will add this
    // feature by p4 runtime controller.
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

    uint32_t port_number = m_switchNetDevice->GetNPorts();

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

int
P4CoreV1model::GetNumEntries(const std::string& tableName)
{
    size_t num = 0;
    bm::MatchErrorCode rc = this->mt_get_num_entries(0, tableName, &num); // cxt_id = 0
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetNumEntries failed for table " << tableName);
        return -1;
    }
    return static_cast<int>(num);
}

int
P4CoreV1model::ClearFlowTableEntries(const std::string& tableName, bool resetDefault)
{
    bm::MatchErrorCode rc = this->mt_clear_entries(0, tableName, resetDefault); // cxt_id = 0
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ClearFlowTableEntries failed for table " << tableName);
        return -1;
    }
    return 0; // success
}

int
P4CoreV1model::AddFlowEntry(const std::string& tableName,
                            const std::vector<bm::MatchKeyParam>& matchKey,
                            const std::string& actionName,
                            bm::ActionData&& actionData,
                            bm::entry_handle_t* handle,
                            int priority)
{
    bm::MatchErrorCode rc = this->mt_add_entry(0, // context ID
                                               tableName,
                                               matchKey,
                                               actionName,
                                               std::move(actionData),
                                               handle,
                                               priority);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("AddFlowEntry failed for table " << tableName << ": "
                                                     << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0; // success
}

int
P4CoreV1model::SetDefaultAction(const std::string& tableName,
                                const std::string& actionName,
                                bm::ActionData&& actionData)
{
    bm::MatchErrorCode rc =
        this->mt_set_default_action(0, tableName, actionName, std::move(actionData));

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetDefaultAction failed for table " << tableName << " action " << actionName);
        NS_LOG_WARN("mt_set_default_action() failed with code: " << static_cast<int>(rc) << " ("
                                                                 << MatchErrorCodeToStr(rc) << ")");

        return -1;
    }

    return 0;
}

int
P4CoreV1model::ResetDefaultEntry(const std::string& tableName)
{
    bm::MatchErrorCode rc = this->mt_reset_default_entry(0, tableName);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ResetDefaultEntry failed for table " << tableName << " with code "
                                                          << static_cast<int>(rc) << " ("
                                                          << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0; // success
}

int
P4CoreV1model::DeleteFlowEntry(const std::string& tableName, bm::entry_handle_t handle)
{
    bm::MatchErrorCode rc = this->mt_delete_entry(0, tableName, handle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("DeleteFlowEntry failed for table " << tableName << ", handle " << handle
                                                        << ": " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4CoreV1model::ModifyFlowEntry(const std::string& tableName,
                               bm::entry_handle_t handle,
                               const std::string& actionName,
                               bm::ActionData actionData)
{
    bm::MatchErrorCode rc =
        this->mt_modify_entry(0, tableName, handle, actionName, std::move(actionData));

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ModifyFlowEntry failed for table " << tableName << ", handle " << handle
                                                        << " with code " << static_cast<int>(rc)
                                                        << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4CoreV1model::SetEntryTtl(const std::string& tableName,
                           bm::entry_handle_t handle,
                           unsigned int ttlMs)
{
    bm::MatchErrorCode rc = this->mt_set_entry_ttl(0, tableName, handle, ttlMs);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetEntryTtl failed for table " << tableName << ", handle " << handle << ": "
                                                    << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

// ======== Action Profile Operations ===========

int
P4CoreV1model::AddActionProfileMember(const std::string& profileName,
                                      const std::string& actionName,
                                      bm::ActionData&& actionData,
                                      bm::ActionProfile::mbr_hdl_t* outHandle)
{
    bm::MatchErrorCode rc =
        this->mt_act_prof_add_member(0, profileName, actionName, std::move(actionData), outHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("AddActionProfileMember failed for profile " << profileName << ", action "
                                                                 << actionName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4CoreV1model::DeleteActionProfileMember(const std::string& profileName,
                                         bm::ActionProfile::mbr_hdl_t memberHandle)
{
    bm::MatchErrorCode rc = this->mt_act_prof_delete_member(0, profileName, memberHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("DeleteActionProfileMember failed for profile "
                    << profileName << ", member handle " << memberHandle);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4CoreV1model::ModifyActionProfileMember(const std::string& profileName,
                                         bm::ActionProfile::mbr_hdl_t memberHandle,
                                         const std::string& actionName,
                                         bm::ActionData&& actionData)
{
    bm::MatchErrorCode rc = this->mt_act_prof_modify_member(0,
                                                            profileName,
                                                            memberHandle,
                                                            actionName,
                                                            std::move(actionData));

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ModifyActionProfileMember failed for profile "
                    << profileName << ", member handle " << memberHandle << ", action "
                    << actionName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4CoreV1model::CreateActionProfileGroup(const std::string& profileName,
                                        bm::ActionProfile::grp_hdl_t* outHandle)
{
    bm::MatchErrorCode rc = this->mt_act_prof_create_group(0, profileName, outHandle);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("CreateActionProfileGroup failed for profile " << profileName << ": "
                                                                   << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::DeleteActionProfileGroup(const std::string& profileName,
                                        bm::ActionProfile::grp_hdl_t groupHandle)
{
    bm::MatchErrorCode rc = this->mt_act_prof_delete_group(0, profileName, groupHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("DeleteActionProfileGroup failed for profile " << profileName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::AddMemberToGroup(const std::string& profileName,
                                bm::ActionProfile::mbr_hdl_t memberHandle,
                                bm::ActionProfile::grp_hdl_t groupHandle)
{
    bm::MatchErrorCode rc =
        this->mt_act_prof_add_member_to_group(0, profileName, memberHandle, groupHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("AddMemberToGroup failed for profile " << profileName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::RemoveMemberFromGroup(const std::string& profileName,
                                     bm::ActionProfile::mbr_hdl_t memberHandle,
                                     bm::ActionProfile::grp_hdl_t groupHandle)
{
    bm::MatchErrorCode rc =
        this->mt_act_prof_remove_member_from_group(0, profileName, memberHandle, groupHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("RemoveMemberFromGroup failed for profile " << profileName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::GetActionProfileMembers(const std::string& profileName,
                                       std::vector<bm::ActionProfile::Member>* members)
{
    *members = this->mt_act_prof_get_members(0, profileName);
    return 0;
}

int
P4CoreV1model::GetActionProfileMember(const std::string& profileName,
                                      bm::ActionProfile::mbr_hdl_t memberHandle,
                                      bm::ActionProfile::Member* member)
{
    bm::MatchErrorCode rc = this->mt_act_prof_get_member(0, profileName, memberHandle, member);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetActionProfileMember failed for profile " << profileName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::GetActionProfileGroups(const std::string& profileName,
                                      std::vector<bm::ActionProfile::Group>* groups)
{
    *groups = this->mt_act_prof_get_groups(0, profileName);
    return 0;
}

int
P4CoreV1model::GetActionProfileGroup(const std::string& profileName,
                                     bm::ActionProfile::grp_hdl_t groupHandle,
                                     bm::ActionProfile::Group* group)
{
    bm::MatchErrorCode rc = this->mt_act_prof_get_group(0, profileName, groupHandle, group);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetActionProfileGroup failed for profile "
                    << profileName << " and group handle " << groupHandle);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

// =========== Indirect Table Operations ============
int
P4CoreV1model::AddIndirectEntry(const std::string& tableName,
                                const std::vector<bm::MatchKeyParam>& matchKey,
                                bm::ActionProfile::mbr_hdl_t memberHandle,
                                bm::entry_handle_t* outHandle,
                                int priority)
{
    bm::MatchErrorCode rc =
        this->mt_indirect_add_entry(0, tableName, matchKey, memberHandle, outHandle, priority);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("AddIndirectEntry failed for table " << tableName);
        NS_LOG_WARN("mt_indirect_add_entry() failed with code: " << static_cast<int>(rc) << " ("
                                                                 << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4CoreV1model::ModifyIndirectEntry(const std::string& tableName,
                                   bm::entry_handle_t entryHandle,
                                   bm::ActionProfile::mbr_hdl_t memberHandle)
{
    bm::MatchErrorCode rc = this->mt_indirect_modify_entry(0, tableName, entryHandle, memberHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ModifyIndirectEntry failed for table " << tableName << " and entry handle "
                                                            << entryHandle);
        NS_LOG_WARN("mt_indirect_modify_entry() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4CoreV1model::DeleteIndirectEntry(const std::string& tableName, bm::entry_handle_t entryHandle)
{
    bm::MatchErrorCode rc = this->mt_indirect_delete_entry(0, tableName, entryHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("DeleteIndirectEntry failed for table " << tableName << " and entry handle "
                                                            << entryHandle);
        NS_LOG_WARN("mt_indirect_delete_entry() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4CoreV1model::SetIndirectEntryTtl(const std::string& tableName,
                                   bm::entry_handle_t handle,
                                   unsigned int ttlMs)
{
    bm::MatchErrorCode rc = this->mt_indirect_set_entry_ttl(0, tableName, handle, ttlMs);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetIndirectEntryTtl failed for table " << tableName << ", handle " << handle);
        NS_LOG_WARN("mt_indirect_set_entry_ttl() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4CoreV1model::SetIndirectDefaultMember(const std::string& tableName,
                                        bm::ActionProfile::mbr_hdl_t memberHandle)
{
    bm::MatchErrorCode rc = this->mt_indirect_set_default_member(0, tableName, memberHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetIndirectDefaultMember failed for table " << tableName << ", member "
                                                                 << memberHandle);
        NS_LOG_WARN("mt_indirect_set_default_member() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4CoreV1model::ResetIndirectDefaultEntry(const std::string& tableName)
{
    bm::MatchErrorCode rc = this->mt_indirect_reset_default_entry(0, tableName);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ResetIndirectDefaultEntry failed for table " << tableName);
        NS_LOG_WARN("mt_indirect_reset_default_entry() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4CoreV1model::AddIndirectWsEntry(const std::string& tableName,
                                  const std::vector<bm::MatchKeyParam>& matchKey,
                                  bm::ActionProfile::grp_hdl_t groupHandle,
                                  bm::entry_handle_t* outHandle,
                                  int priority)
{
    bm::MatchErrorCode rc =
        this->mt_indirect_ws_add_entry(0, tableName, matchKey, groupHandle, outHandle, priority);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("AddIndirectWsEntry failed for table " << tableName
                                                           << ", group = " << groupHandle);
        NS_LOG_WARN("mt_indirect_ws_add_entry() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4CoreV1model::ModifyIndirectWsEntry(const std::string& tableName,
                                     bm::entry_handle_t handle,
                                     bm::ActionProfile::grp_hdl_t groupHandle)
{
    bm::MatchErrorCode rc = this->mt_indirect_ws_modify_entry(0, tableName, handle, groupHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ModifyIndirectWsEntry failed for table "
                    << tableName << ", handle = " << handle << ", group = " << groupHandle);
        NS_LOG_WARN("mt_indirect_ws_modify_entry() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4CoreV1model::SetIndirectWsDefaultGroup(const std::string& tableName,
                                         bm::ActionProfile::grp_hdl_t groupHandle)
{
    bm::MatchErrorCode rc = this->mt_indirect_ws_set_default_group(0, tableName, groupHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetIndirectWsDefaultGroup failed for table " << tableName
                                                                  << ", group = " << groupHandle);
        NS_LOG_WARN("mt_indirect_ws_set_default_group() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

// ======== Flow Table Entry Retrieval Operations ===========
std::vector<bm::MatchTable::Entry>
P4CoreV1model::GetFlowEntries(const std::string& tableName)
{
    try
    {
        return this->mt_get_entries(0, tableName); // cxt_id = 0
    }
    catch (const std::exception& e)
    {
        NS_LOG_ERROR("Exception in GetFlowEntries: " << e.what());
        return {}; // empty vector
    }
}

std::vector<bm::MatchTableIndirect::Entry>
P4CoreV1model::GetIndirectFlowEntries(const std::string& tableName)
{
    try
    {
        return this->mt_indirect_get_entries(0, tableName); // cxt_id = 0
    }
    catch (const std::exception& e)
    {
        NS_LOG_ERROR("Error in GetIndirectFlowEntries: " << e.what());
        return {};
    }
}

std::vector<bm::MatchTableIndirectWS::Entry>
P4CoreV1model::GetIndirectWsFlowEntries(const std::string& tableName)
{
    try
    {
        return this->mt_indirect_ws_get_entries(0, tableName); // cxt_id = 0
    }
    catch (const std::exception& e)
    {
        NS_LOG_ERROR("Error in GetIndirectWsFlowEntries: " << e.what());
        return {};
    }
}

int
P4CoreV1model::GetEntry(const std::string& tableName,
                        bm::entry_handle_t handle,
                        bm::MatchTable::Entry* entry)
{
    bm::MatchErrorCode rc = this->mt_get_entry(0, tableName, handle, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetEntry failed for table: " << tableName << ", handle: " << handle
                                                  << ", code: " << static_cast<int>(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::GetIndirectEntry(const std::string& tableName,
                                bm::entry_handle_t handle,
                                bm::MatchTableIndirect::Entry* entry)
{
    bm::MatchErrorCode rc = this->mt_indirect_get_entry(0, tableName, handle, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetIndirectEntry failed for table: " << tableName << ", handle: " << handle
                                                          << ", code: " << static_cast<int>(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::GetIndirectWsEntry(const std::string& tableName,
                                  bm::entry_handle_t handle,
                                  bm::MatchTableIndirectWS::Entry* entry)
{
    bm::MatchErrorCode rc = this->mt_indirect_ws_get_entry(0, tableName, handle, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetIndirectWsEntry failed for table: " << tableName << ", handle: " << handle
                                                            << ", code: " << static_cast<int>(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::GetDefaultEntry(const std::string& tableName, bm::MatchTable::Entry* entry)
{
    bm::MatchErrorCode rc = this->mt_get_default_entry(0, tableName, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetDefaultEntry failed for table: " << tableName
                                                         << ", code: " << static_cast<int>(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::GetIndirectDefaultEntry(const std::string& tableName,
                                       bm::MatchTableIndirect::Entry* entry)
{
    bm::MatchErrorCode rc = this->mt_indirect_get_default_entry(0, tableName, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("Indirect default entry fn failed with code: "
                    << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }
    return 0;
}

int
P4CoreV1model::GetIndirectWsDefaultEntry(const std::string& tableName,
                                         bm::MatchTableIndirectWS::Entry* entry)
{
    bm::MatchErrorCode rc = this->mt_indirect_ws_get_default_entry(0, tableName, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetIndirectWsDefaultEntry failed for table: " << tableName << ", code: "
                                                                   << static_cast<int>(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::GetEntryFromKey(const std::string& tableName,
                               const std::vector<bm::MatchKeyParam>& matchKey,
                               bm::MatchTable::Entry* entry,
                               int priority)
{
    bm::MatchErrorCode rc = this->mt_get_entry_from_key(0, tableName, matchKey, entry, priority);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetEntryFromKey failed for table: " << tableName
                                                         << ", error: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::GetIndirectEntryFromKey(const std::string& tableName,
                                       const std::vector<bm::MatchKeyParam>& matchKey,
                                       bm::MatchTableIndirect::Entry* entry,
                                       int priority)
{
    bm::MatchErrorCode rc =
        this->mt_indirect_get_entry_from_key(0, tableName, matchKey, entry, priority);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetIndirectEntryFromKey failed for table: " << tableName << ", error: "
                                                                 << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::GetIndirectWsEntryFromKey(const std::string& tableName,
                                         const std::vector<bm::MatchKeyParam>& matchKey,
                                         bm::MatchTableIndirectWS::Entry* entry,
                                         int priority)
{
    bm::MatchErrorCode rc =
        this->mt_indirect_ws_get_entry_from_key(0, tableName, matchKey, entry, priority);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetIndirectWsEntryFromKey failed for table: " << tableName << ", error: "
                                                                   << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

// ========== Counter Operations ============
int
P4CoreV1model::ReadTableCounters(const std::string& tableName,
                                 bm::entry_handle_t handle,
                                 uint64_t* bytes,
                                 uint64_t* packets)
{
    bm::MatchErrorCode rc = this->mt_read_counters(0, tableName, handle, bytes, packets);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ReadTableCounters failed for table "
                    << tableName << ", handle " << handle
                    << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::ResetTableCounters(const std::string& tableName)
{
    bm::MatchErrorCode rc = this->mt_reset_counters(0, tableName);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ResetTableCounters failed for table "
                    << tableName << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::WriteTableCounters(const std::string& tableName,
                                  bm::entry_handle_t handle,
                                  uint64_t bytes,
                                  uint64_t packets)
{
    bm::MatchErrorCode rc = this->mt_write_counters(0, tableName, handle, bytes, packets);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("WriteTableCounters failed for table "
                    << tableName << ", handle " << handle
                    << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::ReadCounter(const std::string& counterName,
                           size_t index,
                           bm::MatchTableAbstract::counter_value_t* bytes,
                           bm::MatchTableAbstract::counter_value_t* packets)
{
    auto rc = this->read_counters(0, counterName, index, bytes, packets); // cxt_id = 0
    if (rc == bm::Counter::CounterErrorCode::SUCCESS)
    {
        NS_LOG_INFO("ReadCounter succeeded for counter [" << counterName << "] at index " << index
                                                          << ": " << *bytes << " bytes, "
                                                          << *packets << " packets");
        return 0;
    }
    else
    {
        NS_LOG_WARN("ReadCounter failed for counter ["
                    << counterName << "] at index " << index
                    << ", reason: " << CounterErrorCodeToStr(rc));
        return -1;
    }
}

int
P4CoreV1model::ResetCounter(const std::string& counterName)
{
    auto rc = this->reset_counters(0, counterName); // cxt_id = 0
    if (rc == bm::Counter::CounterErrorCode::SUCCESS)
    {
        NS_LOG_INFO("ResetCounter succeeded for counter [" << counterName << "]");
        return 0;
    }
    else
    {
        NS_LOG_WARN("ResetCounter failed for counter ["
                    << counterName << "], reason: " << CounterErrorCodeToStr(rc));
        return -1;
    }
}

int
P4CoreV1model::WriteCounter(const std::string& counterName,
                            size_t index,
                            bm::MatchTableAbstract::counter_value_t bytes,
                            bm::MatchTableAbstract::counter_value_t packets)
{
    auto rc = this->write_counters(0, counterName, index, bytes, packets); // cxt_id = 0
    if (rc == bm::Counter::CounterErrorCode::SUCCESS)
    {
        NS_LOG_INFO("WriteCounter succeeded for counter [" << counterName << "] at index " << index
                                                           << ": " << bytes << " bytes, " << packets
                                                           << " packets");
        return 0;
    }
    else
    {
        NS_LOG_WARN("WriteCounter failed for counter ["
                    << counterName << "] at index " << index
                    << ", reason: " << CounterErrorCodeToStr(rc));
        return -1;
    }
}

// ============= Meter Operations ============

int
P4CoreV1model::SetMeterRates(const std::string& tableName,
                             bm::entry_handle_t handle,
                             const std::vector<bm::Meter::rate_config_t>& configs)
{
    bm::MatchErrorCode rc = this->mt_set_meter_rates(0, tableName, handle, configs);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetMeterRates failed for table " << tableName << ", handle " << handle
                                                      << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4CoreV1model::GetMeterRates(const std::string& tableName,
                             bm::entry_handle_t handle,
                             std::vector<bm::Meter::rate_config_t>* configs)
{
    bm::MatchErrorCode rc = this->mt_get_meter_rates(0, tableName, handle, configs);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetMeterRates failed for table " << tableName << ", handle " << handle
                                                      << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4CoreV1model::ResetMeterRates(const std::string& tableName, bm::entry_handle_t handle)
{
    bm::MatchErrorCode rc = this->mt_reset_meter_rates(0, tableName, handle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ResetMeterRates failed for table " << tableName << ", handle " << handle
                                                        << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4CoreV1model::SetMeterArrayRates(const std::string& meterName,
                                  const std::vector<bm::Meter::rate_config_t>& configs)
{
    bm::Meter::MeterErrorCode rc = this->meter_array_set_rates(0, meterName, configs);

    if (rc != bm::Meter::MeterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetMeterArrayRates failed for meter "
                    << meterName << ", reason: " << MeterErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4CoreV1model::MeterSetRates(const std::string& meterName,
                             size_t idx,
                             const std::vector<bm::Meter::rate_config_t>& configs)
{
    bm::Meter::MeterErrorCode rc = this->meter_set_rates(0, meterName, idx, configs);

    if (rc != bm::Meter::MeterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetMeterRates failed for meter " << meterName << ", index " << idx
                                                      << ", reason: " << MeterErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4CoreV1model::MeterGetRates(const std::string& meterName,
                             size_t idx,
                             std::vector<bm::Meter::rate_config_t>* configs)
{
    bm::Meter::MeterErrorCode rc = this->meter_get_rates(0, meterName, idx, configs);

    if (rc != bm::Meter::MeterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetMeterRates failed for meter " << meterName << ", index " << idx
                                                      << ", reason: " << MeterErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4CoreV1model::MeterResetRates(const std::string& meterName, size_t idx)
{
    bm::Meter::MeterErrorCode rc = this->meter_reset_rates(0, meterName, idx);

    if (rc != bm::Meter::MeterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ResetMeterRates failed for meter " << meterName << ", index " << idx
                                                        << ", reason: " << MeterErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

// ============ Register Operations =============
int
P4CoreV1model::RegisterRead(const std::string& registerName, size_t index, bm::Data* value)
{
    bm::Register::RegisterErrorCode rc = this->register_read(0, registerName, index, value);
    if (rc != bm::Register::RegisterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("RegisterRead failed for register "
                    << registerName << " at index " << index
                    << " with error: " << RegisterErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::RegisterWrite(const std::string& registerName, size_t index, const bm::Data& value)
{
    bm::Register::RegisterErrorCode rc = this->register_write(0, registerName, index, value);
    if (rc != bm::Register::RegisterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("RegisterWrite failed for register "
                    << registerName << " at index " << index
                    << " with error: " << RegisterErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

std::vector<bm::Data>
P4CoreV1model::RegisterReadAll(const std::string& registerName)
{
    return this->register_read_all(0, registerName);
}

int
P4CoreV1model::RegisterWriteRange(const std::string& registerName,
                                  size_t startIndex,
                                  size_t endIndex,
                                  const bm::Data& value)
{
    bm::Register::RegisterErrorCode rc =
        this->register_write_range(0, registerName, startIndex, endIndex, value);
    if (rc != bm::Register::RegisterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("RegisterWriteRange failed for register "
                    << registerName << " from index " << startIndex << " to " << endIndex
                    << " with error: " << RegisterErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::RegisterReset(const std::string& registerName)
{
    bm::Register::RegisterErrorCode rc = this->register_reset(0, registerName);
    if (rc != bm::Register::RegisterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("RegisterReset failed for register "
                    << registerName << " with error: " << RegisterErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::ParseVsetAdd(const std::string& vsetName, const bm::ByteContainer& value)
{
    bm::ParseVSet::ErrorCode rc = this->parse_vset_add(0, vsetName, value);
    if (rc != bm::ParseVSet::SUCCESS)
    {
        NS_LOG_WARN("ParseVsetAdd failed for set '" << vsetName << "' with error code " << rc);
        return -1;
    }
    return 0;
}

int
P4CoreV1model::ParseVsetRemove(const std::string& vsetName, const bm::ByteContainer& value)
{
    bm::ParseVSet::ErrorCode rc = this->parse_vset_remove(0, vsetName, value);
    if (rc != bm::ParseVSet::SUCCESS)
    {
        NS_LOG_WARN("ParseVsetRemove failed for set '" << vsetName << "' with error code " << rc);
        return -1;
    }
    return 0;
}

int
P4CoreV1model::ParseVsetGet(const std::string& vsetName, std::vector<bm::ByteContainer>* values)
{
    bm::ParseVSet::ErrorCode rc = this->parse_vset_get(0, vsetName, values);
    if (rc != bm::ParseVSet::SUCCESS)
    {
        NS_LOG_WARN("ParseVsetGet failed for set '" << vsetName << "' with error code " << rc);
        return -1;
    }
    return 0;
}

int
P4CoreV1model::ParseVsetClear(const std::string& vsetName)
{
    bm::ParseVSet::ErrorCode rc = this->parse_vset_clear(0, vsetName);
    if (rc != bm::ParseVSet::SUCCESS)
    {
        NS_LOG_WARN("ParseVsetClear failed for set '" << vsetName << "' with error code " << rc);
        return -1;
    }
    return 0;
}

int
P4CoreV1model::ResetState()
{
    bm::RuntimeInterface::ErrorCode rc = this->reset_state();
    if (rc != bm::RuntimeInterface::SUCCESS)
    {
        NS_LOG_WARN("ResetState failed with error: " << RuntimeErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::Serialize(std::ostream* out)
{
    bm::RuntimeInterface::ErrorCode rc = this->serialize(out);
    if (rc != bm::RuntimeInterface::SUCCESS)
    {
        NS_LOG_WARN("Serialize failed with error: " << RuntimeErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::LoadNewConfig(const std::string& newConfig)
{
    bm::RuntimeInterface::ErrorCode rc = this->load_new_config(newConfig);
    if (rc != bm::RuntimeInterface::SUCCESS)
    {
        NS_LOG_WARN("LoadNewConfig failed with error: " << RuntimeErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::SwapConfigs()
{
    bm::RuntimeInterface::ErrorCode rc = this->swap_configs();
    if (rc != bm::RuntimeInterface::SUCCESS)
    {
        NS_LOG_WARN("SwapConfigs failed with error: " << RuntimeErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4CoreV1model::GetConfig(std::string* configOut)
{
    if (!configOut)
        return -1;
    *configOut = this->get_config();
    return 0;
}

int
P4CoreV1model::GetConfigMd5(std::string* md5Out)
{
    if (!md5Out)
        return -1;
    *md5Out = this->get_config_md5();
    return 0;
}

} // namespace ns3