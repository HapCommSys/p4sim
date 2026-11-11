/* Copyright 2013-present Barefoot Networks, Inc.
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
 * Author: Antonin Bas<antonin@barefootnetworks.com>
 * Modified: Mingyu Ma<mingyu.ma@tu-dresden.de>
 */

#include "ns3/p4-core-psa.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/register-access-v1model.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE("P4CorePsa");

#undef LOG_INFO
#undef LOG_ERROR
#undef LOG_DEBUG
#undef LOG_WARN
#undef LOG_LOGIC

namespace ns3
{

namespace
{

struct hash_ex_psa
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

struct bmv2_hash_psa
{
    uint64_t operator()(const char* buf, size_t s) const
    {
        return bm::hash::xxh64(buf, s);
    }
};

} // namespace

// if REGISTER_HASH calls placed in the anonymous namespace, some compiler can
// give an unused variable warning
REGISTER_HASH(hash_ex_psa);
REGISTER_HASH(bmv2_hash_psa);

P4CorePsa::P4CorePsa(P4SwitchNetDevice* net_device,
                     bool enable_swap,
                     bool enable_tracing,
                     uint64_t packet_rate,
                     size_t input_buffer_size,
                     size_t queue_buffer_size,
                     size_t nb_queues_per_port)
    : P4SwitchCore(net_device, enable_swap, enable_tracing),
      m_packetId(0),
      m_firstPacket(false),
      m_switchRate(packet_rate),
      m_nbQueuesPerPort(nb_queues_per_port),
      input_buffer(input_buffer_size),
      egress_buffer(nb_egress_threads,
                    queue_buffer_size,
                    EgressThreadMapper(nb_egress_threads),
                    nb_queues_per_port),
      output_buffer(SSWITCH_VIRTUAL_QUEUE_NUM_PSA)
{
    // configure for the switch v1model
    m_thriftCommand = "psa_switch_CLI"; // default thrift command for v1model
    m_enableQueueingMetadata = true;    // enable queueing metadata for v1model

    add_component<bm::McSimplePreLAG>(m_pre);

    add_required_field("psa_ingress_parser_input_metadata", "ingress_port");
    add_required_field("psa_ingress_parser_input_metadata", "packet_path");

    add_required_field("psa_ingress_input_metadata", "ingress_port");
    add_required_field("psa_ingress_input_metadata", "packet_path");
    add_required_field("psa_ingress_input_metadata", "ingress_timestamp");
    add_required_field("psa_ingress_input_metadata", "parser_error");

    add_required_field("psa_ingress_output_metadata", "class_of_service");
    add_required_field("psa_ingress_output_metadata", "clone");
    add_required_field("psa_ingress_output_metadata", "clone_session_id");
    add_required_field("psa_ingress_output_metadata", "drop");
    add_required_field("psa_ingress_output_metadata", "resubmit");
    add_required_field("psa_ingress_output_metadata", "multicast_group");
    add_required_field("psa_ingress_output_metadata", "egress_port");

    add_required_field("psa_egress_parser_input_metadata", "egress_port");
    add_required_field("psa_egress_parser_input_metadata", "packet_path");

    add_required_field("psa_egress_input_metadata", "class_of_service");
    add_required_field("psa_egress_input_metadata", "egress_port");
    add_required_field("psa_egress_input_metadata", "packet_path");
    add_required_field("psa_egress_input_metadata", "instance");
    add_required_field("psa_egress_input_metadata", "egress_timestamp");
    add_required_field("psa_egress_input_metadata", "parser_error");

    add_required_field("psa_egress_output_metadata", "clone");
    add_required_field("psa_egress_output_metadata", "clone_session_id");
    add_required_field("psa_egress_output_metadata", "drop");

    add_required_field("psa_egress_deparser_input_metadata", "egress_port");

    force_arith_header("psa_ingress_parser_input_metadata");
    force_arith_header("psa_ingress_input_metadata");
    force_arith_header("psa_ingress_output_metadata");
    force_arith_header("psa_egress_parser_input_metadata");
    force_arith_header("psa_egress_input_metadata");
    force_arith_header("psa_egress_output_metadata");
    force_arith_header("psa_egress_deparser_input_metadata");

    CalculateScheduleTime();
}

P4CorePsa::~P4CorePsa()
{
    NS_LOG_FUNCTION(this << " Switch ID: " << m_p4SwitchId);
    input_buffer.push_front(nullptr);
    for (size_t i = 0; i < nb_egress_threads; i++)
    {
        egress_buffer.push_front(i, 0, nullptr);
    }
    output_buffer.push_front(nullptr);
}

void
P4CorePsa::start_and_return_()
{
    NS_LOG_FUNCTION("Switch ID: " << m_p4SwitchId << " start");
    CheckQueueingMetadata();

    if (!m_egressTimeRef.IsZero())
    {
        NS_LOG_DEBUG("Switch ID: " << m_p4SwitchId
                                   << " Scheduling initial timer event using m_egressTimeRef = "
                                   << m_egressTimeRef.GetNanoSeconds() << " ns");
        m_egressTimeEvent =
            Simulator::Schedule(m_egressTimeRef, &P4CorePsa::SetEgressTimerEvent, this);
    }
}

void
P4CorePsa::SetEgressTimerEvent()
{
    NS_LOG_FUNCTION("p4_switch has been triggered by the egress timer event");
    bool checkflag = HandleEgressPipeline(0);
    m_egressTimeEvent = Simulator::Schedule(m_egressTimeRef, &P4CorePsa::SetEgressTimerEvent, this);
    if (!m_firstPacket && checkflag)
    {
        m_firstPacket = true;
    }
    if (m_firstPacket && !checkflag)
    {
        NS_LOG_INFO("Egress timer event needs additional scheduling due to !checkflag.");
        Simulator::Schedule(Time(NanoSeconds(10)), &P4CorePsa::HandleEgressPipeline, this, 0);
    }
}

void
P4CorePsa::swap_notify_()
{
    NS_LOG_FUNCTION("p4_switch has been notified of a config swap");
    CheckQueueingMetadata();
}

void
P4CorePsa::reset_target_state_()
{
    NS_LOG_DEBUG("Resetting simple_switch target-specific state");
    get_component<bm::McSimplePreLAG>()->reset_state();
}

int
P4CorePsa::ReceivePacket(Ptr<Packet> packetIn,
                         int inPort,
                         uint16_t protocol,
                         const Address& destination)
{
    NS_LOG_FUNCTION(this);
    std::unique_ptr<bm::Packet> bm_packet = ConvertToBmPacket(packetIn, inPort);

    bm::PHV* phv = bm_packet->get_phv();
    int len = bm_packet.get()->get_data_size();
    bm_packet.get()->set_ingress_port(inPort);

    // many current p4 programs assume this
    // from psa spec - PSA does not mandate initialization of user-defined
    // metadata to known values as given as input to the ingress parser
    phv->reset_metadata();

    // setting ns3 specific metadata in packet register
    RegisterAccess::clear_all(bm_packet.get());
    RegisterAccess::set_ns_protocol(bm_packet.get(), protocol);
    int addr_index = GetAddressIndex(destination);
    RegisterAccess::set_ns_address(bm_packet.get(), addr_index);

    // TODO use appropriate enum member from JSON
    phv->get_field("psa_ingress_parser_input_metadata.packet_path").set(PACKET_PATH_NORMAL);
    phv->get_field("psa_ingress_parser_input_metadata.ingress_port").set(inPort);

    // using packet register 0 to store length, this register will be updated for
    // each add_header / remove_header primitive call
    bm_packet->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, len);

    input_buffer.push_front(std::move(bm_packet));
    // input_buffer.push_front (InputBuffer::PacketType::NORMAL, std::move (bm_packet));
    HandleIngressPipeline();
    NS_LOG_DEBUG("Packet received by P4CorePsa, Port: " << inPort << ", Packet ID: " << m_packetId
                                                        << ", Size: " << len << " bytes");
    return 0;
}

void
P4CorePsa::Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet)
{
    packet->set_egress_port(egress_port);

    bm::PHV* phv = packet->get_phv();

    auto priority = phv->has_field("intrinsic_metadata.priority")
                        ? phv->get_field("intrinsic_metadata.priority").get<size_t>()
                        : 0u;
    if (priority >= m_nbQueuesPerPort)
    {
        NS_LOG_ERROR("Priority out of range, dropping packet");
        return;
    }

    egress_buffer.push_front(egress_port, m_nbQueuesPerPort - 1 - priority, std::move(packet));
    NS_LOG_DEBUG("Packet enqueued in P4QueueDisc, Port: " << egress_port
                                                          << ", Priority: " << priority);
}

void
P4CorePsa::HandleIngressPipeline()
{
    NS_LOG_FUNCTION(this);

    std::unique_ptr<bm::Packet> bm_packet;
    input_buffer.pop_back(&bm_packet);
    if (bm_packet == nullptr)
        return;

    bm::PHV* phv = bm_packet->get_phv();

    auto ingress_port = phv->get_field("psa_ingress_parser_input_metadata.ingress_port").get_uint();

    NS_LOG_INFO("Processing packet from port "
                << ingress_port << ", Packet ID: " << bm_packet->get_packet_id()
                << ", Size: " << bm_packet->get_data_size() << " bytes");

    /* Ingress cloning and resubmitting work on the packet before parsing.
         `buffer_state` contains the `data_size` field which tracks how many
         bytes are parsed by the parser ("lifted" into p4 headers). Here, we
         track the buffer_state prior to parsing so that we can put it back
         for packets that are cloned or resubmitted, same as in simple_switch.cpp
      */
    const bm::Packet::buffer_state_t packet_in_state = bm_packet->save_buffer_state();
    auto ingress_packet_size = bm_packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);

    // The PSA specification says that for all packets, whether they
    // are new ones from a port, or resubmitted, or recirculated, the
    // ingress_timestamp should be the time near when the packet began
    // ingress processing.  This one place for assigning a value to
    // ingress_timestamp covers all cases.
    phv->get_field("psa_ingress_input_metadata.ingress_timestamp").set(GetTimeStamp());

    bm::Parser* parser = this->get_parser("ingress_parser");
    parser->parse(bm_packet.get());

    // pass relevant values from ingress parser
    // ingress_timestamp is already set above
    phv->get_field("psa_ingress_input_metadata.ingress_port")
        .set(phv->get_field("psa_ingress_parser_input_metadata.ingress_port"));
    phv->get_field("psa_ingress_input_metadata.packet_path")
        .set(phv->get_field("psa_ingress_parser_input_metadata.packet_path"));
    phv->get_field("psa_ingress_input_metadata.parser_error")
        .set(bm_packet->get_error_code().get());

    // set default metadata values according to PSA specification
    phv->get_field("psa_ingress_output_metadata.class_of_service").set(0);
    phv->get_field("psa_ingress_output_metadata.clone").set(0);
    phv->get_field("psa_ingress_output_metadata.drop").set(1);
    phv->get_field("psa_ingress_output_metadata.resubmit").set(0);
    phv->get_field("psa_ingress_output_metadata.multicast_group").set(0);

    bm::Pipeline* ingress_mau = this->get_pipeline("ingress");
    ingress_mau->apply(bm_packet.get());
    bm_packet->reset_exit();

    const auto& f_ig_cos = phv->get_field("psa_ingress_output_metadata.class_of_service");
    const auto ig_cos = f_ig_cos.get_uint();

    // ingress cloning - each cloned packet is a copy of the packet as it entered the ingress parser
    //                 - dropped packets should still be cloned - do not move below drop
    auto clone = phv->get_field("psa_ingress_output_metadata.clone").get_uint();
    if (clone)
    {
        MirroringSessionConfig config;
        auto clone_session_id =
            phv->get_field("psa_ingress_output_metadata.clone_session_id").get<int>();
        auto is_session_configured = GetMirroringSession(clone_session_id, &config);

        if (is_session_configured)
        {
            NS_LOG_DEBUG("Cloning packet at ingress to session id " << clone_session_id);
            const bm::Packet::buffer_state_t packet_out_state = bm_packet->save_buffer_state();
            bm_packet->restore_buffer_state(packet_in_state);

            std::unique_ptr<bm::Packet> packet_copy = bm_packet->clone_no_phv_ptr();
            packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, ingress_packet_size);
            auto phv_copy = packet_copy->get_phv();
            phv_copy->reset_metadata();
            phv_copy->get_field("psa_egress_parser_input_metadata.packet_path")
                .set(PACKET_PATH_CLONE_I2E);

            if (config.mgid_valid)
            {
                NS_LOG_DEBUG("Cloning packet to multicast group " << config.mgid);
                // TODO 0 as the last arg (for class_of_service) is currently a placeholder
                // implement cos into cloning session configs
                MultiCastPacket(packet_copy.get(), config.mgid, PACKET_PATH_CLONE_I2E, 0);
            }

            if (config.egress_port_valid)
            {
                NS_LOG_DEBUG("Cloning packet to egress port " << config.egress_port);
                Enqueue(config.egress_port, std::move(packet_copy));
            }

            bm_packet->restore_buffer_state(packet_out_state);
        }
        else
        {
            //   BMLOG_DEBUG_PKT (*packet,
            //                    "Cloning packet at ingress to unconfigured session id {} causes no
            //                    " "clone packets to be created", clone_session_id);
            NS_LOG_DEBUG("Cloning packet at ingress to unconfigured session id "
                         << clone_session_id << " causes no clone packets to be created");
        }
    }

    // drop - packets marked via the ingress_drop action
    auto drop = phv->get_field("psa_ingress_output_metadata.drop").get_uint();
    if (drop)
    {
        NS_LOG_DEBUG("Dropping packet at the end of ingress");
        return;
    }

    // resubmit - these packets get immediately resub'd to ingress, and skip
    //            deparsing, do not move below multicast or deparse
    auto resubmit = phv->get_field("psa_ingress_output_metadata.resubmit").get_uint();
    if (resubmit)
    {
        NS_LOG_DEBUG("Resubmitting packet");

        bm_packet->restore_buffer_state(packet_in_state);
        phv->reset_metadata();
        phv->get_field("psa_ingress_parser_input_metadata.packet_path").set(PACKET_PATH_RESUBMIT);

        // input_buffer.push_front (InputBuffer::PacketType::RESUBMIT, std::move (bm_packet));
        input_buffer.push_front(std::move(bm_packet));
        HandleIngressPipeline();
        return;
    }

    bm::Deparser* deparser = this->get_deparser("ingress_deparser");
    deparser->deparse(bm_packet.get());

    auto& f_packet_path = phv->get_field("psa_egress_parser_input_metadata.packet_path");

    auto mgid = phv->get_field("psa_ingress_output_metadata.multicast_group").get_uint();
    if (mgid != 0)
    {
        //   BMLOG_DEBUG_PKT (*bm_packet, "Multicast requested for packet with multicast group {}",
        //   mgid);
        NS_LOG_DEBUG("Multicast requested for packet with multicast group " << mgid);
        // MulticastPacket (packet_copy.get (), config.mgid);
        MultiCastPacket(bm_packet.get(), mgid, PACKET_PATH_NORMAL_MULTICAST, ig_cos);
        return;
    }

    auto& f_instance = phv->get_field("psa_egress_input_metadata.instance");
    auto& f_eg_cos = phv->get_field("psa_egress_input_metadata.class_of_service");
    f_instance.set(0);
    // TODO use appropriate enum member from JSON
    f_eg_cos.set(ig_cos);

    f_packet_path.set(PACKET_PATH_NORMAL_UNICAST);
    auto egress_port = phv->get_field("psa_ingress_output_metadata.egress_port").get<uint32_t>();

    NS_LOG_DEBUG("Egress port is " << egress_port);
    Enqueue(egress_port, std::move(bm_packet));
}

bool
P4CorePsa::HandleEgressPipeline(size_t worker_id)
{
    NS_LOG_FUNCTION("Dequeue packet from QueueBuffer");
    std::unique_ptr<bm::Packet> bm_packet;
    size_t port;
    size_t priority;

    int queue_number = SSWITCH_VIRTUAL_QUEUE_NUM_PSA;

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

    egress_buffer.pop_back(worker_id, &port, &priority, &bm_packet);
    if (bm_packet == nullptr)
        return false;

    NS_LOG_FUNCTION("Egress processing for the packet");
    bm::PHV* phv = bm_packet->get_phv();

    // this reset() marks all headers as invalid - this is important since PSA
    // deparses packets after ingress processing - so no guarantees can be made
    // about their existence or validity while entering egress processing
    phv->reset();
    phv->get_field("psa_egress_parser_input_metadata.egress_port").set(port);
    phv->get_field("psa_egress_input_metadata.egress_timestamp").set(GetTimeStamp());

    bm::Parser* parser = this->get_parser("egress_parser");
    parser->parse(bm_packet.get());

    phv->get_field("psa_egress_input_metadata.egress_port")
        .set(phv->get_field("psa_egress_parser_input_metadata.egress_port"));
    phv->get_field("psa_egress_input_metadata.packet_path")
        .set(phv->get_field("psa_egress_parser_input_metadata.packet_path"));
    phv->get_field("psa_egress_input_metadata.parser_error").set(bm_packet->get_error_code().get());

    // default egress output values according to PSA spec
    // clone_session_id is undefined by default
    phv->get_field("psa_egress_output_metadata.clone").set(0);
    phv->get_field("psa_egress_output_metadata.drop").set(0);

    bm::Pipeline* egress_mau = this->get_pipeline("egress");
    egress_mau->apply(bm_packet.get());
    bm_packet->reset_exit();
    // TODO(peter): add stf test where exit is invoked but packet still gets recirc'd
    phv->get_field("psa_egress_deparser_input_metadata.egress_port")
        .set(phv->get_field("psa_egress_parser_input_metadata.egress_port"));

    bm::Deparser* deparser = this->get_deparser("egress_deparser");
    deparser->deparse(bm_packet.get());

    // egress cloning - each cloned packet is a copy of the packet as output by the egress deparser
    auto clone = phv->get_field("psa_egress_output_metadata.clone").get_uint();
    if (clone)
    {
        MirroringSessionConfig config;
        auto clone_session_id =
            phv->get_field("psa_egress_output_metadata.clone_session_id").get<int>();
        auto is_session_configured = GetMirroringSession(clone_session_id, &config);

        if (is_session_configured)
        {
            NS_LOG_DEBUG("Cloning packet after egress to session id " << clone_session_id);
            std::unique_ptr<bm::Packet> packet_copy = bm_packet->clone_no_phv_ptr();
            auto phv_copy = packet_copy->get_phv();
            phv_copy->reset_metadata();
            phv_copy->get_field("psa_egress_parser_input_metadata.packet_path")
                .set(PACKET_PATH_CLONE_E2E);

            if (config.mgid_valid)
            {
                NS_LOG_DEBUG("Cloning packet to multicast group " << config.mgid);
                // TODO 0 as the last arg (for class_of_service) is currently a placeholder
                // implement cos into cloning session configs
                MultiCastPacket(packet_copy.get(), config.mgid, PACKET_PATH_CLONE_E2E, 0);
            }

            if (config.egress_port_valid)
            {
                NS_LOG_DEBUG("Cloning packet to egress port " << config.egress_port);
                Enqueue(config.egress_port, std::move(packet_copy));
            }
        }
        else
        {
            NS_LOG_DEBUG("Cloning packet after egress to unconfigured session id "
                         << clone_session_id << " causes no clone packets to be created");
        }
    }

    auto drop = phv->get_field("psa_egress_output_metadata.drop").get_uint();
    if (drop)
    {
        NS_LOG_DEBUG("Dropping packet at the end of egress");
        return true;
    }

    if (port == PSA_PORT_RECIRCULATE)
    {
        NS_LOG_DEBUG("Recirculating packet");

        phv->reset();
        phv->reset_header_stacks();
        phv->reset_metadata();

        phv->get_field("psa_ingress_parser_input_metadata.ingress_port").set(PSA_PORT_RECIRCULATE);
        phv->get_field("psa_ingress_parser_input_metadata.packet_path")
            .set(PACKET_PATH_RECIRCULATE);
        // input_buffer.push_front (InputBuffer::PacketType::RECIRCULATE, std::move (bm_packet));
        input_buffer.push_front(std::move(bm_packet));
        HandleIngressPipeline();
        return true;
    }

    uint16_t protocol = RegisterAccess::get_ns_protocol(bm_packet.get());
    int addr_index = RegisterAccess::get_ns_address(bm_packet.get());

    Ptr<Packet> ns_packet = this->ConvertToNs3Packet(std::move(bm_packet));
    m_switchNetDevice->SendNs3Packet(ns_packet, port, protocol, m_destinationList[addr_index]);
    return true;
}

void
P4CorePsa::MultiCastPacket(bm::Packet* packet,
                           unsigned int mgid,
                           PktInstanceTypePsa path,
                           unsigned int class_of_service)
{
    auto phv = packet->get_phv();
    const auto pre_out = m_pre->replicate({mgid});
    auto& f_eg_cos = phv->get_field("psa_egress_input_metadata.class_of_service");
    auto& f_instance = phv->get_field("psa_egress_input_metadata.instance");
    auto& f_packet_path = phv->get_field("psa_egress_parser_input_metadata.packet_path");
    auto packet_size = packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);
    for (const auto& out : pre_out)
    {
        auto egress_port = out.egress_port;
        auto instance = out.rid;
        NS_LOG_DEBUG("Replicating packet on port " << egress_port << " with instance " << instance);
        f_eg_cos.set(class_of_service);
        f_instance.set(instance);
        // TODO use appropriate enum member from JSON
        f_packet_path.set(path);
        std::unique_ptr<bm::Packet> packet_copy = packet->clone_with_phv_ptr();
        packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, packet_size);
        Enqueue(egress_port, std::move(packet_copy));
    }
}

void
P4CorePsa::CalculateScheduleTime()
{
    m_egressTimeEvent = EventId();

    uint64_t bottleneck_ns = 1e9 / m_switchRate;
    egress_buffer.set_rate_for_all(m_switchRate);
    m_egressTimeRef = Time::FromDouble(bottleneck_ns, Time::NS);

    NS_LOG_DEBUG("Switch ID: " << m_p4SwitchId << " Egress time reference set to " << bottleneck_ns
                               << " ns (" << m_egressTimeRef.GetNanoSeconds() << " [ns])");
}

int
P4CorePsa::SetEgressPriorityQueueDepth(size_t port, size_t priority, const size_t depth_pkts)
{
    egress_buffer.set_capacity(port, priority, depth_pkts);
    return 0;
}

int
P4CorePsa::SetEgressQueueDepth(size_t port, const size_t depth_pkts)
{
    egress_buffer.set_capacity(port, depth_pkts);
    return 0;
}

int
P4CorePsa::SetAllEgressQueueDepths(const size_t depth_pkts)
{
    egress_buffer.set_capacity_for_all(depth_pkts);
    return 0;
}

int
P4CorePsa::SetEgressPriorityQueueRate(size_t port, size_t priority, const uint64_t rate_pps)
{
    egress_buffer.set_rate(port, priority, rate_pps);
    return 0;
}

int
P4CorePsa::SetEgressQueueRate(size_t port, const uint64_t rate_pps)
{
    egress_buffer.set_rate(port, rate_pps);
    return 0;
}

int
P4CorePsa::SetAllEgressQueueRates(const uint64_t rate_pps)
{
    egress_buffer.set_rate_for_all(rate_pps);
    return 0;
}

} // namespace ns3
