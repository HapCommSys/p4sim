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

#include "ns3/data-rate.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/register-access-v1model.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE("P4CorePsa");

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
    NS_LOG_FUNCTION("Switch ID: " << m_p4SwitchId << " start (event-driven scheduler)");
    CheckQueueingMetadata();
    // The event-driven scheduler is triggered on-demand from Enqueue().
    // No initial polling event is scheduled.
}

// ---------------------------------------------------------------------------
// Legacy polling callback – retained for reference, no longer scheduled.
// ---------------------------------------------------------------------------
void
P4CorePsa::SetEgressTimerEvent()
{
    NS_LOG_FUNCTION("p4_switch has been triggered by the egress timer event (legacy)");
    bool checkflag = HandleEgressPipeline(0);
    m_egressTimeEvent = Simulator::Schedule(m_egressTimeRef, &P4CorePsa::SetEgressTimerEvent, this);
    if (!m_firstPacket && checkflag)
        m_firstPacket = true;
    if (m_firstPacket && !checkflag)
    {
        NS_LOG_INFO("Egress timer event needs additional scheduling due to !checkflag.");
        Simulator::Schedule(Time(NanoSeconds(10)), &P4CorePsa::HandleEgressPipeline, this, 0);
    }
}

// ---------------------------------------------------------------------------
// Event-driven scheduler
// ---------------------------------------------------------------------------

void
P4CorePsa::ScheduleEgressIfNeeded(uint32_t port)
{
    NS_LOG_FUNCTION(this << port);

    auto& pstate = m_portTxState[port];

    // Port busy: PortTxComplete() will re-trigger when the link is free.
    if (pstate.busy)
    {
        NS_LOG_DEBUG("PSA port " << port << " busy until " << pstate.busyUntil.GetNanoSeconds()
                                 << " ns – deferring");
        return;
    }

    // Cancel any stale pending event and reschedule for the tightest time.
    if (pstate.pendingEvent.IsRunning())
    {
        Simulator::Cancel(pstate.pendingEvent);
        pstate.pendingEvent = EventId();
    }

    Time now = Simulator::Now();
    Time nextEligible = egress_buffer.get_next_tp_all_ports();

    if (nextEligible == Time::Max())
    {
        NS_LOG_DEBUG("PSA port " << port << ": all queues empty, not scheduling dequeue");
        return;
    }

    Time delay = (nextEligible > now) ? (nextEligible - now) : Time(0);

    NS_LOG_DEBUG("PSA port " << port << ": scheduling dequeue in " << delay.GetNanoSeconds()
                             << " ns");

    pstate.pendingEvent =
        Simulator::Schedule(delay, &P4CorePsa::EventDrivenEgressDequeue, this, port);
}

void
P4CorePsa::EventDrivenEgressDequeue(uint32_t port)
{
    NS_LOG_FUNCTION(this << port);

    auto& pstate = m_portTxState[port];
    pstate.pendingEvent = EventId();

    if (pstate.busy)
    {
        NS_LOG_DEBUG("PSA port " << port << " still busy – PortTxComplete will retry");
        return;
    }

    // Try to pop a rate-eligible packet.
    std::unique_ptr<bm::Packet> bm_packet;
    size_t out_port = 0;
    size_t priority = 0;

    egress_buffer.pop_back(0 /* workerId */, &out_port, &priority, &bm_packet);

    if (!bm_packet)
    {
        NS_LOG_DEBUG("PSA port " << port << ": no eligible packet right now");
        Time now = Simulator::Now();
        Time nextEligible = egress_buffer.get_next_tp_all_ports();
        // Only reschedule if there are actually queued packets for this port;
        // get_next_tp_all_ports() returns now+5s as a sentinel when all queues
        // are empty, which must not be treated as a real future deadline.
        if (nextEligible != Time::Max() && nextEligible > now)
        {
            pstate.pendingEvent = Simulator::Schedule(nextEligible - now,
                                                      &P4CorePsa::EventDrivenEgressDequeue,
                                                      this,
                                                      port);
        }
        return;
    }

    // Bug-fix: pop_back() is global – the dequeued packet may belong to any
    // port, not necessarily 'port'.  All state from here on must be keyed on
    // out_port.
    auto& out_pstate = m_portTxState[static_cast<uint32_t>(out_port)];
    if (out_pstate.busy)
    {
        NS_LOG_WARN("PSA port " << out_port << " busy when dequeued from port " << port
                                << " scheduler – packet lost");
        return;
    }

    // ---- Run the PSA egress pipeline ----
    NS_LOG_FUNCTION("PSA egress processing for dequeued packet");
    bm::PHV* phv = bm_packet->get_phv();

    phv->reset();
    phv->get_field("psa_egress_parser_input_metadata.egress_port").set(out_port);
    phv->get_field("psa_egress_input_metadata.egress_timestamp").set(GetTimeStamp());

    bm::Parser* parser = this->get_parser("egress_parser");
    parser->parse(bm_packet.get());

    phv->get_field("psa_egress_input_metadata.egress_port")
        .set(phv->get_field("psa_egress_parser_input_metadata.egress_port"));
    phv->get_field("psa_egress_input_metadata.packet_path")
        .set(phv->get_field("psa_egress_parser_input_metadata.packet_path"));
    phv->get_field("psa_egress_input_metadata.parser_error").set(bm_packet->get_error_code().get());

    phv->get_field("psa_egress_output_metadata.clone").set(0);
    phv->get_field("psa_egress_output_metadata.drop").set(0);

    bm::Pipeline* egress_mau = this->get_pipeline("egress");
    egress_mau->apply(bm_packet.get());
    bm_packet->reset_exit();

    phv->get_field("psa_egress_deparser_input_metadata.egress_port")
        .set(phv->get_field("psa_egress_parser_input_metadata.egress_port"));

    bm::Deparser* deparser = this->get_deparser("egress_deparser");
    deparser->deparse(bm_packet.get());

    // EGRESS CLONING
    auto clone = phv->get_field("psa_egress_output_metadata.clone").get_uint();
    if (clone)
    {
        MirroringSessionConfig config;
        auto clone_session_id =
            phv->get_field("psa_egress_output_metadata.clone_session_id").get<int>();
        if (GetMirroringSession(clone_session_id, &config))
        {
            NS_LOG_DEBUG("PSA: cloning packet after egress to session " << clone_session_id);
            std::unique_ptr<bm::Packet> packet_copy = bm_packet->clone_no_phv_ptr();
            auto phv_copy = packet_copy->get_phv();
            phv_copy->reset_metadata();
            phv_copy->get_field("psa_egress_parser_input_metadata.packet_path")
                .set(PACKET_PATH_CLONE_E2E);
            if (config.mgid_valid)
                MultiCastPacket(packet_copy.get(), config.mgid, PACKET_PATH_CLONE_E2E, 0);
            if (config.egress_port_valid)
                Enqueue(config.egress_port, std::move(packet_copy));
        }
        else
        {
            NS_LOG_DEBUG("PSA: clone to unconfigured session " << clone_session_id
                                                               << " – no clone created");
        }
    }

    // DROP
    auto drop = phv->get_field("psa_egress_output_metadata.drop").get_uint();
    if (drop)
    {
        NS_LOG_DEBUG("PSA: dropping packet at end of egress");
        PortTxComplete(static_cast<uint32_t>(out_port));
        return;
    }

    // RECIRCULATE
    if (out_port == PSA_PORT_RECIRCULATE)
    {
        NS_LOG_DEBUG("PSA: recirculating packet");
        phv->reset();
        phv->reset_header_stacks();
        phv->reset_metadata();
        phv->get_field("psa_ingress_parser_input_metadata.ingress_port").set(PSA_PORT_RECIRCULATE);
        phv->get_field("psa_ingress_parser_input_metadata.packet_path")
            .set(PACKET_PATH_RECIRCULATE);
        input_buffer.push_front(std::move(bm_packet));
        HandleIngressPipeline();
        PortTxComplete(static_cast<uint32_t>(out_port));
        return;
    }

    // ---- Model link serialisation delay ----
    int pkt_bytes = static_cast<int>(bm_packet->get_data_size());
    uint64_t tx_ns = (m_linkRateBps > 0)
                         ? (static_cast<uint64_t>(pkt_bytes) * 8ULL * 1000000000ULL / m_linkRateBps)
                         : 0ULL;
    Time txDelay = NanoSeconds(tx_ns);

    out_pstate.busy = true;
    out_pstate.busyUntil = Simulator::Now() + txDelay;

    NS_LOG_DEBUG("PSA port " << out_port << ": transmitting " << pkt_bytes
                             << " B, tx delay = " << tx_ns << " ns");

    uint16_t protocol = RegisterAccess::get_ns_protocol(bm_packet.get());
    int addr_index = RegisterAccess::get_ns_address(bm_packet.get());
    Ptr<Packet> ns_packet = this->ConvertToNs3Packet(std::move(bm_packet));
    m_switchNetDevice->SendNs3Packet(ns_packet,
                                     static_cast<int>(out_port),
                                     protocol,
                                     m_destinationList[addr_index]);

    Simulator::Schedule(txDelay, &P4CorePsa::PortTxComplete, this, static_cast<uint32_t>(out_port));
}

void
P4CorePsa::PortTxComplete(uint32_t port)
{
    NS_LOG_FUNCTION(this << port);
    auto& pstate = m_portTxState[port];
    pstate.busy = false;

    if (egress_buffer.size(port) > 0)
    {
        NS_LOG_DEBUG("PSA port " << port << ": PortTxComplete – more packets queued");
        ScheduleEgressIfNeeded(port);
    }
    else
    {
        NS_LOG_DEBUG("PSA port " << port << ": PortTxComplete – queue empty, port idle");
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
    NS_LOG_DEBUG("PSA packet enqueued, Port: " << egress_port << ", Priority: " << priority);

    // Event-driven scheduler: trigger a dequeue attempt for this port.
    ScheduleEgressIfNeeded(egress_port);
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
    NS_LOG_FUNCTION("PSA HandleEgressPipeline (delegates to event-driven dequeue)");

    // Quick check: any queue non-empty?
    int queue_number = SSWITCH_VIRTUAL_QUEUE_NUM_PSA;
    bool any_queued = false;
    for (int i = 0; i < queue_number; i++)
    {
        if (egress_buffer.size(i) > 0)
        {
            any_queued = true;
            break;
        }
    }
    if (!any_queued)
        return false;

    // Delegate to event-driven path (UINT32_MAX = any port).
    EventDrivenEgressDequeue(UINT32_MAX);
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

    // Compute inter-packet gap from the configured switch rate.
    // This is still used as the per-queue rate in egress_buffer.
    uint64_t bottleneck_ns = 1e9 / m_switchRate;
    egress_buffer.set_rate_for_all(m_switchRate);
    m_egressTimeRef = Time::FromDouble(bottleneck_ns, Time::NS);

    // Try to obtain the physical link rate from the first bridge port so that
    // the event-driven scheduler can model per-packet transmission delay
    // accurately.  Fall back to 1 Gbps if no port is attached yet.
    if (m_switchNetDevice && m_switchNetDevice->GetNPorts() > 0)
    {
        Ptr<SwitchedEthernetChannel> ch = m_switchNetDevice->GetPortChannel(0);
        if (ch)
        {
            m_linkRateBps = ch->GetDataRate().GetBitRate();
            NS_LOG_INFO("PSA Switch ID "
                        << m_p4SwitchId << ": link rate from port 0 = " << m_linkRateBps << " bps");
        }
        else
        {
            NS_LOG_DEBUG("PSA Switch ID " << m_p4SwitchId
                                          << ": no channel on port 0; using default 1 Gbps");
        }
    }

    NS_LOG_DEBUG("Switch ID: " << m_p4SwitchId << " Egress time reference set to " << bottleneck_ns
                               << " ns (" << m_egressTimeRef.GetNanoSeconds() << " [ns])"
                               << ", link rate = " << m_linkRateBps << " bps");
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
