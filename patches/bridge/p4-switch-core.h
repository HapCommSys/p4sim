/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018 Stanford University
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
 * Authors: Stephen Ibanez <sibanez@stanford.edu>
 *          Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#ifndef P4_SWITCH_CORE_H
#define P4_SWITCH_CORE_H

#include "fifo-queue-disc.h"
#include "standard-metadata-tag.h"
#include "traffic-control/p4-input-queue-buffer.h"
#include "traffic-control/p4-queue-disc.h"

#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/switch.h>

namespace ns3
{


struct PacketInfo
    {
        int inPort,
        uint16_t protocol;
        Address destination;
        int64_t packet_id;
    };

enum class PacketType
    {
        NORMAL,
        RESUBMIT,
        RECIRCULATE,
        SENTINEL // signal for the ingress thread to terminate
    };

std::string PacketTypeToString(PacketType type)
{
    switch (type)
    {
    case PacketType::CONTROL:
        return "CONTROL";
    case PacketType::DATA:
        return "DATA";
    case PacketType::MANAGEMENT:
        return "MANAGEMENT";
    default:
        return "UNKNOWN";
    }
}

/**
 * \ingroup p4-pipeline
 *
 * Base class for a P4 programmable pipeline.
 */
class P4Switch : public bm::Switch
{
  public:
    // by default, swapping is off
    P4Switch(P4NetDevice* netDevice,
             bool enable_swap = false,
             port_t drop_port = default_drop_port,
             size_t nb_queues_per_port = default_nb_queues_per_port);

    ~P4Switch();

    /**
     * \brief Run the provided CLI commands to populate table entries
     */
    void run_cli(std::string commandsFile);

    /**
     * \brief Unused
     */
    int receive_(port_t port_num, const char* buffer, int len) override;

    /**
     * \brief Unused
     */
    void start_and_return_() override;

    // void reset_target_state_() override;

    // void swap_notify_() override;

    // bool mirroring_add_session(mirror_id_t mirror_id, const MirroringSessionConfig& config);

    // bool mirroring_delete_session(mirror_id_t mirror_id);

    // bool mirroring_get_session(mirror_id_t mirror_id, MirroringSessionConfig* config) const;
    // int set_egress_priority_queue_depth(size_t port, size_t priority, const size_t depth_pkts);
    // int set_egress_queue_depth(size_t port, const size_t depth_pkts);
    // int set_all_egress_queue_depths(const size_t depth_pkts);

    // int set_egress_priority_queue_rate(size_t port, size_t priority, const uint64_t rate_pps);
    // int set_egress_queue_rate(size_t port, const uint64_t rate_pps);
    // int set_all_egress_queue_rates(const uint64_t rate_pps);

    port_t get_drop_port() const
    {
        return drop_port;
    }

    int ReceivePacket(Ptr<Packet> packetIn,
                      int inPort,
                      uint16_t protocol,
                      const Address& destination);
    int init(int argc, char* argv[]);

    /**
     * \brief configure switch with json file
     */
    int InitFromCommandLineOptionsLocal(int argc,
                                        char* argv[],
                                        bm::TargetParserBasic* tp = nullptr);

    void packets_process_pipeline(Ptr<Packet> packetIn,
                                  int inPort,
                                  uint16_t protocol,
                                  const Address& destination);

    void input_buffer(Ptr<Packet> packetIn);

    void input_buffer(std::unique_ptr<bm::Packet>&& bm_packet, PacketType packet_type);

    void transmit_buffer(std::unique_ptr<bm::Packet>&& bm_packet);

    void parser_ingress_processing();

    void enqueue(port_t egress_port, std::unique_ptr<bm::Packet>&& bm_packet);

    void egress_deparser_processing();

    bool mirroring_add_session(mirror_id_t mirror_id, const MirroringSessionConfig& config);

    bool mirroring_delete_session(mirror_id_t mirror_id);

    bool mirroring_get_session(mirror_id_t mirror_id, MirroringSessionConfig* config) const;
    
    void copy_field_list_and_set_type(
			const std::unique_ptr<bm::Packet> &packet,
			const std::unique_ptr<bm::Packet> &packet_copy,
			PktInstanceType copy_type, p4object_id_t field_list_id);

    void multicast(bm::Packet *packet, unsigned int mgid);

    void check_queueing_metadata();

    int set_egress_priority_queue_depth(size_t port, size_t priority, const size_t depth_pkts);
    int set_egress_queue_depth(size_t port, const size_t depth_pkts);
    int set_all_egress_queue_depths(const size_t depth_pkts);
    int set_egress_priority_queue_rate(size_t port, size_t priority, const uint64_t rate_pps);
    int set_egress_queue_rate(size_t port, const uint64_t rate_pps);
    int set_all_egress_queue_rates(const uint64_t rate_pps);

    /**
     * \brief Set whether to skip tracing, default is true
     */
    void SetSkipTracing(bool skipTracing)
    {
        skip_tracing = skipTracing;
    }

    std::unique_ptr<bm::Packet> get_bm_packet(Ptr<Packet> ns3_packet);
    std::unique_ptr<bm::Packet> get_bm_packet_from_ingress(Ptr<Packet> ns_packet);
    Ptr<Packet> get_ns3_packet(std::unique_ptr<bm::Packet> bm_packet);

    P4Switch(const P4Switch&) = delete;
    P4Switch& operator=(const P4Switch&) = delete;
    P4Switch(P4Switch&&) = delete;
    P4Switch&& operator=(P4Switch&&) = delete;

  protected:
    static bm::packet_id_t packet_id;
    static int thrift_port;

  private:
    bool skip_tracing = true;          // whether to skip tracing
    bool with_queueing_metadata{true}; // whether to include queueing metadata

    size_t nb_queues_per_port{8}; // 3 bit for the queue number, max value is 8
    std::unique_ptr<MirroringSessions> mirroring_sessions;

    std::vector<Address> destination_list; //!< list for address, using by index

    P4InputQueueBufferDisc input_buffer;
    std::vector<P4QueueDisc> queue_buffers;
    FifoQueueDisc transmit_buffer;
};

} // namespace ns3

#endif // !P4_SWITCH_CORE_H