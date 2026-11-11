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
 * Authors: Antonin Bas<antonin@barefootnetworks.com>
 * Modified: Mingyu Ma<mingyu.ma@tu-dresden.de>
 */

#ifndef P4_CORE_PSA_H
#define P4_CORE_PSA_H

#include "ns3/p4-queue.h"
#include "ns3/p4-switch-core.h"

#define SSWITCH_VIRTUAL_QUEUE_NUM_PSA 8

namespace ns3
{

class P4CorePsa : public P4SwitchCore
{
  public:
    // === Constructor & Destructor ===
    P4CorePsa(
        P4SwitchNetDevice* net_device,
        bool enable_swap,
        bool enable_tracing,
        uint64_t packet_rate,
        size_t input_buffer_size,
        size_t queue_buffer_size,
        size_t nb_queues_per_port = SSWITCH_VIRTUAL_QUEUE_NUM_PSA); // by default, swapping is off
    ~P4CorePsa();

    enum PktInstanceTypePsa
    {
        PACKET_PATH_NORMAL,
        PACKET_PATH_NORMAL_UNICAST,
        PACKET_PATH_NORMAL_MULTICAST,
        PACKET_PATH_CLONE_I2E,
        PACKET_PATH_CLONE_E2E,
        PACKET_PATH_RESUBMIT,
        PACKET_PATH_RECIRCULATE,
    };

    // === Public Methods ===
    int ReceivePacket(Ptr<Packet> packetIn,
                      int inPort,
                      uint16_t protocol,
                      const Address& destination) override;

    void SetEgressTimerEvent();
    void CalculateScheduleTime();

    // === override ===

    void start_and_return_() override;
    void swap_notify_() override;
    void reset_target_state_() override;

    void HandleIngressPipeline() override;
    void Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet) override;
    bool HandleEgressPipeline(size_t workerId) override;

    void MultiCastPacket(bm::Packet* packet,
                         unsigned int mgid,
                         PktInstanceTypePsa path,
                         unsigned int class_of_service);

    // Queue Configuration
    int SetEgressPriorityQueueDepth(size_t port, size_t priority, size_t depthPkts);
    int SetEgressQueueDepth(size_t port, size_t depthPkts);
    int SetAllEgressQueueDepths(size_t depthPkts);
    int SetEgressPriorityQueueRate(size_t port, size_t priority, uint64_t ratePps);
    int SetEgressQueueRate(size_t port, uint64_t ratePps);
    int SetAllEgressQueueRates(uint64_t ratePps);

  protected:
    struct EgressThreadMapper
    {
        explicit EgressThreadMapper(size_t nb_threads)
            : nb_threads(nb_threads)
        {
        }

        size_t operator()(size_t egress_port) const
        {
            return egress_port % nb_threads;
        }

        size_t nb_threads;
    };

  private:
    static constexpr uint32_t PSA_PORT_RECIRCULATE = 0xfffffffa;
    static constexpr size_t nb_egress_threads = 1u; // 4u default
    uint64_t m_packetId;                            // Packet ID
    bool m_firstPacket;
    bool m_enableTracing;
    uint64_t m_switchRate; //!< Switch processing capability (unit: PPS (Packets
                           //!< Per Second))
    size_t m_nbQueuesPerPort;

    EventId m_egressTimeEvent;  //!< The timer event ID [Egress]
    EventId m_egressRetryEvent; //!< Extra egress run scheduled by the timer
    Time m_egressTimeRef;       //!< Desired time between timer event triggers

    // Buffers and Transmit Function
    // std::unique_ptr<InputBuffer> input_buffer;
    bm::Queue<std::unique_ptr<bm::Packet>> input_buffer;
    NSQueueingLogicPriRL<std::unique_ptr<bm::Packet>, EgressThreadMapper> egress_buffer;
    bm::Queue<std::unique_ptr<bm::Packet>> output_buffer;
};

} // namespace ns3

#endif // !P4_CORE_PSA_H