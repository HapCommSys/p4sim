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

#include <unordered_map>

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

    void CalculateScheduleTime();

    // ---- Event-driven scheduler ----

    /**
     * @brief [Legacy / polling] Periodic egress drain callback.
     * @deprecated Replaced by the event-driven scheduler.
     */
    void SetEgressTimerEvent();

    /**
     * @brief Attempt to dequeue and process one packet from the egress buffer.
     *
     * Invoked when a packet is enqueued into a previously-empty queue
     * (via ScheduleEgressIfNeeded()) or when port transmission completes
     * (via PortTxComplete()).  If no packet is currently eligible based on
     * its rate-limit timestamp, the next eligible time is computed and a
     * new event is scheduled at that time.
     *
     * @param port  Egress port to dequeue from.  Pass UINT32_MAX to let the
     *              scheduler pick the next eligible port (used by the legacy
     *              HandleEgressPipeline wrapper).
     */
    void EventDrivenEgressDequeue(uint32_t port);

    /**
     * @brief Schedule an egress-dequeue event for @p port if none is pending.
     *
     * Called from Enqueue() after a packet is pushed.  If the port is idle
     * and no dequeue event is already pending, a new EventDrivenEgressDequeue
     * event is scheduled at the earliest rate-eligible time.
     *
     * @param port  The egress port that just received a packet.
     */
    void ScheduleEgressIfNeeded(uint32_t port);

    /**
     * @brief Callback invoked when link serialisation of a packet finishes.
     *
     * Marks the port free and calls ScheduleEgressIfNeeded() to drain the
     * next queued packet.
     *
     * @param port  The egress port whose transmission just completed.
     */
    void PortTxComplete(uint32_t port);

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
    uint64_t m_packetId;
    bool m_firstPacket;
    bool m_enableTracing;
    uint64_t m_switchRate; //!< Switch processing rate (packets per second)
    size_t m_nbQueuesPerPort;

    EventId m_egressTimeEvent; //!< Legacy polling event (unused in event-driven mode)
    Time m_egressTimeRef;      //!< Inter-packet gap derived from m_switchRate

    // Buffers
    bm::Queue<std::unique_ptr<bm::Packet>> input_buffer;
    NSQueueingLogicPriRL<std::unique_ptr<bm::Packet>, EgressThreadMapper> egress_buffer;
    bm::Queue<std::unique_ptr<bm::Packet>> output_buffer;

    // ---- Event-driven scheduler state ----

    /**
     * @brief Per-port transmission state.
     *
     * busy         : true while a packet is being serialised on the link.
     * busyUntil    : simulation time when the link becomes free.
     * pendingEvent : EventId of the next scheduled dequeue attempt; allows
     *                cancellation when a new packet arrives earlier.
     */
    struct PortTxState
    {
        bool busy{false};
        Time busyUntil{Time(0)};
        EventId pendingEvent{};
    };

    /// Indexed by egress port number; created on first use.
    std::unordered_map<uint32_t, PortTxState> m_portTxState;

    /**
     * @brief Link rate for transmission-delay modelling (bits per second).
     * Queried from the underlying NetDevice in CalculateScheduleTime().
     * Defaults to 1 Gbps when no port is available.
     */
    uint64_t m_linkRateBps{1000000000ULL};
};

} // namespace ns3

#endif // !P4_CORE_PSA_H