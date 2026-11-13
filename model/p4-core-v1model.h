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
 *           Vineet Goel <vineetgoel692@gmail.com>
 */

#ifndef P4_CORE_V1MODEL_H
#define P4_CORE_V1MODEL_H

#include "ns3/p4-queue.h"
#include "ns3/p4-switch-core.h"
#include "ns3/p4-switch-queue-item.h"
#include "ns3/p4-traffic-manager.h"
#include "ns3/queue-disc.h"
#include "ns3/switched-ethernet-channel.h"

#include <bm/bm_sim/counters.h>
#include <unordered_map>

#define SSWITCH_VIRTUAL_QUEUE_NUM_V1MODEL 8

namespace ns3
{

class P4CoreV1model : public P4SwitchCore
{
  public:
    // === Constructor & Destructor ===
    P4CoreV1model(P4SwitchNetDevice* net_device,
                  bool enable_swap,
                  bool enableTracing,
                  uint64_t packet_rate,
                  size_t input_buffer_size_low,
                  size_t input_buffer_size_high,
                  size_t queue_buffer_size,
                  size_t nb_queues_per_port = SSWITCH_VIRTUAL_QUEUE_NUM_V1MODEL);
    ~P4CoreV1model();

    /**
     * @brief Packet instance types used to distinguish processing paths.
     */
    enum PktInstanceTypeV1model
    {
        PKT_INSTANCE_TYPE_NORMAL,
        PKT_INSTANCE_TYPE_INGRESS_CLONE,
        PKT_INSTANCE_TYPE_EGRESS_CLONE,
        PKT_INSTANCE_TYPE_COALESCED,
        PKT_INSTANCE_TYPE_RECIRC,
        PKT_INSTANCE_TYPE_REPLICATION,
        PKT_INSTANCE_TYPE_RESUBMIT,
    };

    // === Packet Processing (P4SwitchCore overrides) ===
    int ReceivePacket(Ptr<Packet> packetIn,
                      int inPort,
                      uint16_t protocol,
                      const Address& destination) override;
    void swap_notify_() override;
    void start_and_return_() override;
    void reset_target_state_() override;
    void HandleIngressPipeline() override;
    void Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet) override;
    bool HandleEgressPipeline(size_t workerId) override;

    // === Scheduling ===
    void CalculateScheduleTime();
    void EventDrivenEgressDequeue(uint32_t port);
    void ScheduleEgressIfNeeded(uint32_t port);
    void PortTxComplete(uint32_t port);
    void TryTransmitFromQueueDisc(uint32_t port);

    // === Optional VOQ + fabric Traffic Manager (opt-in, default OFF) ===
    //
    // Additive integration layer.  When disabled (the default), the switch uses
    // the legacy output-queued path (egress_buffer + event-driven dequeue) and
    // NONE of the methods below have any effect.  When enabled via
    // SetEnableVoqFabric(true) before the switch starts, packets leaving the
    // ingress pipeline are steered into a P4TrafficManager (VOQ -> priority-first
    // fabric -> strict-priority egress) instead of egress_buffer.  The legacy
    // path is left fully intact for side-by-side comparison / review.

    /**
     * @brief Enable or disable the VOQ + fabric Traffic Manager path.
     *
     * Must be called before start_and_return_() (the TM is constructed there,
     * once the ports/link rate are known).  Default is disabled.
     */
    void SetEnableVoqFabric(bool enable);
    bool GetEnableVoqFabric() const;

    /** @brief The Traffic Manager instance, or nullptr if the VOQ path is off. */
    Ptr<P4TrafficManager> GetTrafficManager() const;

    // === Per-port QueueDisc ===

    /**
     * @brief Install (or replace) a QueueDisc on a given egress port.
     *
     * The QueueDisc will be initialized automatically if it has not been
     * already.  Pass nullptr to remove an existing QueueDisc.
     *
     * @param port  Egress port index.
     * @param qd    The QueueDisc to install, or nullptr to remove.
     */
    void SetPortQueueDisc(uint32_t port, Ptr<QueueDisc> qd);

    // === Internal helpers ===
    void MulticastPacket(bm::Packet* packet, unsigned int mgid);
    void CopyFieldList(const std::unique_ptr<bm::Packet>& packet,
                       const std::unique_ptr<bm::Packet>& packetCopy,
                       PktInstanceTypeV1model copyType,
                       int fieldListId);

    // === Queue configuration ===
    int SetEgressPriorityQueueDepth(size_t port, size_t priority, size_t depthPkts);
    int SetEgressQueueDepth(size_t port, size_t depthPkts);
    int SetAllEgressQueueDepths(size_t depthPkts);
    int SetEgressPriorityQueueRate(size_t port, size_t priority, uint64_t ratePps);
    int SetEgressQueueRate(size_t port, uint64_t ratePps);
    int SetAllEgressQueueRates(uint64_t ratePps);

  protected:
    /**
     * @brief Maps an egress port to the worker thread index (single-threaded in ns-3).
     */
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
    uint64_t m_packetId;
    uint64_t m_switchRate;

    Time m_timeInterval;       ///< Statistics logging interval
    double m_virtualQueueRate; ///< Per-queue rate (pps)

    size_t m_nbQueuesPerPort;
    uint64_t m_startTimestamp; ///< Simulation start timestamp

    static constexpr size_t m_nbEgressThreads = 1u;

    std::unique_ptr<InputBuffer> input_buffer;
    NSQueueingLogicPriRL<std::unique_ptr<bm::Packet>, EgressThreadMapper> egress_buffer;

    // ---- SwitchRate: the packet rate of the whole pipeline ----

    /**
     * @brief Put \p packet into the input buffer and let the ingress pipeline
     * take it as SwitchRate allows: at once if SwitchRate is 0 or the pipeline
     * is idle, otherwise when the pipeline is free again.
     * @return false if the input buffer is full; the packet is then dropped
     */
    bool AdmitToIngress(InputBuffer::PacketType type, std::unique_ptr<bm::Packet>&& packet);

    /**
     * @brief Run the ingress pipeline on the next packet of the input buffer,
     * and schedule the one after it one service time (1/SwitchRate) later.
     */
    void ServeIngress();

    Time m_ingressServiceTime; ///< 1/SwitchRate, the pipeline's time per packet; 0 = no limit
    Time m_ingressFreeAt;      ///< when the pipeline can take the next packet
    EventId m_ingressEvent;    ///< the pending ServeIngress()

    // ---- Event-driven scheduler state ----

    /**
     * @brief Per-port transmission state.
     *
     * busy is set when a packet has been handed to the NetDevice and cleared
     * when the device reports the end of serialisation via PortTxComplete().
     * pendingEvent allows cancellation of a stale dequeue timer.
     */
    struct PortTxState
    {
        bool busy{false};
        EventId pendingEvent{};
    };

    std::unordered_map<uint32_t, Ptr<QueueDisc>> m_portQueueDiscs;
    std::unordered_map<uint32_t, PortTxState> m_portTxState;

    /// Link rate of port 0, read at startup: seeds the Traffic Manager's PortRate and
    /// appears in log messages. Serialisation is timed by each port's channel.
    uint64_t m_linkRateBps{1000000000ULL};

    // ---- VOQ + fabric Traffic Manager (opt-in) ----

    /// When true, HandleIngressPipeline's Enqueue() steers packets into m_trafficManager
    /// instead of egress_buffer.  Default false keeps the legacy output-queued path.
    bool m_enableVoqFabric{false};

    /// The Traffic Manager (VOQ + fabric + egress).  Null unless m_enableVoqFabric.
    Ptr<P4TrafficManager> m_trafficManager;

    /// Steer a post-ingress bm::Packet into the Traffic Manager's VOQ.
    void EnqueueToTrafficManager(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet);

    /// TransmitCallback target: run egress pipeline + deparse + send for a packet
    /// the Traffic Manager has selected for transmission.
    void TmTransmit(uint32_t outPort, uint8_t priority, std::unique_ptr<TmPayload> payload);

    /// Datapath -> Traffic Manager completion hook.  Scheduled by TmTransmit()
    /// for the moment the output port finishes serialising the current frame;
    /// forwards to P4TrafficManager::NotifyEgressTxComplete() so the TM accounts
    /// for the frame (transmitted, dropped, or recirculated) and serves the next
    /// one.  \p outcome tells the TM what actually happened to the frame.
    void TmNotifyTxDone(uint32_t outPort, TmTxOutcome outcome);

    /// Schedule a TmNotifyTxDone() for \p outPort after \p delay, recording its
    /// EventId in m_pendingTxDone so the destructor can cancel it before the TM
    /// is disposed (a pending completion must never fire on a torn-down core).
    void ScheduleTmNotifyTxDone(uint32_t outPort, Time delay, TmTxOutcome outcome);

    /// Pending TmNotifyTxDone events, keyed by output port.  At most one frame
    /// is in flight per port in completion-driven egress, so at most one entry
    /// per port.  Cancelled in the destructor before m_trafficManager->Dispose().
    std::unordered_map<uint32_t, EventId> m_pendingTxDone;
}; // class P4CoreV1model

} // namespace ns3

#endif // P4_CORE_V1MODEL_H
