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

#ifndef P4_NIC_PNA_H
#define P4_NIC_PNA_H

#include "ns3/p4-queue.h"
#include "ns3/p4-switch-core.h"

namespace ns3
{

class P4PnaNic : public P4SwitchCore
{
  public:
    // by default, swapping is off
    explicit P4PnaNic(P4SwitchNetDevice* net_device, bool enable_swap = false);

    ~P4PnaNic();

    enum PktInstanceTypePna
    {
        FROM_NET_PORT,
        FROM_NET_LOOPEDBACK,
        FROM_NET_RECIRCULATED,
        FROM_HOST,
        FROM_HOST_LOOPEDBACK,
        FROM_HOST_RECIRCULATED,
    };

    int receive_(port_t port_num, const char* buffer, int len) override;

    void start_and_return_() override;

    void reset_target_state_() override;

    void HandleIngressPipeline() override;
    void Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet) override;
    bool HandleEgressPipeline(size_t workerId) override;

    bool main_processing_pipeline();

    int ReceivePacket(Ptr<Packet> packetIn,
                      int inPort,
                      uint16_t protocol,
                      const Address& destination) override;

  private:
    enum PktDirection
    {
        NET_TO_HOST,
        HOST_TO_NET,
    };

    uint64_t m_packetId; // Packet ID

    bm::Queue<std::unique_ptr<bm::Packet>> input_buffer;

    // ---- Event-driven scheduler state ----

    /**
     * @brief Per-port transmission state.
     *
     * busy         : true while a packet is being serialised on the link.
     * busyUntil    : simulation time when the link becomes free.
     * pendingEvent : EventId of an upcoming PortTxComplete callback.
     */
    struct PortTxState
    {
        bool busy{false};
        Time busyUntil{Time(0)};
        EventId pendingEvent{};
    };

    /// Indexed by egress port number; entries created on first use.
    std::unordered_map<uint32_t, PortTxState> m_portTxState;

    /**
     * @brief Physical link rate used for serialisation-delay modelling (bps).
     * Read from the first bridge port's DataRate attribute; falls back to 1 Gbps.
     */
    uint64_t m_linkRateBps{1000000000ULL}; // default 1 Gbps
};

} // namespace ns3

#endif // PNA_NIC_PNA_NIC_H_