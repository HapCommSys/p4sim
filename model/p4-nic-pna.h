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

#include "ns3/data-rate.h"
#include "ns3/event-id.h"
#include "ns3/nstime.h"
#include "ns3/p4-queue.h"
#include "ns3/p4-switch-core.h"

#include <deque>
#include <unordered_map>

#undef LOG_INFO
#undef LOG_ERROR
#undef LOG_DEBUG
#undef LOG_WARN
#undef LOG_LOGIC

namespace ns3
{

class P4PnaNic : public P4SwitchCore
{
  public:
    /**
     * @param net_device       the device of the NIC
     * @param enable_swap      allow swapping the program at run time (off by default)
     * @param queueBufferSize  capacity of the output queue of each port, in frames
     */
    explicit P4PnaNic(P4SwitchNetDevice* net_device,
                      bool enable_swap = false,
                      size_t queueBufferSize = 128);

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
    void EnqueueNow(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet) override;
    bool HandleEgressPipeline(size_t workerId) override;

    bool main_processing_pipeline();

    int ReceivePacket(Ptr<Packet> packetIn,
                      int inPort,
                      uint16_t protocol,
                      const Address& destination) override;

    // ---- Event-driven scheduler ----

    /**
     * @brief Hand the oldest frame in the output queue of @p port to the
     * device, unless the port is still sending a frame.
     *
     * Called when main_processing_pipeline() has queued a frame, and from
     * PortTxComplete().
     *
     * @param port  The egress port.
     */
    void ScheduleTxIfNeeded(uint32_t port);

    /**
     * @brief The device has sent the frame on @p port, or refused it.
     *
     * The device calls it through the port-TX-done callback (see
     * P4SwitchNetDevice::SetPortTxDoneCallback()). Marks the port free and
     * sends the next queued frame.
     *
     * @param port  The egress port whose transmission just completed.
     */
    void PortTxComplete(uint32_t port);

  private:
    enum PktDirection
    {
        NET_TO_HOST,
        HOST_TO_NET,
    };

    uint64_t m_packetId; // Packet ID

    bm::Queue<std::unique_ptr<bm::Packet>> input_buffer;

    // ---- Event-driven scheduler state ----

    /// A frame waiting in the output queue of its port
    struct QueuedFrame
    {
        Ptr<Packet> packet; ///< the frame
        uint16_t protocol;  ///< its protocol, for SendNs3Packet()
        int addrIndex;      ///< index of its destination in m_destinationList
    };

    /**
     * @brief Per-port transmission state.
     *
     * busy            : true from handing a frame to the device until the
     *                   device reports its end through PortTxComplete().
     * queue           : the frames waiting for the port, oldest first.
     * txCompleteEvent : PortTxComplete() for a frame the device refused.
     */
    struct PortTxState
    {
        bool busy{false};
        std::deque<QueuedFrame> queue;
        EventId txCompleteEvent{};
    };

    /// Indexed by egress port number; entries created on first use.
    std::unordered_map<uint32_t, PortTxState> m_portTxState;

    size_t m_queueBufferSize; ///< capacity of the output queue of each port (frames)

    // "loopedback" (current pna.p4) or "recirculated" (older pna.p4)
    std::string m_loopedbackField{"loopedback"};
};

} // namespace ns3

#endif // PNA_NIC_PNA_NIC_H_