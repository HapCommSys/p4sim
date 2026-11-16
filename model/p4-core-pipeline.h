/*
 * Copyright (c)
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
 * Author: Jiasong Bai
 * Modified: Mingyu Ma<mingyu.ma@tu-dresden.de>
 */

#ifndef P4_CORE_V1MODEL_PIPELINE_H
#define P4_CORE_V1MODEL_PIPELINE_H

#include "ns3/p4-queue.h"
#include "ns3/p4-switch-core.h"

namespace ns3
{

/**
 * @brief A P4 Pipeline Implementation to be wrapped in P4 Device,
 * using the v1model architecture, It does not contain any buffer, queueing metadata, time control
 * and scheduling models. It can only realize the calculation and processing functions of p4.
 * This implementation comes from: https://github.com/p4db/NS4-DEV
 */
class P4CorePipeline : public P4SwitchCore
{
  public:
    /**
     * @brief Construct a new P4 Core Pipeline object
     * @param netDevice P4 Switch Net Device
     * @param enableSwap enable swapping in run time
     * @param enableTracing enable tracing
     */
    P4CorePipeline(P4SwitchNetDevice* netDevice, bool enableSwap, bool enableTracing);

    /**
     * @brief Destroy the P4 Core Pipeline object
     */
    ~P4CorePipeline();

    /**
     * @brief The type of packet instance
     */
    enum PktInstanceType
    {
        PKT_INSTANCE_TYPE_NORMAL, // only normal pkts
    };

    /**
     * @brief Receive a packet from the network and process with
     * the P4 pipeline: parser, ingress, egress, deparser, notication:
     * there is no queue buffer in this simple v1model pipeline
     *
     * @param packetIn the packet passed from the SwitchNetDevice
     * @param inPort the port where the packet is received
     * @param protocol the protocol of the packet
     * @param destination the destination address of the packet
     * @return int 0 if success
     */
    int ReceivePacket(Ptr<Packet> packetIn,
                      int inPort,
                      uint16_t protocol,
                      const Address& destination) override;

    /**
     * @brief [override, dummy] Receive a packet from the network
     */
    int receive_(uint32_t port_num, const char* buffer, int len) override;

    /**
     * @brief [override, dummy] Start the switch and return
     */
    void start_and_return_() override;

    /**
     * @brief [override, dummy] Notify the switch of a config swap
     */
    void swap_notify_() override;

    /**
     * @brief [override, dummy] Reset the target-specific state
     */
    void reset_target_state_() override;

    /**
     * @brief [override, dummy] Handle the ingress pipeline
     */
    void HandleIngressPipeline() override;

    /**
     * @brief [override, dummy] Enqueue a packet to the switch queue buffer
     */
    void Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet) override;

    /**
     * @brief [override, dummy] Handle the egress pipeline
     */
    bool HandleEgressPipeline(size_t workerId) override;

  private:
    uint64_t m_packetId; //!< Packet ID
};

} // namespace ns3

#endif // !P4_CORE_V1MODEL_PIPELINE_H