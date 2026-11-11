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
};

} // namespace ns3

#endif // PNA_NIC_PNA_NIC_H_