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

#include "ns3/p4-nic-pna.h"

#include "ns3/data-rate.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/primitives-pna.h"
#include "ns3/psa-externs.h"
#include "ns3/register-access-v1model.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE("P4CorePna");

namespace ns3
{

P4PnaNic::P4PnaNic(P4SwitchNetDevice* net_device, bool enable_swap, size_t queueBufferSize)
    : P4SwitchCore(net_device, enable_swap),
      m_packetId(0),
      input_buffer(1024),
      m_queueBufferSize(queueBufferSize)
{
    // configure for the switch pna
    // BMv2's generic runtime CLI: it has the table commands of every target
    m_thriftCommand = "bm_CLI";
    m_enableQueueingMetadata = false; // enable queueing metadata for pna

    // used by reset_target_state_()
    add_component<bm::McSimplePreLAG>(m_pre);

    // The loopback flag is named "loopedback" in current p4c pna.p4 and
    // "recirculated" in older versions, so it is not a required field here;
    // the name actually present in the JSON is resolved in start_and_return_().
    add_required_field("pna_main_parser_input_metadata", "input_port");

    add_required_field("pna_main_input_metadata", "timestamp");
    add_required_field("pna_main_input_metadata", "parser_error");
    add_required_field("pna_main_input_metadata", "class_of_service");
    add_required_field("pna_main_input_metadata", "input_port");

    add_required_field("pna_main_output_metadata", "class_of_service");

    force_arith_header("pna_main_parser_input_metadata");
    force_arith_header("pna_main_input_metadata");
    force_arith_header("pna_main_output_metadata");

    import_pna_primitives(); // register send_to_port, drop_packet
    ImportPsaExterns();      // Counter, Hash, InternetChecksum, Meter, Random
}

P4PnaNic::~P4PnaNic()
{
    // BMv2 pushes a sentinel to stop the ingress thread. ns-3 has no such
    // thread, and the push would wait forever on a full buffer.
    // Cancel the PortTxComplete() for a refused frame, which points to this NIC.
    for (auto& kv : m_portTxState)
    {
        Simulator::Cancel(kv.second.txCompleteEvent);
    }
}

bool
P4PnaNic::main_processing_pipeline()
{
    NS_LOG_FUNCTION(this);

    std::unique_ptr<bm::Packet> bm_packet;
    input_buffer.pop_back(&bm_packet);
    if (bm_packet == nullptr)
        return false;

    bm::PHV* phv = bm_packet->get_phv();
    auto input_port = phv->get_field("pna_main_parser_input_metadata.input_port").get_uint();

    NS_LOG_DEBUG("Processing packet received on port " << input_port);

    phv->get_field("pna_main_input_metadata.timestamp").set(GetTimeStamp());

    bm::Parser* parser = this->get_parser("main_parser");
    // With a target profile: what the packet does here sets when it reaches the queues
    IngressPass pass(*this, *bm_packet, "main_parser", "main_control");
    parser->parse(bm_packet.get());

    // pass relevant values from main parser
    phv->get_field("pna_main_input_metadata." + m_loopedbackField)
        .set(phv->get_field("pna_main_parser_input_metadata." + m_loopedbackField));
    phv->get_field("pna_main_input_metadata.parser_error").set(bm_packet->get_error_code().get());
    phv->get_field("pna_main_input_metadata.class_of_service").set(0);
    phv->get_field("pna_main_input_metadata.input_port")
        .set(phv->get_field("pna_main_parser_input_metadata.input_port"));

    // A packet is dropped unless the main control calls send_to_port().
    bm_packet->set_egress_port(m_dropPort);

    bm::Pipeline* main_mau = this->get_pipeline("main_control");
    main_mau->apply(bm_packet.get());
    pass.IngressDone();
    bm_packet->reset_exit();

    bm::Deparser* deparser = this->get_deparser("main_deparser");
    deparser->deparse(bm_packet.get());

    int out_port = bm_packet->get_egress_port();

    // drop_packet() sets the egress port to 511 (SSWITCH_DROP_PORT).
    // Discard the packet silently rather than sending it to the network stack.
    if (out_port == static_cast<int>(m_dropPort))
    {
        NS_LOG_DEBUG("PNA: drop_packet() invoked – discarding packet");
        return false;
    }

    // To the output queue of the port once the pipeline delay is over (see
    // P4SwitchCore::SetPipelineDelay()); without a delay, at once (EnqueueNow())
    Enqueue(static_cast<uint32_t>(out_port), std::move(bm_packet));
    return true;
}

int
P4PnaNic::ReceivePacket(Ptr<Packet> packetIn,
                        int inPort,
                        uint16_t protocol,
                        const Address& destination)
{
    std::unique_ptr<bm::Packet> bm_packet = ConvertToBmPacket(packetIn, inPort);
    int len = bm_packet.get()->get_data_size();
    bm::PHV* phv = bm_packet->get_phv();

    // many current p4 programs assume this
    // from pna spec - PNA does not mandate initialization of user-defined
    // metadata to known values as given as input to the parser
    phv->reset_metadata();

    // setting ns3 specific metadata in packet register
    RegisterAccess::clear_all(bm_packet.get());
    RegisterAccess::set_ns_protocol(bm_packet.get(), protocol);
    int addr_index = GetAddressIndex(destination);
    RegisterAccess::set_ns_address(bm_packet.get(), addr_index);

    phv->get_field("pna_main_parser_input_metadata." + m_loopedbackField).set(0);
    phv->get_field("pna_main_parser_input_metadata.input_port").set(inPort);

    // using packet register 0 to store length, this register will be updated for
    // each add_header / remove_header primitive call
    bm_packet->set_register(0, len);

    input_buffer.push_front(std::move(bm_packet));

    // The pipeline processes the packet at once; the frame then waits in the
    // output queue of its port (see ScheduleTxIfNeeded()).
    main_processing_pipeline();
    return 0;
}

int
P4PnaNic::receive_(port_t port_num, const char* buffer, int len)
{
    NS_LOG_FUNCTION(this << " Port: " << port_num << " Len: " << len);
    return 0;
}

std::map<std::string, std::string>
P4PnaNic::GetMissingPrimitives() const
{
    return {{"recirculate",
             "P4sim's PNA, like BMv2's pna_nic, cannot recirculate a packet; v1model and PSA "
             "can"},
            {"mirror_packet",
             "P4sim's PNA, like BMv2's pna_nic, cannot mirror a packet; v1model and PSA can "
             "clone it"}};
}

void
P4PnaNic::start_and_return_()
{
    NS_LOG_FUNCTION(this);

    bool found = false;
    for (const char* name : {"loopedback", "recirculated"})
    {
        if (field_exists("pna_main_parser_input_metadata", name) &&
            field_exists("pna_main_input_metadata", name))
        {
            m_loopedbackField = name;
            found = true;
            break;
        }
    }
    if (!found)
    {
        NS_FATAL_ERROR("PNA JSON defines neither 'loopedback' nor 'recirculated' in "
                       "pna_main_parser_input_metadata / pna_main_input_metadata");
    }
    NS_LOG_DEBUG("PNA NIC ID " << m_p4SwitchId << ": event-driven scheduler active");
}

void
P4PnaNic::reset_target_state_()
{
    NS_LOG_FUNCTION(this);
    get_component<bm::McSimplePreLAG>()->reset_state();
}

void
P4PnaNic::HandleIngressPipeline()
{
    NS_LOG_FUNCTION(this);
    NS_LOG_DEBUG(
        "Dummy functions for handling ingress pipeline, use main_processing_pipeline instead");
}

bool
P4PnaNic::HandleEgressPipeline(size_t workerId)
{
    NS_LOG_FUNCTION(this);
    NS_LOG_DEBUG(
        "Dummy functions for handling egress pipeline, use main_processing_pipeline instead");
    return false;
}

void
P4PnaNic::EnqueueNow(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet)
{
    NS_LOG_FUNCTION(this << egress_port);
    // Queue the frame for its port. The device sends one frame at a time and
    // reports the end of each one through PortTxComplete().
    auto& pstate = m_portTxState[egress_port];
    if (pstate.queue.size() >= m_queueBufferSize)
    {
        NS_LOG_WARN("PNA port " << egress_port << ": output queue full, packet dropped");
        return;
    }
    uint16_t protocol = RegisterAccess::get_ns_protocol(packet.get());
    int addr_index = RegisterAccess::get_ns_address(packet.get());
    pstate.queue.push_back({this->ConvertToNs3Packet(std::move(packet)), protocol, addr_index});
    ScheduleTxIfNeeded(egress_port);
}

// ---------------------------------------------------------------------------
// Event-driven scheduler
// ---------------------------------------------------------------------------

void
P4PnaNic::ScheduleTxIfNeeded(uint32_t port)
{
    NS_LOG_FUNCTION(this << port);

    auto& pstate = m_portTxState[port];
    if (pstate.busy || pstate.queue.empty())
    {
        return; // PortTxComplete() sends the next frame
    }
    QueuedFrame frame = std::move(pstate.queue.front());
    pstate.queue.pop_front();
    pstate.busy = true;

    NS_LOG_DEBUG("PNA port " << port << ": transmitting " << frame.packet->GetSize() << " B, "
                             << pstate.queue.size() << " frames queued");
    if (!m_switchNetDevice->SendNs3Packet(frame.packet,
                                          static_cast<int>(port),
                                          frame.protocol,
                                          GetDestination(frame.addrIndex)))
    {
        // Dropped by the device: nothing is on the wire, free the port.
        pstate.txCompleteEvent = Simulator::ScheduleNow(&P4PnaNic::PortTxComplete, this, port);
    }
}

void
P4PnaNic::PortTxComplete(uint32_t port)
{
    NS_LOG_FUNCTION(this << port);
    m_portTxState[port].busy = false;
    ScheduleTxIfNeeded(port);
}

} // namespace ns3
