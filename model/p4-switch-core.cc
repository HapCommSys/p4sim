/*
 * Copyright (c) 2025 TU Dresden
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
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_OFF

#ifdef Mutex
#undef Mutex
#endif

// Undefine conflicting macro if it exists
#ifdef registry_t
#undef registry_t
#endif

#include <bm/spdlog/spdlog.h>
#undef LOG_INFO
#undef LOG_ERROR
#undef LOG_DEBUG

#include "ns3/log.h"
#include "ns3/p4-switch-core.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/simulator.h"

#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/options_parse.h>
#include <fstream>

NS_LOG_COMPONENT_DEFINE("P4SwitchCore");

namespace ns3
{

static constexpr uint16_t MAX_MIRROR_SESSION_ID = (1u << 15) - 1;

class P4SwitchCore::MirroringSessions
{
  public:
    bool add_session(int mirror_id, const MirroringSessionConfig& config)
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (0 <= mirror_id && mirror_id <= MAX_MIRROR_SESSION_ID)
        {
            sessions_map[mirror_id] = config;
            NS_LOG_INFO("Session added with mirror_id=" << mirror_id);
            return true;
        }
        else
        {
            NS_LOG_ERROR("mirror_id out of range. No session added.");
            return false;
        }
    }

    bool delete_session(int mirror_id)
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (0 <= mirror_id && mirror_id <= MAX_MIRROR_SESSION_ID)
        {
            bool erased = sessions_map.erase(mirror_id) == 1;
            if (erased)
            {
                NS_LOG_INFO("Session deleted with mirror_id=" << mirror_id);
            }
            else
            {
                NS_LOG_WARN("No session found for mirror_id=" << mirror_id);
            }
            return erased;
        }
        else
        {
            NS_LOG_ERROR("mirror_id out of range. No session deleted.");
            return false;
        }
    }

    bool get_session(int mirror_id, MirroringSessionConfig* config) const
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = sessions_map.find(mirror_id);
        if (it == sessions_map.end())
        {
            NS_LOG_WARN("No session found for mirror_id=" << mirror_id);
            return false;
        }
        *config = it->second;
        NS_LOG_INFO("Session retrieved for mirror_id=" << mirror_id);
        return true;
    }

  private:
    mutable std::mutex mutex;
    std::unordered_map<int, MirroringSessionConfig> sessions_map;
};

// P4SwitchCore.cpp
P4SwitchCore::P4SwitchCore(P4SwitchNetDevice* netDevice,
                           bool enableSwap,
                           bool enableTracing,
                           uint32_t dropPort)
    : bm::Switch(enableSwap),
      m_switchNetDevice(netDevice),
      m_enableTracing(enableTracing),
      m_dropPort(dropPort),
      m_pre(new bm::McSimplePreLAG()),
      m_startTimestamp(Simulator::Now().GetNanoSeconds()),
      m_mirroringSessions(new MirroringSessions())
{
    static int switch_id = 1;
    m_p4SwitchId = switch_id++;
    NS_LOG_INFO("Initialized P4 Switch with ID: " << m_p4SwitchId);
}

P4SwitchCore::~P4SwitchCore()
{
}

void
P4SwitchCore::InitializeSwitchFromP4Json(const std::string& jsonPath)
{
    NS_LOG_FUNCTION(this);
    NS_LOG_INFO("Applying p4 json to switch.");
    int status = 0;

    static int p4_switch_ctrl_plane_thrift_port = 9090;
    m_thriftPort = p4_switch_ctrl_plane_thrift_port;

    std::cout << "P4 switch " << m_p4SwitchId
              << " thrift port: " << p4_switch_ctrl_plane_thrift_port << std::endl;

    bm::OptionsParser opt_parser;
    opt_parser.config_file_path = jsonPath;
    opt_parser.debugger_addr =
        "ipc:///tmp/bmv2-" + std::to_string(p4_switch_ctrl_plane_thrift_port) + "-debug.ipc";
    opt_parser.notifications_addr = "ipc:///tmp/bmv2-" +
                                    std::to_string(p4_switch_ctrl_plane_thrift_port) +
                                    "-notifications.ipc";
    opt_parser.file_logger =
        "/tmp/bmv2-" + std::to_string(p4_switch_ctrl_plane_thrift_port) + "-pipeline.log";
    opt_parser.thrift_port = p4_switch_ctrl_plane_thrift_port++;
    opt_parser.console_logging = false;

    // Initialize the switch
    status = init_from_options_parser(opt_parser);
    if (status != 0)
    {
        // BMv2 prints the reason to std::cout without flushing it; flush it so
        // the message is not lost, and stop here instead of crashing later on
        // the first packet (the PHV factory is not initialized).
        std::cout.flush();
        NS_FATAL_ERROR("Switch ID " << m_p4SwitchId << ": failed to load P4 JSON " << jsonPath
                                    << " (BMv2 init status " << status << ")");
    }

    NS_LOG_INFO("P4 json applied successfully.");
}

int
P4SwitchCore::InitFromCommandLineOptions(int argc, char* argv[])
{
    bm::OptionsParser parser;
    parser.parse(argc, argv, m_argParser);

    std::shared_ptr<bm::TransportIface> transport = std::shared_ptr<bm::TransportIface>(
        bm::TransportIface::make_dummy()); // create a dummy transport

    int status = 0;
    if (parser.no_p4)
        status = init_objects_empty(parser.device_id, transport);
    else
        status = init_objects(parser.config_file_path, parser.device_id, transport);
    return status;
}

int
P4SwitchCore::LoadFlowTableToSwitch(const std::string& flowTablePath)
{
    NS_LOG_INFO("Loading flow table from: " << flowTablePath);
    return ExecuteCliCommands(flowTablePath);
}

int
P4SwitchCore::ExecuteCliCommands(const std::string& commandsFile)
{
    NS_LOG_FUNCTION(this << " Switch ID: " << m_p4SwitchId << " Running CLI commands from "
                         << commandsFile);

    if (m_thriftCommand.empty())
    {
        NS_LOG_ERROR("Thrift command not set for switch ID: " << m_p4SwitchId);
        return 1;
    }

    // Check if the commands file exists
    std::ifstream infile(commandsFile);
    if (!infile.good())
    {
        NS_LOG_ERROR("Commands file not found: " << commandsFile);
        return 1;
    }

    // Get runtime port and start the server
    int port = get_runtime_port();
    bm_runtime::start_server(this, port);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Construct the CLI command
    std::ostringstream cmdStream;
    cmdStream << m_thriftCommand << " --thrift-port " << port << " < " << commandsFile
              << " > /dev/null 2>&1";
    std::string cmd = cmdStream.str();

    NS_LOG_DEBUG("Executing CLI command: " << cmd);

    // Run the CLI command to populate table entries
    int result = std::system(cmd.c_str());
    if (result != 0)
    {
        NS_LOG_WARN("CLI command returned non-zero exit code: " << result);
    }

    return result;
}

uint64_t
P4SwitchCore::GetTimeStamp()
{
    return Simulator::Now().GetNanoSeconds() - m_startTimestamp;
}

Ptr<Packet>
P4SwitchCore::ConvertToNs3Packet(std::unique_ptr<bm::Packet>&& bm_packet)
{
    // Create a new ns3::Packet using the data buffer
    char* bm_buf = bm_packet.get()->data();
    size_t len = bm_packet.get()->get_data_size();
    Ptr<Packet> ns_packet = Create<Packet>((uint8_t*)(bm_buf), len);

    return ns_packet;
}

std::unique_ptr<bm::Packet>
P4SwitchCore::ConvertToBmPacket(Ptr<Packet> nsPacket, int inPort)
{
    int len = nsPacket->GetSize();
    uint8_t* pkt_buffer = new uint8_t[len];
    nsPacket->CopyData(pkt_buffer, len);
    bm::PacketBuffer buffer(len + 512, (char*)pkt_buffer, len);
    std::unique_ptr<bm::Packet> bm_packet(
        new_packet_ptr(inPort, m_packetId++, len, std::move(buffer)));
    delete[] pkt_buffer;

    return bm_packet;
}

int
P4SwitchCore::GetAddressIndex(const Address& destination)
{
    auto it = m_addressMap.find(destination);
    if (it != m_addressMap.end())
    {
        return it->second;
    }
    else
    {
        int new_index = m_destinationList.size();
        m_destinationList.push_back(destination);
        m_addressMap[destination] = new_index;
        return new_index;
    }
}

int
P4SwitchCore::receive_(uint32_t port_num, const char* buffer, int len)
{
    NS_LOG_FUNCTION("Deprecated function, using ReceivePacket instead.");
    return 0;
}

void
P4SwitchCore::start_and_return_()
{
    NS_LOG_FUNCTION("Switch begin to start.");
}

void
P4SwitchCore::swap_notify_()
{
    NS_LOG_FUNCTION("P4 switch has been notified of a config swap.");
}

void
P4SwitchCore::reset_target_state_()
{
    NS_LOG_DEBUG("Resetting simple_switch target-specific state");
    get_component<bm::McSimplePreLAG>()->reset_state();
}

bool
P4SwitchCore::AddMirroringSession(int mirror_id, const MirroringSessionConfig& config)
{
    return m_mirroringSessions->add_session(mirror_id, config);
}

bool
P4SwitchCore::DeleteMirroringSession(int mirror_id)
{
    return m_mirroringSessions->delete_session(mirror_id);
}

bool
P4SwitchCore::GetMirroringSession(int mirror_id, MirroringSessionConfig* config) const
{
    return m_mirroringSessions->get_session(mirror_id, config);
}

void
P4SwitchCore::CheckQueueingMetadata()
{
    // TODO(antonin): add qid in required fields
    bool enq_timestamp_e = field_exists("queueing_metadata", "enq_timestamp");
    bool enq_qdepth_e = field_exists("queueing_metadata", "enq_qdepth");
    bool deq_timedelta_e = field_exists("queueing_metadata", "deq_timedelta");
    bool deq_qdepth_e = field_exists("queueing_metadata", "deq_qdepth");
    if (enq_timestamp_e || enq_qdepth_e || deq_timedelta_e || deq_qdepth_e)
    {
        if (enq_timestamp_e && enq_qdepth_e && deq_timedelta_e && deq_qdepth_e)
        {
            m_enableQueueingMetadata = true;
            return;
        }
        else
        {
            NS_LOG_WARN("Switch ID: "
                        << m_p4SwitchId
                        << " Your JSON input defines some but not all queueing metadata fields");
        }
    }
    else
    {
        NS_LOG_WARN(
            "Switch ID: " << m_p4SwitchId
                          << " Your JSON input does not define any queueing metadata fields");
    }
    m_enableQueueingMetadata = false;
}
} // namespace ns3