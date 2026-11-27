/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
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
#include "ns3/p4sim-ns3-compat.h"
#include "ns3/simulator.h"

#include <algorithm>
#include <array>
#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/dev_mgr.h>
#include <bm/bm_sim/options_parse.h>
#include <bm/bm_sim/port_monitor.h>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <json/json.h>
#include <map>
#include <memory>
#include <netinet/in.h>
#include <spawn.h>
#include <sstream>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MFD_NOEXEC_SEAL // glibc before 2.39
#define MFD_NOEXEC_SEAL 0x0008U
#endif

NS_LOG_COMPONENT_DEFINE("P4SwitchCore");

namespace
{

/**
 * Run a shell command with this standard input and return what it writes to its
 * standard output and error. The command gets no other descriptor of this process:
 * a runtime CLI that held the listening Thrift sockets of the switches would wait
 * for itself forever if this process ended while it runs. (With glibc before 2.34,
 * which cannot close them, it inherits them as before.)
 */
std::string
RunWithInput(const std::string& command, int input)
{
    int out[2];
    if (pipe2(out, O_CLOEXEC) != 0)
    {
        return std::string("cannot create a pipe: ") + std::strerror(errno);
    }
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, input, STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, out[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, out[1], STDERR_FILENO);
#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 34)
    posix_spawn_file_actions_addclosefrom_np(&actions, STDERR_FILENO + 1);
#endif
    const char* argv[] = {"sh", "-c", command.c_str(), nullptr};
    pid_t pid;
    int rc =
        posix_spawn(&pid, "/bin/sh", &actions, nullptr, const_cast<char* const*>(argv), environ);
    posix_spawn_file_actions_destroy(&actions);
    close(out[1]);
    std::string output;
    if (rc != 0)
    {
        output = std::string("cannot run /bin/sh: ") + std::strerror(rc);
    }
    else
    {
        std::array<char, 4096> buffer;
        for (ssize_t n; (n = read(out[0], buffer.data(), buffer.size())) != 0;)
        {
            if (n > 0)
            {
                output.append(buffer.data(), n);
            }
            else if (errno != EINTR)
            {
                break;
            }
        }
        while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR)
        {
        }
    }
    close(out[0]);
    return output;
}

/**
 * BMv2 swaps the P4 program only when no packet of the switch holds a PHV
 * (bm::SwitchWContexts::do_swap() waits for that), but it has no public way to
 * ask for this count: the PHV source of the switch is a private member. An
 * explicit template instantiation may name a private member (the usual access
 * checking does not apply to it, C++ standard [temp.explicit]), so
 * PhvSourceAccess, instantiated below, defines PhvSource(), which returns a
 * pointer to that member.
 */
using PhvSourceMember = std::unique_ptr<bm::PHVSourceIface> bm::SwitchWContexts::*;

/// Selects PhvSource()
struct PhvSourceTag
{
    friend PhvSourceMember PhvSource(PhvSourceTag);
};

/// Defines PhvSource() to return \p Member
template <PhvSourceMember Member>
struct PhvSourceAccess
{
    friend PhvSourceMember PhvSource(PhvSourceTag)
    {
        return Member;
    }
};

template struct PhvSourceAccess<&bm::SwitchWContexts::phv_source>;

/**
 * BMv2 device manager without ports. P4sim moves the packets between BMv2 and
 * ns-3 itself, so a switch needs no BMv2 port and P4sim never starts a device
 * manager. Without this one, init_from_options_parser() creates BMv2's default
 * device manager (BMI), whose destructor joins a thread that only a start
 * creates: with glibc 2.43 (Ubuntu 26.04) every simulation then crashes at its
 * end (BMv2 1.15.8, bmi_port_destroy_mgr()). This one starts no thread and
 * opens no socket.
 */
class NoPortsDevMgr : public bm::DevMgrIface
{
  public:
    NoPortsDevMgr()
    {
        p_monitor = bm::PortMonitorIface::make_dummy();
    }

  private:
    ReturnCode port_add_(const std::string& /* ifaceName */,
                         port_t /* port */,
                         const PortExtras& /* extras */) override
    {
        return ReturnCode::UNSUPPORTED;
    }

    ReturnCode port_remove_(port_t /* port */) override
    {
        return ReturnCode::UNSUPPORTED;
    }

    void transmit_fn_(port_t /* port */, const char* /* buffer */, int /* len */) override
    {
    }

    void start_() override
    {
    }

    ReturnCode set_packet_handler_(const PacketHandler& /* handler */, void* /* cookie */) override
    {
        return ReturnCode::SUCCESS;
    }

    bool port_is_up_(port_t /* port */) const override
    {
        return false;
    }

    std::map<port_t, PortInfo> get_port_info_() const override
    {
        return {};
    }
};

/// Default first port of the automatic Thrift port allocation
constexpr int P4SIM_DEFAULT_THRIFT_PORT_BASE = 9090;
/// Number of ports tried by the automatic Thrift port allocation
constexpr int P4SIM_THRIFT_PORT_SEARCH_RANGE = 1000;

/// First port of the automatic allocation: $P4SIM_THRIFT_PORT_BASE or 9090
int
GetThriftPortBase()
{
    const char* env = std::getenv("P4SIM_THRIFT_PORT_BASE");
    if (env == nullptr || *env == '\0')
    {
        return P4SIM_DEFAULT_THRIFT_PORT_BASE;
    }
    char* end = nullptr;
    long base = std::strtol(env, &end, 10);
    if (*end != '\0' || base < 1 || base > 65535)
    {
        NS_FATAL_ERROR("Invalid P4SIM_THRIFT_PORT_BASE='" << env
                                                          << "' (expected a port number)");
    }
    return static_cast<int>(base);
}

/// True if nothing listens on TCP port \p port (a bind attempt succeeds)
bool
IsTcpPortFree(int port)
{
    int sock = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0)
    {
        return true; // cannot check; BMv2 reports a real conflict later
    }
    int one = 1;
    // Like the Thrift server: a connection in TIME_WAIT does not make the port busy
    ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    bool isFree = ::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    ::close(sock);
    return isFree;
}

/// True if a server on this host accepts TCP connections on port \p port
bool
ServerListens(int port)
{
    int sock = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0)
    {
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    bool listens = ::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    ::close(sock);
    return listens;
}

/**
 * Reserve \p port for this process if it is free.
 *
 * The reservation is an exclusive flock() on /tmp/p4sim-thrift-<port>.lock. It
 * is held until the process exits (the kernel also releases it on a crash), so
 * p4sim processes running in parallel, e.g. under test.py, never pick the same
 * port. A port that another program listens on is skipped as well.
 */
bool
TryReservePort(int port)
{
    std::string lockPath = "/tmp/p4sim-thrift-" + std::to_string(port) + ".lock";
    int fd = ::open(lockPath.c_str(), O_RDONLY | O_CREAT | O_CLOEXEC, 0666);
    if (fd < 0)
    {
        return false;
    }
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0)
    {
        ::close(fd); // reserved by another p4sim process (or another switch of ours)
        return false;
    }
    if (!IsTcpPortFree(port))
    {
        ::close(fd); // releases the lock
        return false;
    }
    // Keep the descriptor open on purpose: it holds the reservation.
    static std::vector<int> s_reservations;
    s_reservations.push_back(fd);
    return true;
}

/// Thrift port for a switch: \p requested if it is free, or the first free port (0)
int
AllocateThriftPort(uint16_t requested, int switchId)
{
    if (requested != 0)
    {
        if (!TryReservePort(requested))
        {
            NS_FATAL_ERROR("P4 switch " << switchId << ": Thrift port " << requested
                                        << " is already in use by another p4sim process or "
                                           "another program. Choose another ThriftPort, or "
                                           "use 0 to pick a free port automatically.");
        }
        return requested;
    }
    int base = GetThriftPortBase();
    int last = std::min(base + P4SIM_THRIFT_PORT_SEARCH_RANGE, 65536);
    for (int port = base; port < last; ++port)
    {
        if (TryReservePort(port))
        {
            return port;
        }
    }
    NS_FATAL_ERROR("P4 switch " << switchId << ": no free Thrift port in [" << base << ", "
                                << last << "). Set P4SIM_THRIFT_PORT_BASE to another range.");
    return -1;
}

/// BMv2 log level for a name such as "trace" or "off" (case-insensitive)
bm::Logger::LogLevel
ParseBmLogLevel(std::string name)
{
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    using L = bm::Logger::LogLevel;
    static const std::map<std::string, L> levels = {
        {"trace", L::TRACE},
        {"debug", L::DEBUG},
        {"info", L::INFO},
        {"notice", L::NOTICE},
        {"warn", L::WARN},
        {"warning", L::WARN},
        {"error", L::ERROR},
        {"critical", L::CRITICAL},
        {"alert", L::ALERT},
        {"emerg", L::EMERG},
        {"off", L::OFF},
    };
    auto it = levels.find(name);
    if (it == levels.end())
    {
        NS_FATAL_ERROR("Invalid BmLogLevel '" << name
                                              << "': expected trace, debug, info, notice, warn, "
                                                 "error, critical, alert, emerg or off");
    }
    return it->second;
}

} // namespace

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
                           uint32_t dropPort)
    : bm::Switch(enableSwap),
      m_switchNetDevice(netDevice),
      m_dropPort(dropPort),
      m_pre(new bm::McSimplePreLAG()),
      m_startTimestamp(Simulator::Now().GetNanoSeconds()),
      m_mirroringSessions(new MirroringSessions())
{
    static int switch_id = 1;
    m_p4SwitchId = switch_id++;
    // The device creates its core when the simulation initializes it
    m_simulationThread = std::this_thread::get_id();
    NS_LOG_INFO("Initialized P4 Switch with ID: " << m_p4SwitchId);
}

P4SwitchCore::~P4SwitchCore()
{
    // A pending ServeIngress() must not run on a destroyed core, nor a pending
    // ReleaseFromPipeline() or TrySwap(). The packets still in the pipeline and
    // the frames held for a swap are freed with it.
    Simulator::Cancel(m_ingressEvent);
    Simulator::Cancel(m_pipelineEvent);
    Simulator::Cancel(m_swapEvent);
    // In case P4SwitchNetDevice::DoDispose() did not: the Thrift server keeps
    // running and must not reach this switch any more
    StopThriftServices();
}

bm::RuntimeInterface::ErrorCode
P4SwitchCore::load_new_config(const std::string& newConfig)
{
    bm::RuntimeInterface::ErrorCode rc = bm::SwitchWContexts::load_new_config(newConfig);
    if (rc == bm::RuntimeInterface::SUCCESS)
    {
        m_newConfigLoaded = true;
    }
    return rc;
}

bm::RuntimeInterface::ErrorCode
P4SwitchCore::swap_configs()
{
    if (!m_newConfigLoaded)
    {
        // Swapping is disabled, or no program is loaded: BMv2 returns the error
        return bm::SwitchWContexts::swap_configs();
    }
    m_swapPending = true;
    // The runtime CLI calls from the Thrift server's thread: then the
    // simulation swaps at the next packet event of this switch.
    if (std::this_thread::get_id() == m_simulationThread)
    {
        TrySwap();
    }
    return bm::RuntimeInterface::SUCCESS;
}

bool
P4SwitchCore::IsSwapPending() const
{
    return m_swapPending;
}

bool
P4SwitchCore::HoldDuringSwap(Ptr<Packet> frame,
                             int inPort,
                             uint16_t protocol,
                             const Address& destination)
{
    if (!m_swapPending)
    {
        return false;
    }
    m_heldFrames.push_back({frame, inPort, protocol, destination});
    CheckPendingSwap();
    return true;
}

void
P4SwitchCore::CheckPendingSwap()
{
    // After the current event, which may still own the packet that leaves
    if (m_swapPending && !P4simIsPending(m_swapEvent))
    {
        m_swapEvent = Simulator::ScheduleNow(&P4SwitchCore::TrySwap, this);
    }
}

bool
P4SwitchCore::HoldsPackets()
{
    // Frames in a transfer buffer have passed the pipeline and hold no PHV, but
    // they have not left the switch
    for (const auto& kv : m_transferBuffers)
    {
        if (!kv.second.empty())
        {
            return true;
        }
    }
    const std::unique_ptr<bm::PHVSourceIface>& phvSource = this->*PhvSource(PhvSourceTag{});
    for (bm::cxt_id_t cxt = 0; cxt < get_nb_cxts(); cxt++)
    {
        if (phvSource->phvs_in_use(cxt) > 0)
        {
            return true;
        }
    }
    return false;
}

void
P4SwitchCore::TrySwap()
{
    if (!m_swapPending || HoldsPackets())
    {
        return; // CheckPendingSwap() tries again when a packet leaves
    }
    // No packet left: BMv2 swaps at once
    m_swapPending = false;
    m_newConfigLoaded = false;
    bm::RuntimeInterface::ErrorCode rc = bm::SwitchWContexts::swap_configs();
    NS_ABORT_MSG_IF(rc != bm::RuntimeInterface::SUCCESS,
                    "Switch " << m_p4SwitchId << ": the swap failed (BMv2 error " << rc << ")");
    m_learnListsRead = false; // those of the new program
    NS_LOG_INFO("Switch " << m_p4SwitchId << " swapped its P4 program; " << m_heldFrames.size()
                          << " held frames enter the pipeline");
    std::deque<HeldFrame> held;
    held.swap(m_heldFrames);
    for (HeldFrame& f : held)
    {
        ReceivePacket(f.frame, f.inPort, f.protocol, f.destination);
    }
}

void
P4SwitchCore::Learn(int listId, const bm::Packet& packet)
{
    NS_LOG_FUNCTION(this << listId);
    get_learn_engine()->learn(listId, packet);

    ReadLearnLists();
    auto list = m_learnLists.find(listId);
    if (list == m_learnLists.end())
    {
        NS_LOG_WARN("Switch " << m_p4SwitchId << ": the P4 program has no learn list " << listId);
        return;
    }
    P4Digest digest;
    digest.listId = static_cast<uint32_t>(listId);
    digest.listName = list->second.name;
    const bm::PHV* phv = packet.get_phv();
    for (const std::string& name : list->second.fields)
    {
        const bm::Field& field = phv->get_field(name);
        const bm::ByteContainer& bytes = field.get_bytes();
        digest.fields.push_back({name,
                                 static_cast<uint32_t>(field.get_nbits()),
                                 std::string(bytes.data(), bytes.size())});
    }
    NS_LOG_DEBUG("Switch " << m_p4SwitchId << ": digest " << digest);
    m_switchNetDevice->NotifyDigest(digest);
}

void
P4SwitchCore::ReadLearnLists()
{
    if (m_learnListsRead)
    {
        return;
    }
    m_learnListsRead = true;
    m_learnLists.clear();
    Json::Value root;
    Json::CharReaderBuilder reader;
    std::string errors;
    std::istringstream config(get_config());
    if (!Json::parseFromStream(reader, config, &root, &errors))
    {
        // BMv2 has loaded this JSON, so this does not happen
        NS_LOG_WARN("Switch " << m_p4SwitchId << ": cannot read the learn lists: " << errors);
        return;
    }
    for (const Json::Value& jsonList : root["learn_lists"])
    {
        LearnList& list = m_learnLists[jsonList["id"].asInt()];
        list.name = jsonList["name"].asString();
        for (const Json::Value& element : jsonList["elements"])
        {
            // BMv2 accepts only fields (P4Objects::init_learn_lists())
            if (element["type"].asString() == "field")
            {
                list.fields.push_back(element["value"][0].asString() + "." +
                                      element["value"][1].asString());
            }
        }
    }
}

void
P4SwitchCore::SetPipelineRate(uint64_t pps)
{
    m_ingressServiceTime = (pps == 0) ? Time(0) : Seconds(1.0 / static_cast<double>(pps));
}

void
P4SwitchCore::SetPipelineDelay(Time delay)
{
    NS_ABORT_MSG_IF(delay.IsStrictlyNegative(), "The pipeline delay must not be negative");
    m_pipelineDelay = delay;
}

Time
P4SwitchCore::GetPipelineDelay() const
{
    return m_pipelineDelay;
}

void
P4SwitchCore::SetTransferBufferSize(uint32_t frames)
{
    m_transferBufferSize = frames;
}

uint32_t
P4SwitchCore::GetTransferBufferSize() const
{
    return m_transferBufferSize;
}

uint32_t
P4SwitchCore::GetTransferBufferLength(uint32_t port) const
{
    auto it = m_transferBuffers.find(port);
    return it == m_transferBuffers.end() ? 0 : static_cast<uint32_t>(it->second.size());
}

bool
P4SwitchCore::PortCanTakePacket(uint32_t port, bool transmitterFree) const
{
    uint32_t waiting = GetTransferBufferLength(port);
    return (transmitterFree && waiting == 0) || waiting < m_transferBufferSize;
}

void
P4SwitchCore::Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet)
{
    CheckPendingSwap(); // a full egress queue drops the packet
    if (m_pipelineDelay.IsZero())
    {
        EnqueueNow(egress_port, std::move(packet));
        return;
    }
    // Every packet is delayed by the same time, so the packets leave the
    // pipeline in the order in which they entered it
    Time leaves = Simulator::Now() + m_pipelineDelay;
    m_pipelinePackets.push_back({leaves, egress_port, std::move(packet)});
    if (!P4simIsPending(m_pipelineEvent))
    {
        m_pipelineEvent =
            Simulator::Schedule(m_pipelineDelay, &P4SwitchCore::ReleaseFromPipeline, this);
    }
}

void
P4SwitchCore::ReleaseFromPipeline()
{
    CheckPendingSwap(); // a full egress queue drops the packet
    Time now = Simulator::Now();
    while (!m_pipelinePackets.empty() && m_pipelinePackets.front().leaves <= now)
    {
        PipelinePacket next = std::move(m_pipelinePackets.front());
        m_pipelinePackets.pop_front();
        EnqueueNow(next.egressPort, std::move(next.packet));
    }
    // EnqueueNow() may have scheduled this again, for a new packet (an egress
    // clone): replace that event with one for the oldest packet.
    Simulator::Cancel(m_pipelineEvent);
    if (!m_pipelinePackets.empty())
    {
        m_pipelineEvent = Simulator::Schedule(m_pipelinePackets.front().leaves - now,
                                              &P4SwitchCore::ReleaseFromPipeline,
                                              this);
    }
}

void
P4SwitchCore::StartIngress()
{
    CheckPendingSwap(); // the ingress may drop the packet
    if (m_ingressServiceTime.IsZero())
    {
        // No rate limit: the pipeline takes the packet at once
        HandleIngressPipeline();
        return;
    }
    if (P4simIsPending(m_ingressEvent))
    {
        return; // the pending ServeIngress() takes it
    }
    // An idle pipeline takes the packet at once, a busy one when it is free
    Time now = Simulator::Now();
    if (now >= m_ingressFreeAt)
    {
        ServeIngress();
    }
    else
    {
        m_ingressEvent =
            Simulator::Schedule(m_ingressFreeAt - now, &P4SwitchCore::ServeIngress, this);
    }
}

void
P4SwitchCore::ServeIngress()
{
    CheckPendingSwap(); // the ingress may drop the packet
    if (GetNInputPackets() == 0)
    {
        return;
    }
    // The pipeline is busy with this packet for one service time
    m_ingressFreeAt = Simulator::Now() + m_ingressServiceTime;
    HandleIngressPipeline();
    if (GetNInputPackets() > 0 && !P4simIsPending(m_ingressEvent))
    {
        m_ingressEvent =
            Simulator::Schedule(m_ingressServiceTime, &P4SwitchCore::ServeIngress, this);
    }
}

void
P4SwitchCore::InitializeSwitchFromP4Json(const std::string& jsonPath)
{
    NS_LOG_FUNCTION(this);
    NS_LOG_INFO("Applying p4 json to switch.");
    int status = 0;

    bm::Logger::LogLevel logLevel = ParseBmLogLevel(m_bmLogLevel);
    m_thriftPort = AllocateThriftPort(m_requestedThriftPort, m_p4SwitchId);

    std::cout << "P4 switch " << m_p4SwitchId << " thrift port: " << m_thriftPort << std::endl;

    // The Thrift port is unique among the p4sim processes of this host (see
    // AllocateThriftPort()), so the IPC sockets and the log file named after it
    // are unique too.
    const std::string portStr = std::to_string(m_thriftPort);
    bm::OptionsParser opt_parser;
    opt_parser.config_file_path = jsonPath;
    opt_parser.debugger_addr = "ipc:///tmp/bmv2-" + portStr + "-debug.ipc";
    opt_parser.notifications_addr = "ipc:///tmp/bmv2-" + portStr + "-notifications.ipc";
    if (logLevel != bm::Logger::LogLevel::OFF)
    {
        opt_parser.file_logger = "/tmp/bmv2-" + portStr + "-pipeline.log";
    }
    opt_parser.log_level = logLevel;
    opt_parser.thrift_port = m_thriftPort;
    opt_parser.console_logging = false;

    // Initialize the switch, with a device manager without ports (NoPortsDevMgr)
    status = init_from_options_parser(opt_parser, nullptr, std::make_unique<NoPortsDevMgr>());
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

void
P4SwitchCore::SetBmLogLevel(const std::string& level)
{
    m_bmLogLevel = level;
}

void
P4SwitchCore::SetThriftPort(uint16_t port)
{
    m_requestedThriftPort = port;
}

int
P4SwitchCore::GetThriftPort() const
{
    return m_thriftPort;
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

bool
P4SwitchCore::ReportCliErrors(const std::string& file,
                              const std::vector<std::pair<uint32_t, std::string>>& commands,
                              const std::string& output) const
{
    // The CLI prints its prompt before the output of each command, and once more
    // at the end of the commands
    const std::string prompt = "RuntimeCmd: ";
    const std::vector<std::string> signs = {"Error: ", "Invalid ", "*** Unknown syntax"};
    size_t command = 0;
    std::string last;    // the last line of this command that is not empty
    bool errors = false; // whether an error was printed
    auto report = [&](const std::string& error) {
        errors = true;
        std::cerr << file;
        if (command >= 1 && command <= commands.size())
        {
            const auto& [number, text] = commands[command - 1];
            std::cerr << ":" << number << ": " << text;
        }
        std::cerr << "\n    " << error << std::endl;
    };

    std::istringstream lines(output);
    for (std::string line; std::getline(lines, line);)
    {
        while (line.rfind(prompt, 0) == 0)
        {
            command++;
            last.clear();
            line.erase(0, prompt.size());
        }
        if (std::any_of(signs.begin(), signs.end(), [&line](const std::string& sign) {
                return line.rfind(sign, 0) == 0;
            }))
        {
            report(line);
        }
        if (!line.empty())
        {
            last = line;
        }
    }
    if (command <= commands.size())
    {
        report(m_thriftCommand +
               (command == 0 ? " failed, the file is skipped"
                             : " stopped here, the rest of the file is skipped") +
               (last.empty() ? "" : ": " + last));
    }
    return errors;
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

    // Without a flow table the tables keep the entries of the P4 program
    if (commandsFile.empty())
    {
        return 0;
    }
    std::vector<std::pair<uint32_t, std::string>> commands; // (line number, command)
    std::ostringstream input;
    {
        std::ifstream file(commandsFile);
        if (!file || std::filesystem::is_directory(commandsFile))
        {
            NS_FATAL_ERROR("Switch ID " << m_p4SwitchId << ": cannot open the flow table "
                                        << commandsFile);
        }
        // The CLI repeats the last command for an empty line and does not know
        // comments or the byte order mark of UTF-8, so it gets none of them
        uint32_t number = 0;
        for (std::string line; std::getline(file, line);)
        {
            number++;
            if (number == 1 && line.rfind("\xEF\xBB\xBF", 0) == 0)
            {
                line.erase(0, 3);
            }
            size_t start = line.find_first_not_of(" \t\r");
            if (start != std::string::npos && line[start] != '#')
            {
                line.erase(line.find_last_not_of(" \t\r") + 1);
                commands.emplace_back(number, line);
                input << line << "\n";
            }
        }
    }

    // Get runtime port and start the server
    int port = get_runtime_port();
    // The server thread points bm_runtime::processor_ to its processor, registers
    // BMv2's services, and then listens. For the second and later switches of a
    // process, start_server() returns before that, so wait until the server
    // listens (at most 5 s): then the services of this switch are registered
    // after BMv2's, and only to its own processor, never to the server of
    // another switch.
    // The server is started once per switch: later calls use it. A second
    // server could not bind the port, and BMv2 would end the process.
    if (!m_thriftServerStarted)
    {
        m_thriftServerStarted = true;
        auto previousProcessor = bm_runtime::processor_;
        bm_runtime::start_server(this, port);
        for (int i = 0; i < 500 && !ServerListens(port); i++)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (ServerListens(port) && bm_runtime::processor_ != previousProcessor)
        {
            GuardThriftServices();
        }
        else
        {
            NS_LOG_WARN("Switch ID: " << m_p4SwitchId
                                      << " Thrift server not started in time, so the commands "
                                         "of the target (e.g. mirroring_add) are not available");
        }
    }

    // The CLI reads the commands from a file in memory, which leaves nothing on the
    // disk if this process is killed. Hosts with vm.memfd_noexec=2 want the flag,
    // and Linux before 6.3 does not know it.
    int fd = memfd_create("p4sim-cli", MFD_NOEXEC_SEAL);
    if (fd < 0 && errno == EINVAL)
    {
        fd = memfd_create("p4sim-cli", 0);
    }
    std::string text = input.str();
    if (fd < 0 || write(fd, text.data(), text.size()) != static_cast<ssize_t>(text.size()) ||
        lseek(fd, 0, SEEK_SET) != 0)
    {
        NS_FATAL_ERROR("Switch ID " << m_p4SwitchId
                                    << ": cannot pass the flow table to the runtime CLI");
    }
    // The encoding lets the CLI read bytes that are not UTF-8: it reads the commands
    // in blocks, so such a byte would end it before the commands above run
    std::string cmd = "PYTHONIOENCODING=utf-8:surrogateescape " + m_thriftCommand +
                      " --thrift-port " + std::to_string(port);
    NS_LOG_DEBUG("Executing CLI command: " << cmd);
    std::string output = RunWithInput(cmd, fd);
    close(fd);
    return ReportCliErrors(commandsFile, commands, output) ? 1 : 0;
}

uint64_t
P4SwitchCore::GetTimeStamp()
{
    return Simulator::Now().GetNanoSeconds() - m_startTimestamp;
}

Ptr<Packet>
P4SwitchCore::ConvertToNs3Packet(std::unique_ptr<bm::Packet>&& bm_packet)
{
    CheckPendingSwap(); // the caller frees the packet once it is sent
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

const Address&
P4SwitchCore::GetDestination(int index) const
{
    NS_ASSERT_MSG(index >= 0 && static_cast<size_t>(index) < m_destinationList.size(),
                  "Switch " << m_p4SwitchId << ": no destination address " << index
                            << " (a packet copy whose registers were not set?)");
    return m_destinationList[index];
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

void
P4SwitchCore::AddThriftServices()
{
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