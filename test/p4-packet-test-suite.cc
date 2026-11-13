// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * Packet tests in the style of p4c's STF files: frames are sent into the ports of
 * one P4 switch, and the frames that leave it are compared with the expected ones.
 *
 * An .stf file has one command per line; '#' starts a comment:
 *   packet <port> <hex>   send this Ethernet frame into the switch on <port>
 *   expect <port> <hex>   this frame leaves the switch on <port>; '*' matches any nibble
 *   mirroring_add <session> <port>   the clones of this mirroring session leave on <port>
 *   mirroring_add_mc <session> <group>   they go to multicast group <group> (v1model)
 * Spaces in <hex> are ignored. All frames are sent at the same time, in file order.
 * A test passes if every port sends exactly the frames expected on it, in that
 * order. The switch has three ports, 0 to 2.
 *
 * On v1model, these commands of simple_switch_CLI configure multicast:
 *   mc_mgrp_create <group>                       create a multicast group
 *   mc_node_create <rid> <port>... [| <lag>...]  create a node; nodes get the handles 0, 1, ...
 *   mc_node_associate <group> <node handle>      add a node to a group
 *   mc_set_lag_membership <lag> <port>...        set the member ports of a LAG
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/test.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>

using namespace ns3;

namespace
{

constexpr uint32_t N_PORTS = 3;

/// A "packet" or "expect" command of an .stf file
struct StfFrame
{
    uint32_t port;
    std::string hex; ///< lower case, no spaces
    int line;
};

/// A multicast command of an .stf file, as in simple_switch_CLI
struct StfMcCommand
{
    std::string cmd;
    std::vector<uint32_t> args; ///< the numbers, without the LAGs of mc_node_create
    std::vector<uint32_t> lags; ///< mc_node_create: the LAGs, after '|'
    int line;
};

/// True if \p frame matches \p expected, in which '*' matches any nibble
bool
Matches(const std::string& expected, const std::string& frame)
{
    if (expected.size() != frame.size())
    {
        return false;
    }
    for (size_t i = 0; i < frame.size(); i++)
    {
        if (expected[i] != '*' && expected[i] != frame[i])
        {
            return false;
        }
    }
    return true;
}

} // namespace

/// Runs p4src/<program>/<stf> on p4src/<program>/<program>_<archName>.json
class StfTestCase : public TestCase
{
  public:
    StfTestCase(const std::string& program,
                const std::string& archName,
                uint32_t arch,
                const std::string& stf)
        : TestCase(archName + ": " + stf),
          m_program(program),
          m_archName(archName),
          m_arch(arch),
          m_stf(stf)
    {
    }

  private:
    void DoRun() override;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// Reads the .stf file; returns an error message, empty on success
    std::string ReadStf(const std::string& path);

    /// Reads the arguments of a multicast command; returns an error message, empty on success
    std::string ReadMcCommand(const std::string& cmd, std::istringstream& words, int line);

    /// Configures the packet replication engine of the switch with the multicast
    /// commands; returns an error message, empty on success
    std::string ApplyMcCommands(Ptr<P4SwitchNetDevice> sw) const;

    /// The host on the frame's port sends it to the switch
    void Send(const StfFrame& frame);

    /// A host received a frame from the switch
    bool Receive(Ptr<NetDevice> host,
                 Ptr<const Packet> packet,
                 uint16_t protocol,
                 const Address& from,
                 const Address& to,
                 NetDevice::PacketType type);

    std::string m_program;
    std::string m_archName;
    uint32_t m_arch;
    std::string m_stf;
    std::vector<StfMcCommand> m_mcCommands; ///< in file order
    std::vector<StfFrame> m_packets;
    std::vector<StfFrame> m_expects;
    std::vector<std::pair<uint32_t, uint32_t>> m_mirroringSessions; ///< (session, port)
    std::vector<std::pair<uint32_t, uint32_t>> m_mcMirroringSessions; ///< (session, group)
    std::vector<Ptr<SimpleNetDevice>> m_hosts;        ///< one per switch port
    std::vector<std::string> m_received[N_PORTS]; ///< frames sent by each port, in hex
};

std::string
StfTestCase::ReadStf(const std::string& path)
{
    std::ifstream in(path);
    if (!in)
    {
        return "cannot open " + path;
    }
    std::string line;
    for (int n = 1; std::getline(in, line); n++)
    {
        std::istringstream words(line.substr(0, line.find('#')));
        std::string cmd;
        std::string hex;
        std::string word;
        uint32_t port = 0;
        if (!(words >> cmd))
        {
            continue;
        }
        if (cmd == "mirroring_add")
        {
            uint32_t session = 0;
            if (!(words >> session >> port) || port >= N_PORTS || (words >> word))
            {
                return m_stf + " line " + std::to_string(n) +
                       ": expected 'mirroring_add <session> <port 0-2>'";
            }
            m_mirroringSessions.emplace_back(session, port);
            continue;
        }
        if (cmd == "mirroring_add_mc")
        {
            uint32_t session = 0;
            uint32_t group = 0;
            if (!(words >> session >> group) || (words >> word))
            {
                return m_stf + " line " + std::to_string(n) +
                       ": expected 'mirroring_add_mc <session> <group>'";
            }
            m_mcMirroringSessions.emplace_back(session, group);
            continue;
        }
        if (cmd == "mc_mgrp_create" || cmd == "mc_node_create" || cmd == "mc_node_associate" ||
            cmd == "mc_set_lag_membership")
        {
            std::string error = ReadMcCommand(cmd, words, n);
            if (!error.empty())
            {
                return error;
            }
            continue;
        }
        bool valid = (cmd == "packet" || cmd == "expect") && (words >> port) && port < N_PORTS;
        while (words >> word)
        {
            hex += word;
        }
        std::transform(hex.begin(), hex.end(), hex.begin(), ::tolower);
        std::string digits = (cmd == "packet") ? "0123456789abcdef" : "0123456789abcdef*";
        valid = valid && hex.size() >= 28 && hex.size() % 2 == 0 &&
                hex.find_first_not_of(digits) == std::string::npos;
        if (!valid)
        {
            return m_stf + " line " + std::to_string(n) +
                   ": expected 'packet|expect <port 0-2> <Ethernet frame in hex>'";
        }
        (cmd == "packet" ? m_packets : m_expects).push_back({port, hex, n});
    }
    return "";
}

std::string
StfTestCase::ReadMcCommand(const std::string& cmd, std::istringstream& words, int line)
{
    StfMcCommand mc{cmd, {}, {}, line};
    bool valid = true;
    bool afterPipe = false;
    std::string word;
    while (words >> word)
    {
        if (word == "|" && cmd == "mc_node_create" && !afterPipe)
        {
            afterPipe = true;
        }
        else if (word.size() <= 9 && word.find_first_not_of("0123456789") == std::string::npos)
        {
            (afterPipe ? mc.lags : mc.args).push_back(std::stoul(word));
        }
        else
        {
            valid = false;
        }
    }
    // The first number is a group, a rid or a LAG. The numbers after it are
    // ports (mc_node_create, mc_set_lag_membership) or a node handle.
    size_t count = mc.args.size();
    bool hasPorts = (cmd == "mc_node_create" || cmd == "mc_set_lag_membership");
    valid = valid && count >= 1 && (hasPorts || count == (cmd == "mc_mgrp_create" ? 1u : 2u));
    for (size_t i = 1; hasPorts && i < count; i++)
    {
        valid = valid && mc.args[i] < bm::McSimplePre::PORT_MAP_SIZE;
    }
    valid = valid && (cmd != "mc_set_lag_membership" || mc.args[0] < bm::McSimplePre::LAG_MAP_SIZE);
    for (uint32_t lag : mc.lags)
    {
        valid = valid && lag < bm::McSimplePre::LAG_MAP_SIZE;
    }
    if (!valid)
    {
        return m_stf + " line " + std::to_string(line) +
               ": expected 'mc_mgrp_create <group>', 'mc_node_create <rid> <port>... [| "
               "<lag>...]', 'mc_node_associate <group> <node handle>' or "
               "'mc_set_lag_membership <lag> <port>...', with ports and LAGs below 512";
    }
    m_mcCommands.push_back(mc);
    return "";
}

std::string
StfTestCase::ApplyMcCommands(Ptr<P4SwitchNetDevice> sw) const
{
    if (m_mcCommands.empty())
    {
        return "";
    }
    if (!sw->GetV1ModelCore())
    {
        return m_stf + ": the multicast commands need v1model";
    }
    auto pre = sw->GetV1ModelCore()->get_component<bm::McSimplePreLAG>();
    for (const StfMcCommand& mc : m_mcCommands)
    {
        bm::McSimplePre::PortMap ports;
        bm::McSimplePre::LagMap lags;
        if (mc.cmd == "mc_node_create" || mc.cmd == "mc_set_lag_membership")
        {
            for (size_t i = 1; i < mc.args.size(); i++)
            {
                ports[mc.args[i]] = true;
            }
        }
        for (uint32_t lag : mc.lags)
        {
            lags[lag] = true;
        }
        bm::McSimplePre::mgrp_hdl_t group = 0;
        bm::McSimplePre::l1_hdl_t node = 0;
        bm::McSimplePre::McReturnCode rc;
        if (mc.cmd == "mc_mgrp_create")
        {
            rc = pre->mc_mgrp_create(mc.args[0], &group);
        }
        else if (mc.cmd == "mc_node_create")
        {
            rc = pre->mc_node_create(mc.args[0], ports, lags, &node);
        }
        else if (mc.cmd == "mc_node_associate")
        {
            // As with simple_switch_CLI, the handle of a group is its ID
            rc = pre->mc_node_associate(mc.args[0], mc.args[1]);
        }
        else
        {
            rc = pre->mc_set_lag_membership(static_cast<bm::McSimplePreLAG::lag_id_t>(mc.args[0]),
                                            ports);
        }
        if (rc != bm::McSimplePre::SUCCESS)
        {
            return m_stf + " line " + std::to_string(mc.line) + ": " + mc.cmd +
                   " failed with code " + std::to_string(rc);
        }
    }
    return "";
}

void
StfTestCase::Send(const StfFrame& frame)
{
    std::vector<uint8_t> bytes(frame.hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); i++)
    {
        bytes[i] = std::stoi(frame.hex.substr(2 * i, 2), nullptr, 16);
    }
    Mac48Address dst;
    Mac48Address src;
    dst.CopyFrom(&bytes[0]);
    src.CopyFrom(&bytes[6]);
    uint16_t type = bytes[12] << 8 | bytes[13];
    Ptr<Packet> payload = Create<Packet>(bytes.data() + 14, bytes.size() - 14);
    m_hosts[frame.port]->SendFrom(payload, src, dst, type);
}

bool
StfTestCase::Receive(Ptr<NetDevice> host,
                     Ptr<const Packet> packet,
                     uint16_t protocol,
                     const Address& from,
                     const Address& to,
                     NetDevice::PacketType type)
{
    // The host device has removed the Ethernet header: put it back
    std::vector<uint8_t> frame(14 + packet->GetSize());
    Mac48Address::ConvertFrom(to).CopyTo(&frame[0]);
    Mac48Address::ConvertFrom(from).CopyTo(&frame[6]);
    frame[12] = protocol >> 8;
    frame[13] = protocol & 0xff;
    packet->CopyData(&frame[14], packet->GetSize());

    std::ostringstream hex;
    for (uint8_t byte : frame)
    {
        hex << std::hex << std::setw(2) << std::setfill('0') << int(byte);
    }
    auto port = std::find(m_hosts.begin(), m_hosts.end(), host) - m_hosts.begin();
    m_received[port].push_back(hex.str());
    return true;
}

void
StfTestCase::DoRun()
{
    SetDataDir(NS_TEST_SOURCEDIR);
    std::string dir = "p4src/" + m_program + "/";
    std::string error = ReadStf(CreateDataDirFilename(dir + m_stf));
    NS_TEST_ASSERT_MSG_EQ(error, "", "Invalid .stf file");
    if (!error.empty())
    {
        return;
    }

    // A switch with N_PORTS ports, each linked to a host device
    Ptr<Node> switchNode = CreateObject<Node>();
    Ptr<Node> hostNode = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("P4SwitchArch", UintegerValue(m_arch));
    sw->SetAttribute(
        "JsonPath",
        StringValue(CreateDataDirFilename(dir + m_program + "_" + m_archName + ".json")));
    sw->SetAttribute("FlowTablePath", StringValue(""));
    sw->SetAttribute("BmLogLevel", StringValue("off"));
    switchNode->AddDevice(sw);
    for (uint32_t i = 0; i < N_PORTS; i++)
    {
        Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
        Ptr<SimpleNetDevice> port = CreateObject<SimpleNetDevice>();
        Ptr<SimpleNetDevice> host = CreateObject<SimpleNetDevice>();
        port->SetAddress(Mac48Address::Allocate());
        host->SetAddress(Mac48Address::Allocate());
        port->SetChannel(channel);
        host->SetChannel(channel);
        switchNode->AddDevice(port);
        hostNode->AddDevice(host);
        sw->AddBridgePort(port);
        host->SetPromiscReceiveCallback(MakeCallback(&StfTestCase::Receive, this));
        m_hosts.push_back(host);
    }
    sw->Initialize();
    for (const auto& [session, port] : m_mirroringSessions)
    {
        NS_TEST_ASSERT_MSG_EQ(sw->AddMirroringSession(session, port),
                              true,
                              "Cannot add mirroring session " << session);
    }
    for (const auto& [session, group] : m_mcMirroringSessions)
    {
        NS_TEST_ASSERT_MSG_EQ(sw->AddMulticastMirroringSession(session, group),
                              true,
                              "Cannot add mirroring session " << session);
    }
    error = ApplyMcCommands(sw);
    NS_TEST_ASSERT_MSG_EQ(error, "", "Cannot configure multicast");

    // All frames at once, in file order: frames to the same port queue up
    for (const StfFrame& frame : m_packets)
    {
        Simulator::Schedule(MilliSeconds(1), &StfTestCase::Send, this, frame);
    }
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    for (uint32_t port = 0; port < N_PORTS; port++)
    {
        std::vector<const StfFrame*> expected;
        for (const StfFrame& frame : m_expects)
        {
            if (frame.port == port)
            {
                expected.push_back(&frame);
            }
        }
        const std::vector<std::string>& received = m_received[port];
        for (size_t i = 0; i < std::max(expected.size(), received.size()); i++)
        {
            std::string frame = i < received.size() ? received[i] : "nothing";
            if (i < expected.size())
            {
                NS_TEST_EXPECT_MSG_EQ(Matches(expected[i]->hex, frame),
                                      true,
                                      m_stf << " line " << expected[i]->line << ": port " << port
                                            << " expected " << expected[i]->hex << ", got "
                                            << frame);
            }
            else
            {
                NS_TEST_EXPECT_MSG_EQ(frame, "nothing", "Unexpected frame on port " << port);
            }
        }
    }
}

/// Every architecture runs the same program, p4src/forward, with the same .stf
/// files; p4src/priority checks the priority queues of v1model, p4src/resubmit
/// and p4src/recirculate its resubmit and recirculation, p4src/clone its clones
/// (also to a multicast group),
/// and p4src/primitives digest(), hash() with max 0 and random() with lo > hi
static class P4PacketTestSuite : public TestSuite
{
  public:
    P4PacketTestSuite()
        : TestSuite("p4-packet", UNIT)
    {
        const std::vector<std::pair<std::string, uint32_t>> archs = {
            {"v1model", P4SWITCH_ARCH_V1MODEL},
            {"pna", P4NIC_ARCH_PNA},
            {"psa", P4SWITCH_ARCH_PSA},
        };
        for (const auto& [name, arch] : archs)
        {
            for (const char* stf : {"ipv4.stf", "drop.stf", "ports.stf"})
            {
                AddTestCase(new StfTestCase("forward", name, arch, stf), TestCase::QUICK);
            }
        }
        AddTestCase(new StfTestCase("priority", "v1model", P4SWITCH_ARCH_V1MODEL, "priority.stf"),
                    TestCase::QUICK);
        AddTestCase(new StfTestCase("resubmit", "v1model", P4SWITCH_ARCH_V1MODEL, "resubmit.stf"),
                    TestCase::QUICK);
        AddTestCase(
            new StfTestCase("recirculate", "v1model", P4SWITCH_ARCH_V1MODEL, "recirculate.stf"),
            TestCase::QUICK);
        AddTestCase(new StfTestCase("clone", "v1model", P4SWITCH_ARCH_V1MODEL, "clone.stf"),
                    TestCase::QUICK);
        AddTestCase(new StfTestCase("clone", "v1model", P4SWITCH_ARCH_V1MODEL, "clone_mc.stf"),
                    TestCase::QUICK);
        AddTestCase(
            new StfTestCase("primitives", "v1model", P4SWITCH_ARCH_V1MODEL, "primitives.stf"),
            TestCase::QUICK);
    }
} g_p4PacketTestSuite;
