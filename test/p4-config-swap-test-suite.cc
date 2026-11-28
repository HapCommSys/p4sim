// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * Swapping the P4 program of a running switch (EnableSwap, load_new_config and
 * swap_configs). The switch starts with egress_ports, which sends the frames for
 * 00:00:00:00:00:01 to port 1, and swaps to swap, which sends them to port 2.
 * Host 0 sends on a 10 Gbps link and ports 1 and 2 have 1 Gbps links, so frames
 * queue up in the switch. BMv2 swaps only when the switch holds no packet: the
 * frames in the switch leave with the old program, and the frames that arrive
 * meanwhile wait for the swap and then use the new program.
 */

#include "ns3/core-module.h"
#include "ns3/eth-net-device.h"
#include "ns3/network-module.h"
#include "ns3/p4-controller.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-runtime-api.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4sim-ns3-compat.h"
#include "ns3/switched-ethernet-channel.h"
#include "ns3/test.h"

#include <fstream>
#include <sstream>

using namespace ns3;

namespace
{

constexpr uint32_t PAYLOAD = 1000; ///< bytes; frame k has PAYLOAD + k, plus the Ethernet header
constexpr uint32_t N_OLD = 10;     ///< frames sent before the swap is asked for
constexpr uint32_t N_NEW = 5;      ///< frames sent after it

/// A frame that reached a host
struct Arrival
{
    uint32_t frame; ///< its number k
    Time left;      ///< when the switch started to send it (1 Gbps link, no delay)
};

/// Records which frame arrived and when the switch sent it. Connected to the
/// PromiscSniffer trace: host 2 also gets the frames for host 1, after the swap.
void
Record(std::vector<Arrival>* arrivals, Ptr<const Packet> frame)
{
    Time serialisation = NanoSeconds(frame->GetSize() * 8); // at 1 Gbps
    arrivals->push_back({frame->GetSize() - 14 - PAYLOAD, Simulator::Now() - serialisation});
}

/// The content of a file
std::string
ReadFile(const std::string& path)
{
    std::ifstream in(path);
    std::ostringstream content;
    content << in.rdbuf();
    return content.str();
}

/// How a test asks for the swap
enum class SwapBy
{
    CONTROLLER, ///< P4Controller::LoadNewConfig() and SwapConfigs()
    CORE,       ///< load_new_config() and swap_configs() of the P4 core
    CLI,        ///< load_new_config_file and swap_configs in simple_switch_CLI
};

} // namespace

/**
 * Host 0 sends frames for host 1, asks for the swap, then sends more frames for
 * host 1. With an idle switch the swap takes effect at once. With a busy one
 * (frames queued for port 1), the frames sent before the swap still go to host 1,
 * and the frames sent after it go to host 2, all of them, in order; the first
 * one leaves the switch when the last old frame does.
 */
class ConfigSwapTestCase : public TestCase
{
  public:
    /**
     * Constructor
     * \param archName "v1model" or "psa"
     * \param arch P4SWITCH_ARCH_*
     * \param busy whether frames are queued in the switch when the swap is asked for
     * \param by how the swap is asked for
     * \param bufferSize TransferBufferSize; 0 leaves the attribute at its default
     */
    ConfigSwapTestCase(const std::string& archName,
                       uint32_t arch,
                       bool busy,
                       SwapBy by,
                       uint32_t bufferSize = 0)
        : TestCase(archName + ": a swap " +
                   (by == SwapBy::CLI          ? "from simple_switch_CLI "
                    : by == SwapBy::CONTROLLER ? "from P4Controller "
                                               : "") +
                   (busy ? "waits for the frames in the switch, and later frames use the new "
                           "program"
                         : "in an idle switch takes effect at once") +
                   (bufferSize > 0 ? ", also in a transfer buffer" : "")),
          m_archName(archName),
          m_arch(arch),
          m_busy(busy),
          m_by(by),
          m_bufferSize(bufferSize)
    {
    }

  private:
    void DoRun() override;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    /// Host 0 sends frame \p k to host 1
    void Send(uint32_t k);

    /// Load the new program and ask for the swap
    void Swap();

    std::string m_archName;
    uint32_t m_arch;
    bool m_busy;
    SwapBy m_by;
    uint32_t m_bufferSize; ///< TransferBufferSize
    Ptr<P4SwitchNetDevice> m_switch;
    P4Controller m_controller;
    std::vector<Ptr<SwitchedEthernetHostDevice>> m_hosts; ///< the host on each port
    std::vector<Arrival> m_arrivals[3];                   ///< arrivals per host
    bool m_pendingAfterRequest{false}; ///< whether the swap waited right after the request
};

void
ConfigSwapTestCase::Send(uint32_t k)
{
    m_hosts[0]->Send(Create<Packet>(PAYLOAD + k), m_hosts[1]->GetAddress(), 0x88b5);
}

void
ConfigSwapTestCase::Swap()
{
    std::string json = CreateDataDirFilename("p4src/swap/swap_" + m_archName + ".json");
    P4SwitchCore* core = m_switch->GetCore();
    switch (m_by)
    {
    case SwapBy::CONTROLLER:
        m_controller.LoadNewConfig(0, ReadFile(json));
        m_controller.SwapConfigs(0);
        break;
    case SwapBy::CORE:
        NS_TEST_EXPECT_MSG_EQ(core->load_new_config(ReadFile(json)),
                              bm::RuntimeInterface::SUCCESS,
                              "load_new_config failed");
        NS_TEST_EXPECT_MSG_EQ(core->swap_configs(),
                              bm::RuntimeInterface::SUCCESS,
                              "swap_configs failed");
        break;
    case SwapBy::CLI: {
        std::string commands = CreateTempDirFilename("swap-cli.txt");
        std::ofstream(commands) << "load_new_config_file " << json << "\nswap_configs\n";
        int status = core->ExecuteCliCommands(commands); // the macro may evaluate it twice
        NS_TEST_EXPECT_MSG_EQ(status, 0, "simple_switch_CLI failed");
        break;
    }
    }
    m_pendingAfterRequest = core->IsSwapPending();
}

void
ConfigSwapTestCase::DoRun()
{
    SetDataDir(NS_TEST_SOURCEDIR);
    Ptr<Node> switchNode = CreateObject<Node>();
    m_switch = CreateObject<P4SwitchNetDevice>();
    m_switch->SetAttribute("P4SwitchArch", UintegerValue(m_arch));
    m_switch->SetAttribute("JsonPath",
                           StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_" +
                                                             m_archName + ".json")));
    m_switch->SetAttribute("FlowTablePath", StringValue(""));
    m_switch->SetAttribute("EnableSwap", BooleanValue(true));
    m_switch->SetAttribute("BmLogLevel", StringValue("off"));
    if (m_bufferSize > 0)
    {
        m_switch->SetAttribute("TransferBufferSize", UintegerValue(m_bufferSize));
    }
    switchNode->AddDevice(m_switch);

    const char* macs[] = {"00:00:00:00:00:10", "00:00:00:00:00:01", "00:00:00:00:00:02"};
    const char* rates[] = {"10Gbps", "1Gbps", "1Gbps"};
    for (uint32_t i = 0; i < 3; i++)
    {
        Ptr<SwitchedEthernetChannel> channel = CreateObject<SwitchedEthernetChannel>();
        channel->SetAttribute("DataRate", DataRateValue(DataRate(rates[i])));
        m_switch->Attach(channel);
        Ptr<Node> node = CreateObject<Node>();
        Ptr<SwitchedEthernetHostDevice> host = CreateObject<SwitchedEthernetHostDevice>();
        host->SetAddress(Mac48Address(macs[i]));
        node->AddDevice(host);
        host->Attach(channel);
        host->TraceConnectWithoutContext("PromiscSniffer",
                                         MakeBoundCallback(&Record, &m_arrivals[i]));
        m_hosts.push_back(host);
    }
    m_switch->Initialize();
    m_controller.RegisterSwitch(m_switch);

    // One frame per microsecond. Port 1 takes about 8 us per frame, so in the
    // busy case nine frames still wait in the switch at 20 us; in the idle case
    // the only frame has left by then.
    uint32_t nOld = m_busy ? N_OLD : 1;
    for (uint32_t k = 0; k < nOld; k++)
    {
        Simulator::Schedule(MicroSeconds(1 + k), &ConfigSwapTestCase::Send, this, k);
    }
    Simulator::Schedule(MicroSeconds(20), &ConfigSwapTestCase::Swap, this);
    for (uint32_t k = nOld; k < nOld + N_NEW; k++)
    {
        Simulator::Schedule(MicroSeconds(21 + k - nOld), &ConfigSwapTestCase::Send, this, k);
    }
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_EXPECT_MSG_EQ(m_pendingAfterRequest, m_busy, "Wrong state right after the request");
    NS_TEST_EXPECT_MSG_EQ(m_switch->GetCore()->IsSwapPending(), false, "The swap never happened");
    // The old program sent frames 0 .. nOld-1 to host 1, the new one the rest to host 2
    NS_TEST_EXPECT_MSG_EQ(m_arrivals[1].size(), nOld, "Host 1 got the wrong number of frames");
    NS_TEST_EXPECT_MSG_EQ(m_arrivals[2].size(), N_NEW, "Host 2 got the wrong number of frames");
    if (m_arrivals[1].size() != nOld || m_arrivals[2].size() != N_NEW)
    {
        return;
    }
    for (uint32_t i = 0; i < nOld; i++)
    {
        NS_TEST_EXPECT_MSG_EQ(m_arrivals[1][i].frame, i, "Host 1: wrong frame or order");
    }
    for (uint32_t i = 0; i < N_NEW; i++)
    {
        NS_TEST_EXPECT_MSG_EQ(m_arrivals[2][i].frame, nOld + i, "Host 2: wrong frame or order");
    }
    // No frame with the new program left the switch before the last one with
    // the old program. In a busy switch the first one leaves just then: the held
    // frames enter the pipeline as soon as the switch is empty, and port 2 is idle.
    if (m_busy)
    {
        NS_TEST_EXPECT_MSG_EQ(m_arrivals[2].front().left,
                              m_arrivals[1].back().left,
                              "The swap did not take place when the last old frame left");
    }
    NS_TEST_EXPECT_MSG_GT_OR_EQ(m_arrivals[2].front().left,
                                m_arrivals[1].back().left,
                                "A frame used the new program before the old frames had left");
}

/**
 * Without EnableSwap, BMv2 refuses to load a new program, and the switch keeps
 * forwarding with its program.
 */
class ConfigSwapDisabledTestCase : public TestCase
{
  public:
    ConfigSwapDisabledTestCase()
        : TestCase("v1model: without EnableSwap the program stays")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        Ptr<Node> switchNode = CreateObject<Node>();
        Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
        sw->SetAttribute(
            "JsonPath",
            StringValue(CreateDataDirFilename("p4src/egress_ports/egress_ports_v1model.json")));
        sw->SetAttribute("FlowTablePath", StringValue(""));
        sw->SetAttribute("BmLogLevel", StringValue("off"));
        switchNode->AddDevice(sw);
        sw->Initialize();

        P4SwitchCore* core = sw->GetCore();
        P4RuntimeApi api(*core);
        std::string json = ReadFile(CreateDataDirFilename("p4src/swap/swap_v1model.json"));
        NS_TEST_EXPECT_MSG_EQ(api.LoadNewConfig(json), -1, "A program was loaded");
        NS_TEST_EXPECT_MSG_EQ(api.SwapConfigs(), -1, "A swap was accepted");
        NS_TEST_EXPECT_MSG_EQ(core->IsSwapPending(), false, "A swap waits");
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * Swapping the P4 program of a running switch.
 */
static class P4ConfigSwapTestSuite : public TestSuite
{
  public:
    P4ConfigSwapTestSuite()
        : TestSuite("p4-config-swap", TestSuite::Type::UNIT)
    {
        AddTestCase(
            new ConfigSwapTestCase("v1model", P4SWITCH_ARCH_V1MODEL, false, SwapBy::CONTROLLER),
            P4SIM_TEST_QUICK);
        AddTestCase(
            new ConfigSwapTestCase("v1model", P4SWITCH_ARCH_V1MODEL, true, SwapBy::CONTROLLER),
            P4SIM_TEST_QUICK);
        AddTestCase(new ConfigSwapTestCase("v1model", P4SWITCH_ARCH_V1MODEL, true, SwapBy::CLI),
                    P4SIM_TEST_QUICK);
        AddTestCase(new ConfigSwapTestCase("psa", P4SWITCH_ARCH_PSA, true, SwapBy::CORE),
                    P4SIM_TEST_QUICK);
        AddTestCase(
            new ConfigSwapTestCase("v1model", P4SWITCH_ARCH_V1MODEL, true, SwapBy::CONTROLLER, 2),
            P4SIM_TEST_QUICK);
        AddTestCase(new ConfigSwapTestCase("psa", P4SWITCH_ARCH_PSA, true, SwapBy::CORE, 2),
                    P4SIM_TEST_QUICK);
        AddTestCase(new ConfigSwapDisabledTestCase, P4SIM_TEST_QUICK);
    }
} g_p4ConfigSwapTestSuite;
