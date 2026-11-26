// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * The externs of PSA and PNA programs (utils/psa_externs): their meters count
 * simulation time, and the runtime API (runtime CLI, P4RuntimeApi) reaches
 * their counters and meters. The program is p4src/externs: it counts (PSA) and
 * meters a frame with EtherType 0x88b5 at the index in its first byte, writes
 * the meter color into its second byte (0 red, 1 green, 2 yellow) and sends it
 * to port 1. The packet tests of these externs are in p4-packet
 * (p4src/externs/psa.stf, pna.stf).
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-runtime-api.h"
#include "ns3/p4-switch-core.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4sim-ns3-compat.h"
#include "ns3/test.h"

#include <vector>

using namespace ns3;

namespace
{

constexpr uint32_t N_PORTS = 3;
constexpr uint8_t RED = 0;
constexpr uint8_t GREEN = 1;
constexpr uint8_t YELLOW = 2;

/// A switch that runs p4src/externs, with a host on each of its three ports;
/// it records the meter color of each frame that the host on port 1 receives
class ExternSwitch
{
  public:
    /**
     * @param arch P4SwitchArch
     * @param json path of the program
     * @param flowTable path of the flow-table file, or empty
     */
    ExternSwitch(uint32_t arch, const std::string& json, const std::string& flowTable)
    {
        Ptr<Node> switchNode = CreateObject<Node>();
        Ptr<Node> hostNode = CreateObject<Node>();
        sw = CreateObject<P4SwitchNetDevice>();
        sw->SetAttribute("P4SwitchArch", UintegerValue(arch));
        sw->SetAttribute("JsonPath", StringValue(json));
        sw->SetAttribute("FlowTablePath", StringValue(flowTable));
        switchNode->AddDevice(sw);
        for (uint32_t i = 0; i < N_PORTS; i++)
        {
            Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
            Ptr<SimpleNetDevice> port = CreateObject<SimpleNetDevice>();
            Ptr<SimpleNetDevice> host = CreateObject<SimpleNetDevice>();
            port->SetAddress(Mac48Address::Allocate());
            port->SetAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
            host->SetAddress(Mac48Address::Allocate());
            port->SetChannel(channel);
            host->SetChannel(channel);
            switchNode->AddDevice(port);
            hostNode->AddDevice(host);
            sw->AddBridgePort(port);
            m_hosts.push_back(host);
        }
        m_hosts[1]->SetPromiscReceiveCallback(MakeCallback(&ExternSwitch::Receive, this));
        sw->Initialize();
    }

    /// Host 0 sends a frame with meter index \p idx at time \p t
    void SendAt(Time t, uint8_t idx)
    {
        Simulator::Schedule(t, &ExternSwitch::Send, this, idx);
    }

    Ptr<P4SwitchNetDevice> sw;   //!< the switch
    std::vector<uint8_t> colors; //!< meter colors of the received frames, in order

  private:
    void Send(uint8_t idx)
    {
        // ext_t of externs_*.p4: idx, color, a..d, crc, csum, rnd, rnd_ok, pad
        std::vector<uint8_t> ext(18, 0);
        ext[0] = idx;
        Ptr<Packet> frame = Create<Packet>(ext.data(), ext.size());
        m_hosts[0]->SendFrom(frame,
                             Mac48Address("00:00:00:00:00:02"),
                             Mac48Address("00:00:00:00:00:01"),
                             0x88b5);
    }

    bool Receive(Ptr<NetDevice> host,
                 Ptr<const Packet> packet,
                 uint16_t protocol,
                 const Address& from,
                 const Address& to,
                 NetDevice::PacketType type)
    {
        uint8_t ext[2] = {0, 0};
        packet->CopyData(ext, 2);
        colors.push_back(ext[1]);
        return true;
    }

    std::vector<Ptr<SimpleNetDevice>> m_hosts;
};

/// The rates of the meter tests, in packets per microsecond: committed 1 per
/// millisecond, peak 2 per millisecond, bursts of 1 packet
const std::vector<bm::Meter::rate_config_t> RATES = {{0.001, 1}, {0.002, 1}};

} // namespace

/**
 * A meter of a PSA or PNA program measures the simulation time: frames at
 * 1.0, 1.1, 3.0 and 3.6 ms give green, red (the peak bucket is empty), green
 * (both refilled) and yellow (only the peak bucket has refilled). With
 * wall-clock time, as in BMv2's own externs, the third frame would be red: the
 * simulation runs the four frames within microseconds.
 */
class ExternMeterTimeTestCase : public TestCase
{
  public:
    /**
     * @param archName "psa" or "pna"
     * @param arch P4SwitchArch
     * @param meter the name of the meter extern in the JSON
     * @param byCli true: the flow-table file sets the rates (runtime CLI);
     *              false: P4RuntimeApi does
     */
    ExternMeterTimeTestCase(const std::string& archName,
                            uint32_t arch,
                            const std::string& meter,
                            bool byCli)
        : TestCase(archName + ": a meter extern counts simulation time (rates set by " +
                   (byCli ? "the runtime CLI)" : "P4RuntimeApi)")),
          m_archName(archName),
          m_arch(arch),
          m_meter(meter),
          m_byCli(byCli)
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        std::string dir = "p4src/externs/";
        ExternSwitch s(m_arch,
                       CreateDataDirFilename(dir + "externs_" + m_archName + ".json"),
                       m_byCli ? CreateDataDirFilename(dir + "meter_" + m_archName + ".txt") : "");
        if (!m_byCli)
        {
            P4RuntimeApi api(*s.sw->GetCore());
            NS_TEST_ASSERT_MSG_EQ(api.SetMeterArrayRates(m_meter, RATES), 0, "Cannot set rates");
        }
        s.SendAt(MicroSeconds(1000), 0);
        s.SendAt(MicroSeconds(1100), 0);
        s.SendAt(MicroSeconds(3000), 0);
        s.SendAt(MicroSeconds(3600), 0);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();

        const std::vector<uint8_t> expected = {GREEN, RED, GREEN, YELLOW};
        NS_TEST_ASSERT_MSG_EQ(s.colors.size(), expected.size(), "Frames received");
        for (size_t i = 0; i < expected.size(); i++)
        {
            NS_TEST_EXPECT_MSG_EQ(int(s.colors[i]), int(expected[i]), "Color of frame " << i);
        }
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    std::string m_archName;
    uint32_t m_arch;
    std::string m_meter;
    bool m_byCli;
};

/**
 * The runtime API reaches the counter extern of a PSA program: read, write
 * and reset, with errors for an index out of range and for an unknown name
 */
class ExternCounterApiTestCase : public TestCase
{
  public:
    ExternCounterApiTestCase()
        : TestCase("psa: the runtime API reads, writes and resets a counter extern")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        ExternSwitch s(P4SWITCH_ARCH_PSA,
                       CreateDataDirFilename("p4src/externs/externs_psa.json"),
                       "");
        s.SendAt(MilliSeconds(1), 0);
        s.SendAt(MilliSeconds(1), 0);
        s.SendAt(MilliSeconds(1), 2);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
        NS_TEST_ASSERT_MSG_EQ(s.colors.size(), 3, "Frames received");

        const std::string name = "IngressImpl.frames";
        P4RuntimeApi api(*s.sw->GetCore());
        bm::MatchTableAbstract::counter_value_t bytes = 0;
        bm::MatchTableAbstract::counter_value_t packets = 0;
        const std::vector<std::pair<size_t, uint64_t>> counts = {{0, 2}, {1, 0}, {2, 1}, {3, 0}};
        for (const auto& [index, expected] : counts)
        {
            NS_TEST_ASSERT_MSG_EQ(api.ReadCounter(name, index, &bytes, &packets), 0, "Read");
            NS_TEST_EXPECT_MSG_EQ(packets, expected, "Packets at index " << index);
        }
        NS_TEST_EXPECT_MSG_EQ(api.ReadCounter(name, 4, &bytes, &packets), -1, "Index 4");
        NS_TEST_EXPECT_MSG_EQ(api.ReadCounter("IngressImpl.nothing", 0, &bytes, &packets),
                              -1,
                              "Unknown counter");

        NS_TEST_ASSERT_MSG_EQ(api.WriteCounter(name, 1, 1000, 7), 0, "Write");
        NS_TEST_ASSERT_MSG_EQ(api.ReadCounter(name, 1, &bytes, &packets), 0, "Read");
        NS_TEST_EXPECT_MSG_EQ(bytes, 1000, "Written bytes");
        NS_TEST_EXPECT_MSG_EQ(packets, 7, "Written packets");

        NS_TEST_ASSERT_MSG_EQ(api.ResetCounter(name), 0, "Reset");
        for (size_t index = 0; index < 4; index++)
        {
            NS_TEST_ASSERT_MSG_EQ(api.ReadCounter(name, index, &bytes, &packets), 0, "Read");
            NS_TEST_EXPECT_MSG_EQ(packets, 0, "Packets after the reset at index " << index);
        }
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }
};

/**
 * The runtime API sets, reads and unsets the rates of a meter extern, for one
 * index and for the whole array; an index out of range is an error. A meter
 * without rates gives green.
 */
class ExternMeterApiTestCase : public TestCase
{
  public:
    ExternMeterApiTestCase(const std::string& archName, uint32_t arch, const std::string& meter)
        : TestCase(archName + ": the runtime API sets, reads and unsets meter rates"),
          m_archName(archName),
          m_arch(arch),
          m_meter(meter)
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        ExternSwitch s(m_arch,
                       CreateDataDirFilename("p4src/externs/externs_" + m_archName + ".json"),
                       "");
        P4RuntimeApi api(*s.sw->GetCore());
        std::vector<bm::Meter::rate_config_t> configs;

        NS_TEST_ASSERT_MSG_EQ(api.MeterSetRates(m_meter, 1, RATES), 0, "Set index 1");
        NS_TEST_ASSERT_MSG_EQ(api.MeterGetRates(m_meter, 1, &configs), 0, "Get index 1");
        NS_TEST_ASSERT_MSG_EQ(configs.size(), RATES.size(), "Rates of index 1");
        for (size_t i = 0; i < RATES.size(); i++)
        {
            NS_TEST_EXPECT_MSG_EQ_TOL(configs[i].info_rate, RATES[i].info_rate, 1e-12, "Rate " << i);
            NS_TEST_EXPECT_MSG_EQ(configs[i].burst_size, RATES[i].burst_size, "Burst " << i);
        }
        configs.clear();
        NS_TEST_ASSERT_MSG_EQ(api.MeterGetRates(m_meter, 0, &configs), 0, "Get index 0");
        NS_TEST_EXPECT_MSG_EQ(configs.size(), 0, "Index 0 has no rates");

        NS_TEST_ASSERT_MSG_EQ(api.MeterResetRates(m_meter, 1), 0, "Reset index 1");
        NS_TEST_ASSERT_MSG_EQ(api.MeterGetRates(m_meter, 1, &configs), 0, "Get index 1");
        NS_TEST_EXPECT_MSG_EQ(configs.size(), 0, "Index 1 has no rates after the reset");

        NS_TEST_ASSERT_MSG_EQ(api.SetMeterArrayRates(m_meter, RATES), 0, "Set the array");
        for (size_t idx = 0; idx < 4; idx++)
        {
            configs.clear();
            NS_TEST_ASSERT_MSG_EQ(api.MeterGetRates(m_meter, idx, &configs), 0, "Get");
            NS_TEST_EXPECT_MSG_EQ(configs.size(), RATES.size(), "Rates of index " << idx);
        }
        NS_TEST_EXPECT_MSG_EQ(api.MeterSetRates(m_meter, 4, RATES), -1, "Index 4");
        NS_TEST_EXPECT_MSG_EQ(api.MeterGetRates(m_meter, 4, &configs), -1, "Index 4");
        NS_TEST_EXPECT_MSG_EQ(api.MeterResetRates(m_meter, 4), -1, "Index 4");

        // Index 2 without rates again: its frames are green
        NS_TEST_ASSERT_MSG_EQ(api.MeterResetRates(m_meter, 2), 0, "Reset index 2");
        s.SendAt(MilliSeconds(1), 2);
        s.SendAt(MilliSeconds(1), 2);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
        NS_TEST_ASSERT_MSG_EQ(s.colors.size(), 2, "Frames received");
        NS_TEST_EXPECT_MSG_EQ(int(s.colors[0]), int(GREEN), "No rates: green");
        NS_TEST_EXPECT_MSG_EQ(int(s.colors[1]), int(GREEN), "No rates: green");
    }

    void DoTeardown() override
    {
        Simulator::Destroy();
    }

    std::string m_archName;
    uint32_t m_arch;
    std::string m_meter;
};

/// The PSA and PNA externs with the runtime API and with simulation time
static class P4ExternsTestSuite : public TestSuite
{
  public:
    P4ExternsTestSuite()
        : TestSuite("p4-externs", TestSuite::Type::UNIT)
    {
        AddTestCase(new ExternMeterTimeTestCase("psa", P4SWITCH_ARCH_PSA, "IngressImpl.meter", true),
                    P4SIM_TEST_QUICK);
        AddTestCase(
            new ExternMeterTimeTestCase("psa", P4SWITCH_ARCH_PSA, "IngressImpl.meter", false),
            P4SIM_TEST_QUICK);
        AddTestCase(
            new ExternMeterTimeTestCase("pna", P4NIC_ARCH_PNA, "MainControlImpl.meter", false),
            P4SIM_TEST_QUICK);
        AddTestCase(new ExternCounterApiTestCase(), P4SIM_TEST_QUICK);
        AddTestCase(new ExternMeterApiTestCase("psa", P4SWITCH_ARCH_PSA, "IngressImpl.meter"),
                    P4SIM_TEST_QUICK);
        AddTestCase(new ExternMeterApiTestCase("pna", P4NIC_ARCH_PNA, "MainControlImpl.meter"),
                    P4SIM_TEST_QUICK);
    }
} g_p4ExternsTestSuite;
