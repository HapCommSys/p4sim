// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * Switch set-up: every architecture loads its P4 program, Thrift ports never
 * collide, and BmLogLevel controls the BMv2 pipeline log. The switches have no
 * ports and no flow table, so no Thrift server starts and no packet is sent.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/test.h"

#include <bm/bm_sim/logger.h>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace ns3;

namespace
{

/// Test case that destroys the simulator in DoTeardown(), also after a failed assertion
class P4TestCase : public TestCase
{
  protected:
    using TestCase::TestCase;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }
};

/// An initialized switch without ports and flow table
Ptr<P4SwitchNetDevice>
CreateSwitch(uint32_t arch, const std::string& json, const std::string& logLevel = "off")
{
    Ptr<Node> node = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("P4SwitchArch", UintegerValue(arch));
    sw->SetAttribute("JsonPath", StringValue(json));
    sw->SetAttribute("FlowTablePath", StringValue(""));
    sw->SetAttribute("BmLogLevel", StringValue(logLevel));
    node->AddDevice(sw);
    sw->Initialize();
    return sw;
}

/// A TCP socket listening on a port the kernel picks; returns the socket (or -1)
int
ListenOnFreePort(int* port)
{
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    socklen_t len = sizeof(addr);
    if (sock >= 0 && (::bind(sock, reinterpret_cast<sockaddr*>(&addr), len) != 0 ||
                      ::listen(sock, 1) != 0 ||
                      ::getsockname(sock, reinterpret_cast<sockaddr*>(&addr), &len) != 0))
    {
        ::close(sock);
        sock = -1;
    }
    if (sock >= 0)
    {
        *port = ntohs(addr.sin_port);
    }
    return sock;
}

/// True if BMv2 wrote the pipeline log of Thrift port \p port after \p since; removes it
bool
PipelineLogWritten(int port, std::filesystem::file_time_type since)
{
    namespace fs = std::filesystem;
    bool written = false;
    for (const char* suffix : {"", ".txt"})
    {
        fs::path log = "/tmp/bmv2-" + std::to_string(port) + "-pipeline.log" + suffix;
        std::error_code ec;
        if (fs::exists(log, ec))
        {
            written = written || fs::last_write_time(log, ec) >= since;
            fs::remove(log, ec);
        }
    }
    return written;
}

} // namespace

/**
 * \ingroup p4sim-tests
 * An architecture loads its P4 program. A JSON that fails to load aborts the
 * test runner, which fails the test too.
 */
class P4SwitchLoadTestCase : public P4TestCase
{
  public:
    /**
     * \param name architecture name
     * \param arch P4SwitchArch value (0 v1model, 1 PSA, 2 PNA)
     * \param json P4 JSON, relative to the test directory
     */
    P4SwitchLoadTestCase(const std::string& name, uint32_t arch, const std::string& json)
        : P4TestCase("Load the " + name + " program"),
          m_arch(arch),
          m_json(json)
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        Ptr<P4SwitchNetDevice> sw = CreateSwitch(m_arch, CreateDataDirFilename(m_json));
        NS_TEST_EXPECT_MSG_GT(sw->GetThriftPort(), 0, "The switch has no Thrift port");
    }

    uint32_t m_arch;    //!< P4SwitchArch value
    std::string m_json; //!< P4 JSON, relative to the test directory
};

/**
 * \ingroup p4sim-tests
 * Thrift ports: unique per switch, and a port another program listens on is skipped.
 * (An explicit ThriftPort is not tested here: picking a free port and then requesting
 * it races with other test processes.)
 */
class P4ThriftPortTestCase : public P4TestCase
{
  public:
    P4ThriftPortTestCase()
        : P4TestCase("Thrift ports are unique and skip ports in use")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        std::string json = CreateDataDirFilename("p4src/simple_v1model/simple_v1model.json");

        Ptr<P4SwitchNetDevice> a = CreateSwitch(0, json);
        Ptr<P4SwitchNetDevice> b = CreateSwitch(0, json);
        NS_TEST_EXPECT_MSG_NE(a->GetThriftPort(), b->GetThriftPort(), "Two switches share a port");

        // Start the automatic search at a port another program listens on.
        int busy = 0;
        int sock = ListenOnFreePort(&busy);
        NS_TEST_ASSERT_MSG_GT(sock, -1, "Could not open a listening socket");
        if (sock < 0)
        {
            return;
        }
        ::setenv("P4SIM_THRIFT_PORT_BASE", std::to_string(busy).c_str(), 1);
        Ptr<P4SwitchNetDevice> c = CreateSwitch(0, json);
        ::unsetenv("P4SIM_THRIFT_PORT_BASE");
        ::close(sock);
        NS_TEST_EXPECT_MSG_GT(c->GetThriftPort(), busy, "A port in use was not skipped");
    }
};

/**
 * \ingroup p4sim-tests
 * BmLogLevel: "off" writes no BMv2 pipeline log, "debug" does (loading the JSON
 * logs debug lines). A log file left by an earlier run is not mistaken for a new
 * one: only a file modified during the test counts.
 */
class P4BmLogLevelTestCase : public P4TestCase
{
  public:
    P4BmLogLevelTestCase()
        : P4TestCase("BmLogLevel=off writes no pipeline log")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        std::string json = CreateDataDirFilename("p4src/simple_v1model/simple_v1model.json");
        for (const std::string level : {"off", "debug"})
        {
            // One second of slack: file times use a coarser clock than now().
            auto since = std::filesystem::file_time_type::clock::now() - std::chrono::seconds(1);
            Ptr<P4SwitchNetDevice> sw = CreateSwitch(0, json, level);
            bm::Logger::get()->flush(); // buffered lines reach the file and update its time
            NS_TEST_EXPECT_MSG_EQ(PipelineLogWritten(sw->GetThriftPort(), since),
                                  (level != "off"),
                                  "Wrong pipeline log for BmLogLevel=" << level);
        }
    }
};

/**
 * \ingroup p4sim-tests
 * Switch set-up tests.
 */
class P4simTestSuite : public TestSuite
{
  public:
    P4simTestSuite()
        : TestSuite("p4sim", TestSuite::Type::UNIT)
    {
        AddTestCase(
            new P4SwitchLoadTestCase("v1model", 0, "p4src/simple_v1model/simple_v1model.json"),
            TestCase::Duration::QUICK);
        AddTestCase(new P4SwitchLoadTestCase("PSA", 1, "p4src/simple_psa/simple_psa.json"),
                    TestCase::Duration::QUICK);
        AddTestCase(new P4SwitchLoadTestCase("PNA", 2, "p4src/simple_pna/simple_pna.json"),
                    TestCase::Duration::QUICK);
        AddTestCase(new P4ThriftPortTestCase, TestCase::Duration::QUICK);
        AddTestCase(new P4BmLogLevelTestCase, TestCase::Duration::QUICK);
    }
};

static P4simTestSuite g_p4simTestSuite; //!< Static variable for test initialization
