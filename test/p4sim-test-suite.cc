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

/*
 * Set-up tests of the P4 switch:
 * - every architecture (v1model, PSA, PNA) loads its P4 program,
 * - switches never share a Thrift port, also with ports used by other programs,
 * - the BmLogLevel attribute controls whether BMv2 writes a pipeline log.
 *
 * The switches have no ports and no flow table, so no Thrift server is started
 * and no packet is sent. Packet processing is tested in other suites.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-core-v1model.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/test.h"

#include <cstdio>
#include <cstdlib>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace ns3;

namespace
{

constexpr uint32_t ARCH_V1MODEL = 0; //!< P4SwitchArch value of v1model
constexpr uint32_t ARCH_PSA = 1;     //!< P4SwitchArch value of PSA
constexpr uint32_t ARCH_PNA = 2;     //!< P4SwitchArch value of PNA

/**
 * Create a P4 switch on a new node and initialize it, which loads the P4 JSON.
 * The switch has no ports and no flow table.
 */
Ptr<P4SwitchNetDevice>
CreateInitializedSwitch(uint32_t arch,
                        const std::string& jsonPath,
                        const std::string& logLevel = "off",
                        uint16_t thriftPort = 0)
{
    Ptr<Node> node = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("P4SwitchArch", UintegerValue(arch));
    sw->SetAttribute("JsonPath", StringValue(jsonPath));
    sw->SetAttribute("FlowTablePath", StringValue("")); // no flow table, no Thrift server
    sw->SetAttribute("BmLogLevel", StringValue(logLevel));
    sw->SetAttribute("ThriftPort", UintegerValue(thriftPort));
    node->AddDevice(sw);
    sw->Initialize();
    return sw;
}

/**
 * Open a TCP socket listening on a port chosen by the kernel.
 * \param [out] port the port the socket listens on
 * \return the socket, or -1 on error
 */
int
OpenListeningSocket(int* port)
{
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        return -1;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;
    socklen_t len = sizeof(addr);
    if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(sock, 1) != 0 ||
        ::getsockname(sock, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
    {
        ::close(sock);
        return -1;
    }
    *port = ntohs(addr.sin_port);
    return sock;
}

/// A TCP port that is free right now (the kernel picks it)
int
FindFreePort()
{
    int port = 0;
    int sock = OpenListeningSocket(&port);
    if (sock >= 0)
    {
        ::close(sock);
    }
    return port;
}

/// True if a file exists
bool
FileExists(const std::string& path)
{
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

/// Path of the BMv2 pipeline log of the switch with Thrift port \p port
std::string
PipelineLogPath(int port)
{
    return "/tmp/bmv2-" + std::to_string(port) + "-pipeline.log";
}

/// Remove the BMv2 pipeline log of the switch with Thrift port \p port
void
RemovePipelineLog(int port)
{
    std::remove(PipelineLogPath(port).c_str());
    std::remove((PipelineLogPath(port) + ".txt").c_str());
}

/// True if BMv2 wrote a pipeline log for the switch with Thrift port \p port
bool
PipelineLogExists(int port)
{
    return FileExists(PipelineLogPath(port)) || FileExists(PipelineLogPath(port) + ".txt");
}

/**
 * Set an environment variable for the lifetime of this object, then restore it.
 */
class ScopedEnv
{
  public:
    ScopedEnv(const std::string& name, const std::string& value)
        : m_name(name)
    {
        const char* old = std::getenv(name.c_str());
        m_hadValue = old != nullptr;
        if (m_hadValue)
        {
            m_oldValue = old;
        }
        ::setenv(name.c_str(), value.c_str(), 1);
    }

    ~ScopedEnv()
    {
        if (m_hadValue)
        {
            ::setenv(m_name.c_str(), m_oldValue.c_str(), 1);
        }
        else
        {
            ::unsetenv(m_name.c_str());
        }
    }

  private:
    std::string m_name;
    std::string m_oldValue;
    bool m_hadValue{false};
};

} // namespace

/**
 * \ingroup p4sim-tests
 * Every architecture loads its P4 program: the switch gets a Thrift port and,
 * for v1model, a core. A JSON that fails to load aborts the simulation, which
 * also fails this test.
 */
class P4SwitchLoadTestCase : public TestCase
{
  public:
    /**
     * \param name architecture name, for the test name
     * \param arch P4SwitchArch value
     * \param json P4 JSON, relative to the test directory
     */
    P4SwitchLoadTestCase(const std::string& name, uint32_t arch, const std::string& json)
        : TestCase("Load the " + name + " P4 program"),
          m_arch(arch),
          m_json(json)
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        Ptr<P4SwitchNetDevice> sw = CreateInitializedSwitch(m_arch, CreateDataDirFilename(m_json));
        NS_TEST_ASSERT_MSG_GT(sw->GetThriftPort(), 0, "The switch has no Thrift port");
        if (m_arch == ARCH_V1MODEL)
        {
            NS_TEST_ASSERT_MSG_NE(sw->GetV1ModelCore(), nullptr, "The switch has no v1model core");
        }
        Simulator::Destroy();
    }

    uint32_t m_arch;    //!< P4SwitchArch value
    std::string m_json; //!< P4 JSON, relative to the test directory
};

/**
 * \ingroup p4sim-tests
 * Thrift port allocation: switches never share a port, ports that another
 * program listens on are skipped, and an explicit free port is used as is.
 */
class P4ThriftPortTestCase : public TestCase
{
  public:
    P4ThriftPortTestCase()
        : TestCase("Thrift ports are unique and skip ports in use")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        std::string json = CreateDataDirFilename("p4src/simple_v1model/simple_v1model.json");

        // Automatic allocation: two switches get two different ports.
        Ptr<P4SwitchNetDevice> a = CreateInitializedSwitch(ARCH_V1MODEL, json);
        Ptr<P4SwitchNetDevice> b = CreateInitializedSwitch(ARCH_V1MODEL, json);
        NS_TEST_ASSERT_MSG_NE(a->GetThriftPort(),
                              b->GetThriftPort(),
                              "Two switches got the same Thrift port");

        // A port that another program listens on is skipped.
        int busyPort = 0;
        int listener = OpenListeningSocket(&busyPort);
        NS_TEST_ASSERT_MSG_GT(listener, -1, "Could not open a listening socket");
        {
            ScopedEnv base("P4SIM_THRIFT_PORT_BASE", std::to_string(busyPort));
            Ptr<P4SwitchNetDevice> c = CreateInitializedSwitch(ARCH_V1MODEL, json);
            NS_TEST_EXPECT_MSG_NE(c->GetThriftPort(),
                                  busyPort,
                                  "The switch got a port another program listens on");
            NS_TEST_EXPECT_MSG_GT(c->GetThriftPort(),
                                  busyPort,
                                  "The allocation did not start at P4SIM_THRIFT_PORT_BASE");
        }
        ::close(listener);

        // An explicitly requested free port is used as is.
        int freePort = FindFreePort();
        NS_TEST_ASSERT_MSG_GT(freePort, 0, "Could not find a free port");
        Ptr<P4SwitchNetDevice> d =
            CreateInitializedSwitch(ARCH_V1MODEL, json, "off", static_cast<uint16_t>(freePort));
        NS_TEST_EXPECT_MSG_EQ(d->GetThriftPort(),
                              freePort,
                              "The requested ThriftPort was not used");

        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * BmLogLevel: with "off" BMv2 writes no pipeline log, otherwise it does.
 */
class P4BmLogLevelTestCase : public TestCase
{
  public:
    P4BmLogLevelTestCase()
        : TestCase("BmLogLevel=off writes no BMv2 pipeline log")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        std::string json = CreateDataDirFilename("p4src/simple_v1model/simple_v1model.json");

        int quietPort = FindFreePort();
        RemovePipelineLog(quietPort); // left over from an earlier run, if any
        Ptr<P4SwitchNetDevice> quiet =
            CreateInitializedSwitch(ARCH_V1MODEL, json, "off", static_cast<uint16_t>(quietPort));
        NS_TEST_EXPECT_MSG_EQ(PipelineLogExists(quiet->GetThriftPort()),
                              false,
                              "BmLogLevel=off still wrote a pipeline log");

        int verbosePort = FindFreePort();
        RemovePipelineLog(verbosePort);
        Ptr<P4SwitchNetDevice> verbose =
            CreateInitializedSwitch(ARCH_V1MODEL, json, "info", static_cast<uint16_t>(verbosePort));
        NS_TEST_EXPECT_MSG_EQ(PipelineLogExists(verbose->GetThriftPort()),
                              true,
                              "BmLogLevel=info wrote no pipeline log");
        RemovePipelineLog(verbose->GetThriftPort());

        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * Set-up tests of the P4 switch.
 */
class P4simTestSuite : public TestSuite
{
  public:
    P4simTestSuite()
        : TestSuite("p4sim", UNIT)
    {
        AddTestCase(new P4SwitchLoadTestCase("v1model",
                                             ARCH_V1MODEL,
                                             "p4src/simple_v1model/simple_v1model.json"),
                    TestCase::QUICK);
        AddTestCase(new P4SwitchLoadTestCase("PSA", ARCH_PSA, "p4src/simple_psa/simple_psa.json"),
                    TestCase::QUICK);
        AddTestCase(new P4SwitchLoadTestCase("PNA", ARCH_PNA, "p4src/simple_pna/simple_pna.json"),
                    TestCase::QUICK);
        AddTestCase(new P4ThriftPortTestCase, TestCase::QUICK);
        AddTestCase(new P4BmLogLevelTestCase, TestCase::QUICK);
    }
};

static P4simTestSuite g_p4simTestSuite; //!< Static variable for test initialization
