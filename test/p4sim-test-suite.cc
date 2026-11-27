// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * Switch set-up: every architecture loads its P4 program and uses no BMv2 port
 * manager, Thrift ports never collide, BmLogLevel controls the BMv2 pipeline log
 * (off by default), the deprecated attributes are still accepted, and errors in
 * a flow table are reported. The switches have no ports, so no packet is sent, and
 * only those of the last test case have a flow table and so a Thrift server.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-switch-core.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4sim-ns3-compat.h"
#include "ns3/test.h"

#include <bm/bm_sim/dev_mgr.h>
#include <bm/bm_sim/logger.h>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <map>
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

/// An initialized switch without ports
Ptr<P4SwitchNetDevice>
CreateSwitch(uint32_t arch,
             const std::string& json,
             const std::string& logLevel = "off",
             const std::string& flowTable = "")
{
    Ptr<Node> node = CreateObject<Node>();
    Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
    sw->SetAttribute("P4SwitchArch", UintegerValue(arch));
    sw->SetAttribute("JsonPath", StringValue(json));
    sw->SetAttribute("FlowTablePath", StringValue(flowTable));
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

/// Size and modification time of each BMv2 pipeline log in /tmp, by path
using LogFiles = std::map<std::string, std::pair<std::uintmax_t, std::filesystem::file_time_type>>;

/// The BMv2 pipeline logs in /tmp
LogFiles
PipelineLogs()
{
    namespace fs = std::filesystem;
    LogFiles logs;
    std::error_code ec;
    for (const fs::directory_entry& entry : fs::directory_iterator("/tmp", ec))
    {
        std::string name = entry.path().filename().string();
        if (name.rfind("bmv2-", 0) == 0 && name.find("-pipeline.log") != std::string::npos)
        {
            logs[entry.path().string()] = {entry.file_size(ec), entry.last_write_time(ec)};
        }
    }
    return logs;
}

/// True if BMv2 created or changed the pipeline log of Thrift port \p port since the
/// logs \p before were listed; removes the log
bool
PipelineLogWritten(int port, const LogFiles& before)
{
    namespace fs = std::filesystem;
    bool written = false;
    for (const char* suffix : {"", ".txt"})
    {
        fs::path log = "/tmp/bmv2-" + std::to_string(port) + "-pipeline.log" + suffix;
        std::error_code ec;
        if (fs::exists(log, ec))
        {
            auto old = before.find(log.string());
            auto now = std::make_pair(fs::file_size(log, ec), fs::last_write_time(log, ec));
            written = written || old == before.end() || old->second != now;
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
 * P4sim moves the packets between BMv2 and ns-3 itself, so a switch of any
 * architecture has a BMv2 device manager without ports: it lists no port, and
 * adding one is unsupported. BMv2's default device manager (BMI) would try to
 * open the interface and fail with an error instead; its destructor crashes
 * with glibc 2.43 when, as in P4sim, it was never started.
 */
class P4NoBmv2PortsTestCase : public P4TestCase
{
  public:
    P4NoBmv2PortsTestCase()
        : P4TestCase("A switch has no BMv2 ports and no BMI device manager")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        const std::map<uint32_t, std::string> jsons = {
            {0, "p4src/simple_v1model/simple_v1model.json"},
            {1, "p4src/simple_psa/simple_psa.json"},
            {2, "p4src/simple_pna/simple_pna.json"}};
        for (const auto& [arch, json] : jsons)
        {
            Ptr<P4SwitchNetDevice> sw = CreateSwitch(arch, CreateDataDirFilename(json));
            P4SwitchCore* core = sw->GetCore();
            NS_TEST_ASSERT_MSG_NE(core, nullptr, "No core for P4SwitchArch " << arch);
            NS_TEST_EXPECT_MSG_EQ(core->get_port_info().size(),
                                  0,
                                  "P4SwitchArch " << arch << " lists BMv2 ports");
            auto rc = core->port_add("p4sim-no-such-port", 7, {});
            NS_TEST_EXPECT_MSG_EQ(
                static_cast<int>(rc),
                static_cast<int>(bm::PacketDispatcherIface::ReturnCode::UNSUPPORTED),
                "P4SwitchArch " << arch << " uses a BMv2 device manager with ports");
        }
    }
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
 * A switch whose BmLogLevel is not set turns the BMv2 log off, so it writes no
 * pipeline log. The BMv2 logger is shared by all switches; the test first sets it
 * to debug, as a switch with BmLogLevel=debug would.
 */
class P4BmLogLevelDefaultTestCase : public P4TestCase
{
  public:
    P4BmLogLevelDefaultTestCase()
        : P4TestCase("BmLogLevel is off by default")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        bm::Logger::set_log_level(bm::Logger::LogLevel::DEBUG);
        Ptr<Node> node = CreateObject<Node>();
        Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
        sw->SetAttribute(
            "JsonPath",
            StringValue(CreateDataDirFilename("p4src/simple_v1model/simple_v1model.json")));
        sw->SetAttribute("FlowTablePath", StringValue(""));
        node->AddDevice(sw);
        sw->Initialize();
        NS_TEST_EXPECT_MSG_EQ(bm::Logger::get()->level(),
                              spdlog::level::off,
                              "The default BmLogLevel does not turn the BMv2 log off");
    }
};

/**
 * \ingroup p4sim-tests
 * Comments and empty lines of a flow table are skipped. A command that the runtime
 * CLI reports as an error is printed with its file and line, and the rest of the
 * file still runs, unless the CLI stops, as at the line EOF. A CLI that cannot run
 * is reported, too. The byte order mark that some editors write at the start of a
 * file is no error. The CLI gets no descriptor of the simulation, which would keep
 * it waiting for a Thrift server that has gone. (A flow table that cannot be opened
 * ends the process.)
 */
class P4FlowTableErrorsTestCase : public P4TestCase
{
  public:
    P4FlowTableErrorsTestCase()
        : P4TestCase("Errors in a flow table name its file and line")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        std::string dir = CreateDataDirFilename("p4src/simple_v1model/");
        std::ostringstream errors;
        std::streambuf* cerrBuffer = std::cerr.rdbuf(errors.rdbuf());
        // The test macros evaluate their arguments twice on a failure, so each
        // flow table runs before, once
        Ptr<P4SwitchNetDevice> sw = CreateSwitch(0, dir + "simple_v1model.json");
        int status = sw->GetCore()->ExecuteCliCommands(dir + "flowtable_errors.txt");
        std::string path = std::getenv("PATH") ? std::getenv("PATH") : "";
        std::ostringstream noCli;
        std::cerr.rdbuf(noCli.rdbuf());
        setenv("PATH", "/nonexistent", 1);
        CreateSwitch(0, dir + "simple_v1model.json", "off", dir + "flowtable_0.txt");
        setenv("PATH", path.c_str(), 1);
        std::ostringstream bomErrors;
        std::cerr.rdbuf(bomErrors.rdbuf());
        std::string bomTable = CreateTempDirFilename("flowtable_bom.txt");
        std::ofstream(bomTable)
            << "\xEF\xBB\xBF"
            << "table_add ipv4_nhop ipv4_forward 0x0a010101 => 00:00:00:00:00:01 0\n";
        Ptr<P4SwitchNetDevice> bom = CreateSwitch(0, dir + "simple_v1model.json");
        int bomStatus = bom->GetCore()->ExecuteCliCommands(bomTable);
        // The CLI's command shell lists the descriptors of the CLI, its parent
        std::ostringstream inheritErrors;
        std::cerr.rdbuf(inheritErrors.rdbuf());
        std::string marker = CreateTempDirFilename("p4sim-descriptor-marker");
        int markerFd = open(marker.c_str(), O_CREAT | O_RDONLY, 0600);
        std::string inheritTable = CreateTempDirFilename("flowtable_inherit.txt");
        std::ofstream(inheritTable) << "shell ls -l /proc/$PPID/fd | grep -q descriptor-marker"
                                    << " && echo 'Error: the CLI holds a descriptor'\n";
        Ptr<P4SwitchNetDevice> inherit = CreateSwitch(0, dir + "simple_v1model.json");
        int inheritStatus = inherit->GetCore()->ExecuteCliCommands(inheritTable);
        close(markerFd);
        std::cerr.rdbuf(cerrBuffer);

        NS_TEST_EXPECT_MSG_EQ(status, 1, "The status must tell that commands failed");
        NS_TEST_EXPECT_MSG_EQ(inheritStatus,
                              0,
                              "The CLI holds a descriptor: " << inheritErrors.str());
        NS_TEST_EXPECT_MSG_EQ(bomStatus, 0, "No command of the second table fails");

        NS_TEST_EXPECT_MSG_EQ(bomErrors.str(), "", "The byte order mark is no error");
        std::size_t bomEntries = 0;
        bom->GetCore()->mt_get_num_entries(0, "MyIngress.ipv4_nhop", &bomEntries);
        NS_TEST_EXPECT_MSG_EQ(bomEntries, 1, "The line with the byte order mark must run");

        NS_TEST_EXPECT_MSG_NE(noCli.str().find("flowtable_0.txt\n    simple_switch_CLI failed"),
                              std::string::npos,
                              "A missing CLI is not reported: " << noCli.str());

        std::size_t entries = 0;
        sw->GetCore()->mt_get_num_entries(0, "MyIngress.ipv4_nhop", &entries);
        NS_TEST_EXPECT_MSG_EQ(entries, 2, "The commands without errors must run");
        std::size_t lines = 0;
        for (char c : errors.str())
        {
            lines += (c == '\n');
        }
        NS_TEST_EXPECT_MSG_EQ(lines, 10, "Expected 5 errors with 2 lines each: " << errors.str());
        for (const std::string error :
             {":5: table_add no_such_table ipv4_forward 0x0a010103 => 00:00:00:00:00:03 2\n"
              "    Error: Invalid table name (no_such_table)",
              ":6: table_add ipv4_nhop ipv4_forward 0x0a010102 => 00:00:00:00:00:02\n"
              "    Error: Action MyIngress.ipv4_forward needs 2 parameters",
              ":7: no_such_command 1 2\n"
              "    *** Unknown syntax: no_such_command 1 2",
              ":8: table_add ipv4_nhop ipv4_forward 0x0a010101 => 00:00:00:00:00:01 0\n"
              "    Invalid table operation (DUPLICATE_ENTRY)",
              ":10: EOF\n"
              "    simple_switch_CLI stopped here, the rest of the file is skipped\n"})
        {
            NS_TEST_EXPECT_MSG_NE(errors.str().find("flowtable_errors.txt" + error),
                                  std::string::npos,
                                  "Not reported: " << error << "\nin: " << errors.str());
        }
    }
};

/**
 * \ingroup p4sim-tests
 * ExecuteCliCommands() runs again on a switch that ran its flow table at the
 * start, also during the simulation: the Thrift server of the switch starts
 * once. (A second server could not bind its port, and BMv2 ended the process.)
 */
class P4FlowTableAgainTestCase : public P4TestCase
{
  public:
    P4FlowTableAgainTestCase()
        : P4TestCase("Commands run again on a switch, also during the simulation")
    {
    }

  private:
    void DoRun() override
    {
        SetDataDir(NS_TEST_SOURCEDIR);
        std::string dir = CreateDataDirFilename("p4src/simple_v1model/");
        // flowtable_0.txt adds two entries to ipv4_nhop
        Ptr<P4SwitchNetDevice> sw =
            CreateSwitch(0, dir + "simple_v1model.json", "off", dir + "flowtable_0.txt");
        std::string table3 = CreateTempDirFilename("flowtable_again_3.txt");
        std::ofstream(table3) << "table_add ipv4_nhop ipv4_forward 0x0a010103 => "
                                 "00:00:00:00:00:05 0x2\n";
        std::string table4 = CreateTempDirFilename("flowtable_again_4.txt");
        std::ofstream(table4) << "table_add ipv4_nhop ipv4_forward 0x0a010104 => "
                                 "00:00:00:00:00:07 0x2\n";
        int status3 = -1;
        int status4 = -1;
        Simulator::Schedule(MilliSeconds(1),
                            [&]() { status3 = sw->GetCore()->ExecuteCliCommands(table3); });
        Simulator::Schedule(MilliSeconds(2),
                            [&]() { status4 = sw->GetCore()->ExecuteCliCommands(table4); });
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();

        NS_TEST_EXPECT_MSG_EQ(status3, 0, "The second flow table must run");
        NS_TEST_EXPECT_MSG_EQ(status4, 0, "The third flow table must run");
        std::size_t entries = 0;
        sw->GetCore()->mt_get_num_entries(0, "MyIngress.ipv4_nhop", &entries);
        NS_TEST_EXPECT_MSG_EQ(entries, 4, "Each flow table must add its entries");
    }
};

/**
 * \ingroup p4sim-tests
 * ChannelType and EnableTracing have no effect and are deprecated: a script that
 * still sets them runs, and ns-3 warns about them.
 */
class P4DeprecatedAttributesTestCase : public P4TestCase
{
  public:
    P4DeprecatedAttributesTestCase()
        : P4TestCase("ChannelType and EnableTracing are deprecated but accepted")
    {
    }

  private:
    void DoRun() override
    {
        Ptr<P4SwitchNetDevice> sw = CreateObject<P4SwitchNetDevice>();
        sw->SetAttribute("ChannelType", UintegerValue(P4CHANNELP2P));
        sw->SetAttribute("EnableTracing", BooleanValue(true));
        TypeId tid = P4SwitchNetDevice::GetTypeId();
        for (const std::string name : {"ChannelType", "EnableTracing"})
        {
            bool deprecated = false;
            for (std::size_t i = 0; i < tid.GetAttributeN(); i++)
            {
                TypeId::AttributeInformation info = tid.GetAttribute(i);
                deprecated = deprecated || (info.name == name &&
                                            info.supportLevel == TypeId::SupportLevel::DEPRECATED);
            }
            NS_TEST_EXPECT_MSG_EQ(deprecated, true, name << " is not deprecated");
        }
    }
};

/**
 * \ingroup p4sim-tests
 * BmLogLevel: "off" writes no BMv2 pipeline log, "debug" does (loading the JSON
 * logs debug lines). A log file left by an earlier run, even a second ago, is not
 * mistaken for a new one: the logs are listed before the switch is created (its
 * Thrift port, and so its log's name, is known only then), and only a log that is
 * new or whose size or time changed counts.
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
            LogFiles before = PipelineLogs();
            Ptr<P4SwitchNetDevice> sw = CreateSwitch(0, json, level);
            bm::Logger::get()->flush(); // buffered lines reach the file and update its time
            NS_TEST_EXPECT_MSG_EQ(PipelineLogWritten(sw->GetThriftPort(), before),
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
            P4SIM_TEST_QUICK);
        AddTestCase(new P4SwitchLoadTestCase("PSA", 1, "p4src/simple_psa/simple_psa.json"),
                    P4SIM_TEST_QUICK);
        AddTestCase(new P4SwitchLoadTestCase("PNA", 2, "p4src/simple_pna/simple_pna.json"),
                    P4SIM_TEST_QUICK);
        AddTestCase(new P4NoBmv2PortsTestCase, P4SIM_TEST_QUICK);
        AddTestCase(new P4ThriftPortTestCase, P4SIM_TEST_QUICK);
        AddTestCase(new P4BmLogLevelTestCase, P4SIM_TEST_QUICK);
        AddTestCase(new P4BmLogLevelDefaultTestCase, P4SIM_TEST_QUICK);
        AddTestCase(new P4DeprecatedAttributesTestCase, P4SIM_TEST_QUICK);
        AddTestCase(new P4FlowTableErrorsTestCase, P4SIM_TEST_QUICK);
        AddTestCase(new P4FlowTableAgainTestCase, P4SIM_TEST_QUICK);
    }
};

static P4simTestSuite g_p4simTestSuite; //!< Static variable for test initialization
