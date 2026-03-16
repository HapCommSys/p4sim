#include "ns3/test.h"
#include "ns3/log.h"
#include "ns3/p4-topology-reader-helper.h"
#include "ns3/format-utils.h"

using namespace ns3;

 NS_LOG_COMPONENT_DEFINE ("P4TopoReaderTest");

// Define a TestCase for the P4 topology reader
class P4TopologyReaderTestCase : public TestCase
{
public:
  P4TopologyReaderTestCase () : TestCase ("Test P4TopologyReader functionality")
  {
  }

private:
  virtual void
  DoRun ()
  {
    // \@TODO [Now only can use a default file for test]
    std::string fileName = GetFileNameFromArgsOrDefault ();
    std::string fileType = "P2P";

    // Set up topology reader
    P4TopologyReaderHelper topoHelper;
    topoHelper.SetFileName (fileName);
    topoHelper.SetFileType (fileType);

    Ptr<P4TopologyReader> reader = topoHelper.GetTopologyReader ();

    NS_TEST_ASSERT_MSG_EQ (reader->GetFileName (), fileName,
                           "Topology Reader set file name incorrectly.");

    // Validate if reader was created successfully
    NS_TEST_ASSERT_MSG_NE (reader, nullptr, "Failed to load the topology.");

    // Validate hosts and switches node counts
    NodeContainer hosts = reader->GetHosts ();
    NodeContainer switches = reader->GetSwitches ();
    size_t hostCount = hosts.GetN ();
    size_t switchCount = switches.GetN ();
    NS_TEST_ASSERT_MSG_EQ (hostCount, 6, "There should be 6 hosts in the topology.");
    NS_TEST_ASSERT_MSG_EQ (switchCount, 2, "There should be 2 switches in the topology.");

    // Validate if the link was created successfully
    NS_TEST_ASSERT_MSG_EQ (reader->LinksSize (), 7, "Topology contains incorrect number of links.");
  }

  // Helper function to get filename from arguments or use a default
  std::string
  GetFileNameFromArgsOrDefault ()
  {
     std::string p4SrcDir = GetP4SimDir();
     std::cout<<p4SrcDir<<std::endl;
    std::string defaultFileName =
       p4SrcDir  +
      "/test/p4src/topology-files/dumbbell-topo.txt";

    const char *envFileName = std::getenv ("TOPOLOGY_FILE");

    if (envFileName != nullptr)
      {
        return std::string (envFileName);
      }

    return defaultFileName;
  }
};

// Define a TestSuite for P4 topology reader
class P4TopologyReaderTestSuite : public TestSuite
{
public:
  P4TopologyReaderTestSuite () : TestSuite ("p4-topology-reader", UNIT)
  {
    AddTestCase (new P4TopologyReaderTestCase, TestCase::QUICK);
  }
};

// Allocate an instance of the test suite
static P4TopologyReaderTestSuite p4TopologyReaderTestSuite;
