#include "ns3/test.h"
#include "ns3/log.h"
#include "ns3/p4-topology-reader-helper.h"

using namespace ns3;

 NS_LOG_COMPONENT_DEFINE ("P4TopoReaderTest");

// Define a TestCase for the P4 topology reader
class P4TopologyReaderTestCase : public TestCase
{
public:
  P4TopologyReaderTestCase () : TestCase ("Read the dumbbell topology")
  {
  }

private:
  virtual void
  DoRun ()
  {
    SetDataDir (NS_TEST_SOURCEDIR);
    std::string fileName = CreateDataDirFilename ("p4src/topology-files/dumbbell-topo.txt");
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

};

// Define a TestSuite for P4 topology reader
class P4TopologyReaderTestSuite : public TestSuite
{
public:
  P4TopologyReaderTestSuite () : TestSuite ("p4-topology-reader", TestSuite::Type::UNIT)
  {
    AddTestCase (new P4TopologyReaderTestCase, TestCase::Duration::QUICK);
  }
};

// Allocate an instance of the test suite
static P4TopologyReaderTestSuite p4TopologyReaderTestSuite;
