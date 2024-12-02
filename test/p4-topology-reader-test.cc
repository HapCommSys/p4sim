#include "ns3/core-module.h"
#include "p4-topology-reader-helper.h"

using namespace ns3;

int main(int argc, char *argv[])
{
  CommandLine cmd;
  std::string fileName = "topology.txt";
  std::string fileType = "P2P";

  cmd.AddValue("fileName", "Input topology file", fileName);
  cmd.AddValue("fileType", "Topology file type (P2P, CsmaTopo)", fileType);
  cmd.Parse(argc, argv);

  P4TopologyReaderHelper topoHelper;
  topoHelper.SetFileName(fileName);
  topoHelper.SetFileType(fileType);

  Ptr<P4TopologyReader> reader = topoHelper.GetTopologyReader();
  if (!reader)
    {
      NS_LOG_ERROR("Failed to load the topology.");
      return 1;
    }

  NS_LOG_INFO("Topology successfully loaded.");
  return 0;
}
