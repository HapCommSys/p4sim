#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
// #include "ns3/csma-helper.h"
#include "ns3/p4-p2p-helper.h"
#include "ns3/internet-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/p4-helper.h"
#include "ns3/format-utils.h"
#include "ns3/p4-topology-reader-helper.h"
#include <iomanip>
#include <filesystem>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("P4Ipv4ForwardingTest1");

unsigned long start = getTickCount ();

// Convert IP address to hexadecimal format
std::string
ConvertIpToHex (Ipv4Address ipAddr)
{
  std::ostringstream hexStream;
  uint32_t ip = ipAddr.Get (); // Get the IP address as a 32-bit integer
  hexStream << "0x" << std::hex << std::setfill ('0') << std::setw (2)
            << ((ip >> 24) & 0xFF) // First byte
            << std::setw (2) << ((ip >> 16) & 0xFF) // Second byte
            << std::setw (2) << ((ip >> 8) & 0xFF) // Third byte
            << std::setw (2) << (ip & 0xFF); // Fourth byte
  return hexStream.str ();
}

void
CalculateThroughput (Ptr<PacketSink> sink, double simulationTime)
{
  uint64_t totalRx = sink->GetTotalRx ();
  double throughput = (totalRx * 8.0) / (simulationTime * 1e6);
  std::cout << "Total Throughput: " << throughput << " Mbps" << std::endl;
}

// Convert MAC address to hexadecimal format
std::string
ConvertMacToHex (Address macAddr)
{
  std::ostringstream hexStream;
  Mac48Address mac = Mac48Address::ConvertFrom (macAddr); // Convert Address to Mac48Address
  uint8_t buffer[6];
  mac.CopyTo (buffer); // Copy MAC address bytes into buffer

  hexStream << "0x";
  for (int i = 0; i < 6; ++i)
    {
      hexStream << std::hex << std::setfill ('0') << std::setw (2) << static_cast<int> (buffer[i]);
    }
  return hexStream.str ();
}

// ============================ data struct ============================
struct SwitchNodeC_t
{
  NetDeviceContainer switchDevices;
  std::vector<std::string> switchPortInfos;
};

struct HostNodeC_t
{
  NetDeviceContainer hostDevice;
  Ipv4InterfaceContainer hostIpv4;
  unsigned int linkSwitchIndex;
  unsigned int linkSwitchPort;
  std::string hostIpv4Str;
};

int
main (int argc, char *argv[])
{
  LogComponentEnable ("P4Ipv4ForwardingTest1", LOG_LEVEL_INFO);

  // ============================ parameters ============================

  // ns3::PacketMetadata::Enable ();

  // ============================ parameters ============================

  // Simulation parameters

  int running_number = 0;
  uint16_t pktSize = 1000; //in Bytes. 1458 to prevent fragments, default 512

  // h1 -> h2 with 2.0Mbps
  std::string appDataRate = "1Mbps"; // Default application data rate

  // Here we need calculated the congestion, how many packets we want to pass the queue
  uint64_t congestion_bottleneck = 10000; // Mbps

  bool enableTracePcap = false;
  double global_start_time = 1.0;
  double sink_start_time = global_start_time + 1.0;
  double client_start_time = sink_start_time + 1.0;
  double client_stop_time = client_start_time + 5; // sending time 30s
  double sink_stop_time = client_stop_time + 10;
  double global_stop_time = sink_stop_time + 10;

  // P4 simulation paths
  // P4GlobalVar::HomePath = "/home/p4/workdir/";
  // P4GlobalVar::g_ns3RootName = "";
  // P4GlobalVar::g_ns3SrcName = "ns3.35/";
  P4GlobalVar::PathConfig::NfDir = P4GlobalVar::PathConfig::HomePath +
                                   P4GlobalVar::PathConfig::Ns3RootName +
                                   P4GlobalVar::PathConfig::Ns3SrcName + "contrib/p4sim/test/";
  P4GlobalVar::InitNfStrUintMap ();

  P4GlobalVar::g_channelType = P4ChannelType::P2P;

  // ============================  command line ============================
  CommandLine cmd;
  cmd.AddValue ("runnum", "running number in loops", running_number);
  cmd.AddValue ("model", "Select P4Simulator[0] or NS3[1]", P4GlobalVar::g_nsType);
  cmd.AddValue ("pktSize", "Packet size in bytes (default 1000)", pktSize);
  cmd.AddValue ("appDataRate", "Application data rate in bps (default 1Mbps)", appDataRate);
  cmd.AddValue ("congestion_bottleneck", "Congestion bottleneck in Mbps (default 5)",
                congestion_bottleneck);
  cmd.AddValue ("pcap", "Trace packet pacp [true] or not[false]", enableTracePcap);
  cmd.Parse (argc, argv);

  // ===== Here the packets size is 1000 bytes (This is sending rate in Application layer, when add
  // header underlayer will be 1000 + 46 bytes (Check the PCAP file) =====`

  P4GlobalVar::g_switchBottleNeck =
      (uint64_t) (congestion_bottleneck * 1000 * 1000 / ((pktSize + 46) * 8));
  NS_LOG_INFO ("*** Congestion bottleneck: "
               << congestion_bottleneck << " Mbps, packet size: " << pktSize
               << " pps, switch bottleneck: " << P4GlobalVar::g_switchBottleNeck << " ns");

  // ============================ topo -> network ============================

  // loading from topo file --> gene topo(linking the nodes)
  std::string topoInput = P4GlobalVar::PathConfig::NfDir + "test_simple/topo.txt";
  std::string topoFormat ("P2PTopo");

  P4TopologyReaderHelper p4TopoHelp;
  p4TopoHelp.SetFileName (topoInput);
  p4TopoHelp.SetFileType (topoFormat);
  NS_LOG_INFO ("*** Reading topology from file: " << topoInput << " with format: " << topoFormat);

  Ptr<P4TopologyReader> topoReader = p4TopoHelp.GetTopologyReader ();

  if (topoReader->LinksSize () == 0)
    {
      NS_LOG_ERROR ("Problems reading the topology file. Failing.");
      return -1;
    }

  // get switch and host node
  NodeContainer terminals = topoReader->GetHostNodeContainer ();
  NodeContainer switchNode = topoReader->GetSwitchNodeContainer ();
  const unsigned int hostNum = terminals.GetN ();
  const unsigned int switchNum = switchNode.GetN ();
  NS_LOG_INFO ("*** Host number: " << hostNum << ", Switch number: " << switchNum);

  // set default network link parameter
  //   CsmaHelper csma;
  //   csma.SetChannelAttribute ("DataRate", StringValue ("10Mbps")); //@todo
  //   csma.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (0.01)));
  P4PointToPointHelper p4p2phelper;
  p4p2phelper.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (10)));

  //  ============================  init network link info ============================
  P4TopologyReader::ConstLinksIterator_t iter;
  SwitchNodeC_t switchNodes[switchNum];
  HostNodeC_t hostNodes[hostNum];
  unsigned int fromIndex, toIndex;
  std::string dataRate, delay;
  for (iter = topoReader->LinksBegin (); iter != topoReader->LinksEnd (); iter++)
    {
      //   if (iter->GetAttributeFailSafe ("DataRate", dataRate))
      //     csma.SetChannelAttribute ("DataRate", StringValue (dataRate));
      //   if (iter->GetAttributeFailSafe ("Delay", delay))
      //     csma.SetChannelAttribute ("Delay", StringValue (delay));

      NetDeviceContainer link =
          p4p2phelper.Install (NodeContainer (iter->GetFromNode (), iter->GetToNode ()));
      fromIndex = iter->GetFromIndex ();
      toIndex = iter->GetToIndex ();
      if (iter->GetFromType () == 's' && iter->GetToType () == 's')
        {
          NS_LOG_INFO ("*** Link from  switch " << fromIndex << " to  switch " << toIndex
                                                << " with data rate " << dataRate << " and delay "
                                                << delay);

          unsigned int fromSwitchPortNumber = switchNodes[fromIndex].switchDevices.GetN ();
          unsigned int toSwitchPortNumber = switchNodes[toIndex].switchDevices.GetN ();
          switchNodes[fromIndex].switchDevices.Add (link.Get (0));
          switchNodes[fromIndex].switchPortInfos.push_back ("s" + UintToString (toIndex) + "_" +
                                                            UintToString (toSwitchPortNumber));

          switchNodes[toIndex].switchDevices.Add (link.Get (1));
          switchNodes[toIndex].switchPortInfos.push_back ("s" + UintToString (fromIndex) + "_" +
                                                          UintToString (fromSwitchPortNumber));
        }
      else
        {
          if (iter->GetFromType () == 's' && iter->GetToType () == 'h')
            {
              NS_LOG_INFO ("*** Link from switch " << fromIndex << " to  host" << toIndex
                                                   << " with data rate " << dataRate
                                                   << " and delay " << delay);

              unsigned int fromSwitchPortNumber = switchNodes[fromIndex].switchDevices.GetN ();
              switchNodes[fromIndex].switchDevices.Add (link.Get (0));
              switchNodes[fromIndex].switchPortInfos.push_back ("h" +
                                                                UintToString (toIndex - switchNum));

              hostNodes[toIndex - switchNum].hostDevice.Add (link.Get (1));
              hostNodes[toIndex - switchNum].linkSwitchIndex = fromIndex;
              hostNodes[toIndex - switchNum].linkSwitchPort = fromSwitchPortNumber;
            }
          else
            {
              if (iter->GetFromType () == 'h' && iter->GetToType () == 's')
                {
                  NS_LOG_INFO ("*** Link from host " << fromIndex << " to  switch" << toIndex
                                                     << " with data rate " << dataRate
                                                     << " and delay " << delay);
                  unsigned int toSwitchPortNumber = switchNodes[toIndex].switchDevices.GetN ();
                  switchNodes[toIndex].switchDevices.Add (link.Get (1));
                  switchNodes[toIndex].switchPortInfos.push_back (
                      "h" + UintToString (fromIndex - switchNum));

                  hostNodes[fromIndex - switchNum].hostDevice.Add (link.Get (0));
                  hostNodes[fromIndex - switchNum].linkSwitchIndex = toIndex;
                  hostNodes[fromIndex - switchNum].linkSwitchPort = toSwitchPortNumber;
                }
              else
                {
                  NS_LOG_ERROR ("link error!");
                  abort ();
                }
            }
        }
    }

  // ============================ print topo info ============================
  // view host link info
  for (unsigned int i = 0; i < hostNum; i++)
    std::cout << "host " << i << ": connect with switch " << hostNodes[i].linkSwitchIndex
              << " port " << hostNodes[i].linkSwitchPort << std::endl;

  // view switch port info
  for (unsigned int i = 0; i < switchNum; i++)
    {
      std::cout << "switch " << i << " connect with: ";
      for (size_t k = 0; k < switchNodes[i].switchPortInfos.size (); k++)
        std::cout << switchNodes[i].switchPortInfos[k] << " ";
      std::cout << std::endl;
    }

  // ============================ add internet stack to the hosts ============================

  InternetStackHelper internet;
  internet.Install (terminals);
  internet.Install (switchNode);

  //  ===============================  Assign IP addresses ===============================
  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  for (unsigned int i = 0; i < hostNum; i++)
    {
      hostNodes[i].hostIpv4 = ipv4.Assign (hostNodes[i].hostDevice);
      hostNodes[i].hostIpv4Str = Uint32IpToHex (hostNodes[i].hostIpv4.GetAddress (0).Get ());
    }

  // build needed parameter to build flow table entries
  std::vector<unsigned int> linkSwitchIndex (hostNum);
  std::vector<unsigned int> linkSwitchPort (hostNum);
  std::vector<std::string> hostIpv4 (hostNum);
  std::vector<std::vector<std::string>> switchPortInfo (switchNum);
  for (unsigned int i = 0; i < hostNum; i++)
    {
      linkSwitchIndex[i] = hostNodes[i].linkSwitchIndex;
      linkSwitchPort[i] = hostNodes[i].linkSwitchPort;
      hostIpv4[i] = hostNodes[i].hostIpv4Str;
    }
  for (unsigned int i = 0; i < switchNum; i++)
    {
      switchPortInfo[i] = switchNodes[i].switchPortInfos;
    }

  //===============================  Print IP and MAC addresses===============================
  NS_LOG_INFO ("Node IP and MAC addresses:");
  for (uint32_t i = 0; i < terminals.GetN (); ++i)
    {
      Ptr<Node> node = terminals.Get (i);
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
      Ptr<NetDevice> netDevice = node->GetDevice (0);

      // Get the IP address
      Ipv4Address ipAddr =
          ipv4->GetAddress (1, 0)
              .GetLocal (); // Interface index 1 corresponds to the first assigned IP

      // Get the MAC address
      Ptr<NetDevice> device = node->GetDevice (0); // Assuming the first device is the desired one
      Mac48Address mac = Mac48Address::ConvertFrom (device->GetAddress ());

      NS_LOG_INFO ("Node " << i << ": IP = " << ipAddr << ", MAC = " << mac);

      // Convert to hexadecimal
      std::string ipHex = ConvertIpToHex (ipAddr);
      std::string macHex = ConvertMacToHex (mac);
      NS_LOG_INFO ("Node " << i << ": IP = " << ipHex << ", MAC = " << macHex);
    }

  // Bridge or P4 switch configuration
  if (P4GlobalVar::g_nsType == P4Simulator)
    {
      NS_LOG_INFO ("*** P4Simulator mode");
      P4GlobalVar::g_populateFlowTableWay = NS3PIFOTM; //LOCAL_CALL RUNTIME_CLI NS3PIFOTM
      P4GlobalVar::g_networkFunc = P4ModuleType::BASIC;
      P4GlobalVar::SetP4MatchTypeJsonPath ();

      P4Helper p4Bridge;
      for (unsigned int i = 0; i < switchNum; i++)
        {
          P4GlobalVar::g_flowTablePath = P4GlobalVar::PathConfig::NfDir + "test_simple/flowtable_" +
                                         std::to_string (i) + ".txt";
          P4GlobalVar::g_viewFlowTablePath = P4GlobalVar::g_flowTablePath;
          NS_LOG_INFO ("*** Installing P4 bridge [ "
                       << i << " ]device with configuration: " << std::endl
                       << "P4JsonPath = " << P4GlobalVar::g_p4JsonPath << ", " << std::endl
                       << "FlowTablePath = " << P4GlobalVar::g_flowTablePath << ", " << std::endl
                       << "ViewFlowTablePath = " << P4GlobalVar::g_viewFlowTablePath);

          p4Bridge.Install (switchNode.Get (i), switchNodes[i].switchDevices);
        }
    }
  else
    {
      BridgeHelper bridge;
      for (unsigned int i = 0; i < switchNum; i++)
        {
          bridge.Install (switchNode.Get (i), switchNodes[i].switchDevices);
        }
    }

  // == First == send link h0 -----> h1
  unsigned int serverI = 1;
  unsigned int clientI = 0;
  uint16_t servPort = 9093; // setting for port

  Ptr<Node> node = terminals.Get (serverI);
  Ptr<Ipv4> ipv4_adder = node->GetObject<Ipv4> ();
  Ipv4Address serverAddr1 =
      ipv4_adder->GetAddress (1, 0)
          .GetLocal (); // Interface index 1 corresponds to the first assigned IP
  InetSocketAddress dst1 = InetSocketAddress (serverAddr1, servPort);
  PacketSinkHelper sink1 = PacketSinkHelper ("ns3::UdpSocketFactory", dst1);
  ApplicationContainer sinkApp1 = sink1.Install (terminals.Get (serverI));

  sinkApp1.Start (Seconds (sink_start_time));
  sinkApp1.Stop (Seconds (sink_stop_time));

  OnOffHelper onOff1 ("ns3::UdpSocketFactory", dst1);
  onOff1.SetAttribute ("PacketSize", UintegerValue (pktSize));
  onOff1.SetAttribute ("DataRate", StringValue (appDataRate));
  onOff1.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
  onOff1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
  // onOff1.SetAttribute ("MaxBytes", UintegerValue (20000));

  ApplicationContainer app1 = onOff1.Install (terminals.Get (clientI));
  app1.Start (Seconds (client_start_time));
  app1.Stop (Seconds (client_stop_time));

  sinkApp1.Get (0)->GetObject<PacketSink> ();
  Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApp1.Get (0));
  if (sink == nullptr)
    {
      std::cerr << "Error: DynamicCast to PacketSink failed!" << std::endl;
      return 0;
    }
  double sink_simulationTime = sink_stop_time - sink_start_time;
  Simulator::Schedule (Seconds (sink_stop_time), &CalculateThroughput, sink, sink_simulationTime);

  // Enable pcap tracing
  if (enableTracePcap)
    {
      // Define the base directory
      std::string baseDir = "/home/p4/data";

      // Create a subdirectory for the current run
      std::string runDir = baseDir + "/run_" + std::to_string (running_number);
      std::filesystem::create_directories (runDir); // Ensure the directory exists

      std::string pcapPrefix = runDir + "/p4-ipv4-forwarding-test-1";
      p4p2phelper.EnablePcapAll (pcapPrefix);
      // csma.EnablePcapAll ("p4-ipv4-forwarding-test");
    }

  // Run simulation
  NS_LOG_INFO ("Running simulation...");
  unsigned long simulate_start = getTickCount ();
  Simulator::Stop (Seconds (global_stop_time));
  Simulator::Run ();
  Simulator::Destroy ();

  unsigned long end = getTickCount ();
  NS_LOG_INFO ("Simulate Running time: " << end - simulate_start << "ms" << std::endl
                                         << "Total Running time: " << end - start << "ms"
                                         << std::endl
                                         << "Run successfully!");

  return 0;
}
