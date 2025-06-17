#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/p4-controller.h"
#include "ns3/node.h"
using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TestFlowTable");

int main(int argc, char *argv[])
{
   LogComponentEnable("TestFlowTable",LOG_LEVEL_INFO);

    std::string flowTableDirPath= "/home/p4/workdir/ns3.39/contrib/p4sim/examples/p4src/test_flow"


     // Create nodes
    NodeContainer nodes;
    nodes.Create(2);  // Host1 <-> Switch

    Ptr<Node> host = nodes.Get(0);
    Ptr<Node> switchNode = nodes.Get(1);

    // Create and attach a P4 switch device to switch node
    Ptr<P4SwitchNetDevice> switchDev = CreateObject<P4SwitchNetDevice>();

    // Assume you have a flow table file in this path (create it manually)
    std::string flowTablePath = "flow_table_node1.txt";
    switchDev->SetFlowTablePath(flowTablePath);  // Your custom setter

   uint32_t idx= switchNode->AddDevice(switchDev);

    // You can add a dummy NetDevice to host if needed for realism
    Ptr<NetDevice> dummyHostDev = CreateObject<PointToPointNetDevice>();
    host->AddDevice(dummyHostDev);

    // Create a dummy controller and test the flow table view functions
    P4Controller controller;
    controller.ViewAllSwitchFlowTableInfo(nodes);


    Simulator::Run();
    Simulator::Destroy();

    return 0;
}