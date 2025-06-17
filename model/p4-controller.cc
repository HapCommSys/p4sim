#include "ns3/p4-controller.h"
#include "ns3/log.h"
#include <iostream>
#include <ns3/network-module.h>
#include "ns3/p4-switch-net-device.h"
namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("P4Controller");
NS_OBJECT_ENSURE_REGISTERED (P4Controller);


TypeId
P4Controller::GetTypeId (void)
{
  static TypeId tid =
      TypeId ("ns3::P4Controller").SetParent<Object> ().SetGroupName ("P4Controller");
  return tid;
}

P4Controller::P4Controller ()
{
  NS_LOG_FUNCTION (this);


  
}

P4Controller::~P4Controller ()
{
  NS_LOG_FUNCTION (this);

  // Clean up all P4SwitchInterface pointers
  // for (size_t i = 0; i < p4SwitchInterfaces_.size (); i++)
  //   {
  //     if (p4SwitchInterfaces_[i] != nullptr)
  //       {
  //         delete p4SwitchInterfaces_[i];
  //         p4SwitchInterfaces_[i] = nullptr;
  //       }
  //   }
}

void
P4Controller::ViewAllSwitchFlowTableInfo (ns3::NodeContainer nodes)
{
  
 
  NS_LOG_INFO("================= Flow Table =================");
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        ns3::Ptr<ns3::Node> node = nodes.Get(i);
  
        for (uint32_t j = 0; j < node->GetNDevices(); ++j) {
            ns3::Ptr<ns3::NetDevice> dev = node->GetDevice(j);
            ns3::Ptr<ns3::P4SwitchNetDevice> sw = ns3::DynamicCast<ns3::P4SwitchNetDevice>(dev);
            if (sw) {
              ViewP4SwitchFlowTableInfo(sw);
            }
        }
    }
}

void
P4Controller::ViewP4SwitchFlowTableInfo (Ptr<P4SwitchNetDevice> sw)
{

  std::string path = sw->GetFlowTablePath(); 
    std::ifstream infile(path);
    NS_LOG_INFO(path);
    if (!infile.is_open()) {
        // std::cerr << "Failed to open flow table file: " << path << std::endl;
        NS_LOG_ERROR("Error reading the file contents");
        return;
    }
    std::string line;
    while (std::getline(infile, line)) {
        NS_LOG_INFO( "  " << line << "\n");
    }

    infile.close();
    NS_LOG_INFO("-------------------------\n");
 
}

void
P4Controller::SetP4SwitchViewFlowTablePath (size_t index, const std::string &viewFlowTablePath)
{
  NS_LOG_FUNCTION (this << index << viewFlowTablePath);

  // if (index >= p4SwitchInterfaces_.size () || p4SwitchInterfaces_[index] == nullptr)
  //   {
  //     NS_LOG_ERROR ("Call SetP4SwitchViewFlowTablePath("
  //                   << index << "): P4SwitchInterface pointer is null or index out of range.");
  //     return;
  //   }

  // p4SwitchInterfaces_[index]->SetViewFlowTablePath (viewFlowTablePath);
}

void
P4Controller::SetP4SwitchFlowTablePath (size_t index, const std::string &flowTablePath)
{
  NS_LOG_FUNCTION (this << index << flowTablePath);

  // if (index >= p4SwitchInterfaces_.size () || p4SwitchInterfaces_[index] == nullptr)
  //   {
  //     NS_LOG_ERROR ("Call SetP4SwitchFlowTablePath("
  //                   << index << "): P4SwitchInterface pointer is null or index out of range.");
  //     return;
  //   }

  // p4SwitchInterfaces_[index]->SetFlowTablePath (flowTablePath);
}

// P4SwitchInterface *
// P4Controller::GetP4Switch (size_t index)
// {
//   NS_LOG_FUNCTION (this << index);

//   // if (index >= p4SwitchInterfaces_.size ())
//   //   {
//   //     NS_LOG_ERROR ("Call GetP4Switch(" << index << "): Index out of range.");
//   //     return nullptr;
//   //   }

//   // return p4SwitchInterfaces_[index];
// }

// P4SwitchInterface *
// P4Controller::AddP4Switch ()
// {
//   NS_LOG_FUNCTION (this);

//   P4SwitchInterface *p4SwitchInterface = new P4SwitchInterface;
//   p4SwitchInterfaces_.push_back (p4SwitchInterface);

//   NS_LOG_INFO ("Added a new P4 switch. Total switches: " << p4SwitchInterfaces_.size ());
//   return p4SwitchInterface;
// }

} // namespace ns3