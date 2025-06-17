#define P4_CONTROLLER_H

#include "ns3/object.h"
#include "p4-switch-net-device.h"
#include <string>
#include <vector>
#include <ns3/network-module.h>

namespace ns3 {

// class P4SwitchInterface;

/**
 * @brief Controller for managing multiple P4 switches in an NS-3 simulation.
@@ -41,15 +42,15 @@ class P4Controller : public Object
  /**
     * @brief View flow table information for all P4 switches managed by the controller.
     */
  void ViewAllSwitchFlowTableInfo (ns3::NodeContainer nodes);

  /**
     * @brief View detailed flow table, counter, register, and meter information 
     *        for a specific P4 switch.
     * 
     * @param index Index of the P4 switch in the controller's collection.
     */
  void ViewP4SwitchFlowTableInfo (Ptr<P4SwitchNetDevice> sw);

  /**
     * @brief Set the path for viewing flow table information of a specific P4 switch.
@@ -73,14 +74,14 @@ class P4Controller : public Object
     * @param index Index of the P4 switch in the controller's collection.
     * @return Pointer to the requested P4SwitchInterface.
     */
//  P4SwitchInterface *GetP4Switch (size_t index);

  /**
     * @brief Add a new P4 switch to the controller.
     * 
     * @return Pointer to the newly added P4SwitchInterface.
     */
//   P4SwitchInterface *AddP4Switch ();

  /**
     * @brief Get the total number of P4 switches managed by the controller.
@@ -89,16 +90,16 @@ class P4Controller : public Object
     */
  unsigned int
  GetP4SwitchNum () const
  { return 1;
   //  return p4SwitchInterfaces_.size ();
  }

private:
  /**
     * @brief Collection of P4 switch interfaces managed by the controller.
     *        Each switch is identified by its index in this vector.
     */
//   std::vector<P4SwitchInterface *> p4SwitchInterfaces_;

  // Disable copy constructor and assignment operatorAdd commentMore actions
  P4Controller (const P4Controller &) = delete;