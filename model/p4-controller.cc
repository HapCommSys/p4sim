#include "ns3/p4-controller.h"

#include "ns3/core-module.h"
#include "ns3/log.h"
#include <iostream>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("P4Controller");
NS_OBJECT_ENSURE_REGISTERED(P4Controller);

TypeId P4Controller::GetTypeId(void) {
  static TypeId tid = TypeId("ns3::P4Controller")
                          .SetParent<Object>()
                          .SetGroupName("P4Controller");
  return tid;
}

P4Controller::P4Controller() { NS_LOG_FUNCTION(this); }

P4Controller::~P4Controller() { NS_LOG_FUNCTION(this); }

void P4Controller::RegisterSwitch(ns3::Ptr<ns3::P4SwitchNetDevice> sw) {
  m_connectedSwitches.push_back(sw);
  NS_LOG_INFO("Switch registered successfully");
}

uint32_t P4Controller::GetN() { return m_connectedSwitches.size(); }

void P4Controller::ConnectToSwitchEvents(uint32_t index) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];

  if (!sw) {
    NS_LOG_WARN("No switch found for " << index);
    return;
  }

  std::ostringstream path;
  path << "/NodeList/" << sw->GetNode()->GetId() << "/DeviceList/"
       << sw->GetIfIndex() << "/$ns3::P4SwitchNetDevice/SwitchEvent";

  Config::ConnectWithoutContext(
      path.str(), MakeCallback(&P4Controller::HandleSwitchEvent, this));

  NS_LOG_INFO("Connected to SwitchEvent trace source for switch " << index);
}

void P4Controller::HandleSwitchEvent(uint32_t switchId,
                                     const std::string &message) {
  NS_LOG_INFO("[Controller] Event from switch " << switchId << ": " << message);
}

void P4Controller::ViewAllSwitchFlowTableInfo() {
  NS_LOG_INFO("\n==== Viewing All P4 Switch Flow Tables ====\n");
  for (uint32_t i = 0; i < m_connectedSwitches.size(); ++i) {
    ViewP4SwitchFlowTableInfo(i);
  }
  NS_LOG_INFO("==========================================\n");
}

void P4Controller::ViewP4SwitchFlowTableInfo(uint32_t index) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_ERROR("[ERROR] Invalid switch index: " << index << "\n");
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  std::string path = sw->GetFlowTablePath();
  std::ifstream file(path);

  if (!file.is_open()) {
    NS_LOG_ERROR("[ERROR] Could not open flow table file at: " << path << "\n");
    return;
  }

  NS_LOG_INFO("Flow Table for Switch " << index << "\n");
  std::string line;
  while (std::getline(file, line)) {
    NS_LOG_INFO("  " << line << "\n");
  }
  file.close();
}

int P4Controller::GetTableEntryCount(uint32_t index,
                                     const std::string &tableName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return -1;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_WARN("Switch " << index << " has no v1model core (core is null)");
    return -1;
  }

  int num = core->GetNumEntries(tableName);
  return num;
}
void P4Controller::PrintTableEntryCount(uint32_t index,
                                        const std::string &tableName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_WARN("Switch " << index << " has no v1model core (core is null)");
    return;
  }

  int num = core->GetNumEntries(tableName);
  NS_LOG_INFO("Switch " << index << " - Table [" << tableName << "] has " << num
                        << " entries.");
}

void P4Controller::ClearFlowTableEntries(uint32_t index,
                                         const std::string &tableName,
                                         bool resetDefault) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_WARN("Switch " << index << " has no v1model core (core is null)");
    return;
  }
  int rc = core->ClearFlowTableEntries(tableName, resetDefault);

  if (rc == 0) {
    NS_LOG_INFO("Successfully cleared entries in table ["
                << tableName << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to clear entries in table ["
                 << tableName << "] on switch " << index);
  }
}

void P4Controller::AddFlowEntry(uint32_t index, const std::string &tableName,
                                const std::vector<bm::MatchKeyParam> &matchKey,
                                const std::string &actionName,
                                bm::ActionData &&actionData,
                                bm::entry_handle_t &handle, int priority) {
  NS_LOG_FUNCTION(this << index << tableName << actionName << priority);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int result = core->AddFlowEntry(tableName, matchKey, actionName,
                                  std::move(actionData), &handle, priority);
  if (result == 0) {
    std::cout << "Successfully added flow entry to table [" << tableName
              << "] on switch " << index << " (handle = " << handle << ")"
              << std::endl;
  } else {
    std::cout << "Failed to add flow entry to table [" << tableName
              << "] on switch " << index << ", result code = " << result
              << std::endl;
  }
}

void P4Controller::SetDefaultAction(uint32_t index,
                                    const std::string &tableName,
                                    const std::string &actionName,
                                    bm::ActionData &&actionData) {
  NS_LOG_FUNCTION(this << index << tableName << actionName);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status =
      core->SetDefaultAction(tableName, actionName, std::move(actionData));

  if (status == 0) {
    NS_LOG_INFO("Successfully set default action ["
                << actionName << "] for table [" << tableName << "] on switch "
                << index);
  } else {
    NS_LOG_ERROR("Failed to set default action for table ["
                 << tableName << "] on switch " << index
                 << ", code = " << status);
  }
}

void P4Controller::ResetDefaultEntry(uint32_t index,
                                     const std::string &tableName) {
  NS_LOG_FUNCTION(this << index << tableName);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->ResetDefaultEntry(tableName);

  if (status == 0) {
    NS_LOG_INFO("Successfully reset default entry for table ["
                << tableName << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to reset default entry for table ["
                 << tableName << "] on switch " << index
                 << ", code = " << status);
  }
}

void P4Controller::DeleteFlowEntry(uint32_t index, const std::string &tableName,
                                   bm::entry_handle_t handle) {
  NS_LOG_FUNCTION(this << index << tableName << handle);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->DeleteFlowEntry(tableName, handle);

  if (status == 0) {
    NS_LOG_INFO("Successfully deleted entry (handle = "
                << handle << ") from table [" << tableName << "] on switch "
                << index);
  } else {
    NS_LOG_ERROR("Failed to delete entry from table ["
                 << tableName << "] on switch " << index
                 << ", code = " << status);
  }
}

void P4Controller::ModifyFlowEntry(uint32_t index, const std::string &tableName,
                                   bm::entry_handle_t handle,
                                   const std::string &actionName,
                                   bm::ActionData actionData) {
  NS_LOG_FUNCTION(this << index << tableName << handle << actionName);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->ModifyFlowEntry(tableName, handle, actionName,
                                     std::move(actionData));

  if (status == 0) {
    NS_LOG_INFO("Modified flow entry for handle " << handle << " in table ["
                                                  << tableName << "] on switch "
                                                  << index);
  } else {
    NS_LOG_ERROR("Failed to modify flow entry for handle "
                 << handle << " in table [" << tableName << "] on switch "
                 << index);
  }
}

void P4Controller::SetEntryTtl(uint32_t index, const std::string &tableName,
                               bm::entry_handle_t handle, unsigned int ttlMs) {
  NS_LOG_FUNCTION(this << index << tableName << handle << ttlMs);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->SetEntryTtl(tableName, handle, ttlMs);

  if (status == 0) {
    NS_LOG_INFO("Set TTL = " << ttlMs << "ms for entry handle " << handle
                             << " in table [" << tableName << "] on switch "
                             << index);
  } else {
    NS_LOG_ERROR("Failed to set TTL for entry handle "
                 << handle << " in table [" << tableName << "] on switch "
                 << index);
  }
}

// ======== Action Profile Operations ===========

void P4Controller::AddActionProfileMember(
    uint32_t index, const std::string &profileName,
    const std::string &actionName, bm::ActionData &&actionData,
    bm::ActionProfile::mbr_hdl_t mbrHandle) {
  NS_LOG_FUNCTION(this << index << profileName << actionName);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  auto core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->AddActionProfileMember(profileName, actionName,
                                            std::move(actionData), &mbrHandle);

  if (status == 0) {
    NS_LOG_INFO("Added action profile member to profile ["
                << profileName << "] on switch " << index
                << ", got handle: " << mbrHandle);
  } else {
    NS_LOG_ERROR("Failed to add member to action profile ["
                 << profileName << "] on switch " << index);
  }
}

void P4Controller::DeleteActionProfileMember(
    uint32_t index, const std::string &profileName,
    bm::ActionProfile::mbr_hdl_t memberHandle) {
  NS_LOG_FUNCTION(this << index << profileName << memberHandle);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  auto core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->DeleteActionProfileMember(profileName, memberHandle);

  if (status == 0) {
    NS_LOG_INFO("Deleted action profile member "
                << memberHandle << " from profile [" << profileName
                << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to delete member " << memberHandle << " from profile ["
                                            << profileName << "] on switch "
                                            << index);
  }
}

void P4Controller::ModifyActionProfileMember(
    uint32_t index, const std::string &profileName,
    bm::ActionProfile::mbr_hdl_t memberHandle, const std::string &actionName,
    bm::ActionData &&actionData) {
  NS_LOG_FUNCTION(this << index << profileName << memberHandle << actionName);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  auto core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->ModifyActionProfileMember(
      profileName, memberHandle, actionName, std::move(actionData));

  if (status == 0) {
    NS_LOG_INFO("Modified member " << memberHandle << " in profile ["
                                   << profileName << "] to action ["
                                   << actionName << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to modify member " << memberHandle << " in profile ["
                                            << profileName << "] on switch "
                                            << index);
  }
}

void P4Controller::CreateActionProfileGroup(
    uint32_t index, const std::string &profileName,
    bm::ActionProfile::grp_hdl_t *outHandle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->CreateActionProfileGroup(profileName, outHandle);
  if (status == 0) {
    NS_LOG_INFO("Created action profile group in profile ["
                << profileName << "] on switch " << index
                << ", handle: " << *outHandle);
  } else {
    NS_LOG_ERROR("Failed to create group in action profile ["
                 << profileName << "] on switch " << index);
  }
}

void P4Controller::DeleteActionProfileGroup(
    uint32_t index, const std::string &profileName,
    bm::ActionProfile::grp_hdl_t groupHandle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->DeleteActionProfileGroup(profileName, groupHandle);
  if (status == 0) {
    NS_LOG_INFO("Deleted group " << groupHandle << " from action profile ["
                                 << profileName << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to delete group "
                 << groupHandle << " from action profile [" << profileName
                 << "] on switch " << index);
  }
}

void P4Controller::AddMemberToGroup(uint32_t index,
                                    const std::string &profileName,
                                    bm::ActionProfile::mbr_hdl_t memberHandle,
                                    bm::ActionProfile::grp_hdl_t groupHandle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->AddMemberToGroup(profileName, memberHandle, groupHandle);
  if (status == 0) {
    std::cout << "Added member " << memberHandle << " to group " << groupHandle
              << " in action profile [" << profileName << "] on switch "
              << index;
  } else {
    NS_LOG_ERROR("Failed to add member "
                 << memberHandle << " to group " << groupHandle
                 << " in action profile [" << profileName << "] on switch "
                 << index);
  }
}
void P4Controller::RemoveMemberFromGroup(
    uint32_t index, const std::string &profileName,
    bm::ActionProfile::mbr_hdl_t memberHandle,
    bm::ActionProfile::grp_hdl_t groupHandle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status =
      core->RemoveMemberFromGroup(profileName, memberHandle, groupHandle);
  if (status == 0) {
    NS_LOG_INFO("Removed member " << memberHandle << " from group "
                                  << groupHandle << " in profile ["
                                  << profileName << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to remove member "
                 << memberHandle << " from group " << groupHandle
                 << " in profile [" << profileName << "] on switch " << index);
  }
}

std::vector<bm::ActionProfile::Member>
P4Controller::GetActionProfileMembers(uint32_t index,
                                      const std::string &profileName) {
  std::vector<bm::ActionProfile::Member> members;

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return members;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return members;
  }

  int status = core->GetActionProfileMembers(profileName, &members);
  if (status == 0) {
    return members;
  } else {
    NS_LOG_ERROR("Failed to get members from profile ["
                 << profileName << "] on switch " << index);
    return members;
  }
}
void P4Controller::PrintActionProfileMembers(uint32_t index,
                                             const std::string &profileName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  std::vector<bm::ActionProfile::Member> members;
  int status = core->GetActionProfileMembers(profileName, &members);
  if (status == 0) {
    std::cout << "=============    Printing ActionProfile members ============"
              << std::endl;

    for (const auto &member : members) {

      std::cout << "  Member Handle: " << member.mbr;

      // Action name (if available)
      if (member.action_fn) {
        std::cout << ", Action Name: " << member.action_fn->get_name();
      } else {
        std::cout << ", Action Name: [nullptr]";
      }

      // Action parameters
      std::cout << ", Action Params: [ ";
      for (const auto &param : member.action_data.action_data) {
        // ADD a method to print param
        std::cout << param.get_string() << " " << std::endl;
      }
      std::cout << "]" << std::endl;
    }
  } else {
    NS_LOG_ERROR("Failed to get members from profile ["
                 << profileName << "] on switch " << index);
  }
}
void P4Controller::GetActionProfileMember(
    uint32_t index, const std::string &profileName,
    bm::ActionProfile::mbr_hdl_t memberHandle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  bm::ActionProfile::Member member;
  int status = core->GetActionProfileMember(profileName, memberHandle, &member);
  if (status == 0) {
    NS_LOG_INFO("Retrieved member " << memberHandle << " from profile ["
                                    << profileName << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to get member " << memberHandle << " from profile ["
                                         << profileName << "] on switch "
                                         << index);
  }
}
void P4Controller::PrintActionProfileGroups(uint32_t index,
                                            const std::string &profileName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  std::vector<bm::ActionProfile::Group> groups;
  int status = core->GetActionProfileGroups(profileName, &groups);

  if (status == 0) {
    NS_LOG_INFO("Retrieved " << groups.size()
                             << " group(s) from action profile [" << profileName
                             << "] on switch " << index);

    for (const auto &group : groups) {

      std::cout << "  Group ID: " << group.grp << ", Members: [" << std::endl;

      for (size_t i = 0; i < group.mbr_handles.size(); ++i) {
        std::cout << group.mbr_handles[i];
        if (i != group.mbr_handles.size() - 1) {
          std::cout << ", ";
        }
      }
      std::cout << "]" << std::endl;
    }
  } else {
    std::cout << "Failed to retrieve groups from profile [" << profileName
              << "] on switch " << index;
  }
}

void P4Controller::GetActionProfileGroups(uint32_t index,
                                          const std::string &profileName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  std::vector<bm::ActionProfile::Group> groups;
  int status = core->GetActionProfileGroups(profileName, &groups);

  if (status == 0) {
    NS_LOG_INFO("Retrieved " << groups.size() << " groups from action profile ["
                             << profileName << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to retrieve groups from profile ["
                 << profileName << "] on switch " << index);
  }
}

void P4Controller::GetActionProfileGroup(
    uint32_t index, const std::string &profileName,
    bm::ActionProfile::grp_hdl_t groupHandle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  bm::ActionProfile::Group group;
  int status = core->GetActionProfileGroup(profileName, groupHandle, &group);

  if (status == 0) {
    NS_LOG_INFO("Retrieved group handle "
                << groupHandle << " from action profile [" << profileName
                << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to retrieve group handle "
                 << groupHandle << " from profile [" << profileName
                 << "] on switch " << index);
  }
}

// ========== Indirect Table Operations ============
void P4Controller::AddIndirectEntry(
    uint32_t index, const std::string &tableName,
    const std::vector<bm::MatchKeyParam> &matchKey,
    bm::ActionProfile::mbr_hdl_t memberHandle, bm::entry_handle_t *outHandle,
    int priority) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->AddIndirectEntry(tableName, matchKey, memberHandle,
                                      outHandle, priority);

  if (status == 0) {
    NS_LOG_INFO("Added indirect entry to table ["
                << tableName << "] with handle " << *outHandle
                << " and member handle " << memberHandle << " on switch "
                << index);
  } else {
    NS_LOG_ERROR("Failed to add indirect entry to table ["
                 << tableName << "] on switch " << index);
  }
}

void P4Controller::ModifyIndirectEntry(
    uint32_t index, const std::string &tableName,
    bm::entry_handle_t entryHandle, bm::ActionProfile::mbr_hdl_t memberHandle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->ModifyIndirectEntry(tableName, entryHandle, memberHandle);

  if (status == 0) {
    NS_LOG_INFO("Modified indirect entry "
                << entryHandle << " in table [" << tableName << "] to member "
                << memberHandle << " on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to modify indirect entry "
                 << entryHandle << " in table [" << tableName << "] on switch "
                 << index);
  }
}

void P4Controller::DeleteIndirectEntry(uint32_t index,
                                       const std::string &tableName,
                                       bm::entry_handle_t entryHandle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->DeleteIndirectEntry(tableName, entryHandle);

  if (status == 0) {
    NS_LOG_INFO("Deleted indirect entry " << entryHandle << " from table ["
                                          << tableName << "] on switch "
                                          << index);
  } else {
    NS_LOG_ERROR("Failed to delete indirect entry "
                 << entryHandle << " from table [" << tableName
                 << "] on switch " << index);
  }
}
void P4Controller::SetIndirectEntryTtl(uint32_t index,
                                       const std::string &tableName,
                                       bm::entry_handle_t handle,
                                       unsigned int ttlMs) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->SetIndirectEntryTtl(tableName, handle, ttlMs);

  if (status == 0) {
    NS_LOG_INFO("Set TTL = " << ttlMs << "ms for indirect entry " << handle
                             << " in table [" << tableName << "] on switch "
                             << index);
  } else {
    NS_LOG_ERROR("Failed to set TTL for indirect entry "
                 << handle << " in table [" << tableName << "] on switch "
                 << index);
  }
}

void P4Controller::SetIndirectDefaultMember(
    uint32_t index, const std::string &tableName,
    bm::ActionProfile::mbr_hdl_t memberHandle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->SetIndirectDefaultMember(tableName, memberHandle);

  if (status == 0) {
    NS_LOG_INFO("Set default member " << memberHandle << " for table ["
                                      << tableName << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to set default member " << memberHandle
                                                 << " for table [" << tableName
                                                 << "] on switch " << index);
  }
}

void P4Controller::ResetIndirectDefaultEntry(uint32_t index,
                                             const std::string &tableName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->ResetIndirectDefaultEntry(tableName);

  if (status == 0) {
    NS_LOG_INFO("Reset indirect default entry for table ["
                << tableName << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to reset indirect default entry for table ["
                 << tableName << "] on switch " << index);
  }
}
void P4Controller::AddIndirectWsEntry(
    uint32_t index, const std::string &tableName,
    const std::vector<bm::MatchKeyParam> &matchKey,
    bm::ActionProfile::grp_hdl_t groupHandle, bm::entry_handle_t *outHandle,
    int priority) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->AddIndirectWsEntry(tableName, matchKey, groupHandle,
                                        outHandle, priority);

  if (status == 0) {
    NS_LOG_INFO("Added indirect WS entry with group "
                << groupHandle << " to table [" << tableName << "] on switch "
                << index << ", assigned handle: " << *outHandle);
  } else {
    NS_LOG_ERROR("Failed to add indirect WS entry to table ["
                 << tableName << "] on switch " << index);
  }
}

void P4Controller::ModifyIndirectWsEntry(
    uint32_t index, const std::string &tableName, bm::entry_handle_t handle,
    bm::ActionProfile::grp_hdl_t groupHandle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->ModifyIndirectWsEntry(tableName, handle, groupHandle);

  if (status == 0) {
    NS_LOG_INFO("Modified indirect WS entry "
                << handle << " in table [" << tableName << "] to group "
                << groupHandle << " on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to modify indirect WS entry in table ["
                 << tableName << "] on switch " << index);
  }
}

void P4Controller::SetIndirectWsDefaultGroup(
    uint32_t index, const std::string &tableName,
    bm::ActionProfile::grp_hdl_t groupHandle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->SetIndirectWsDefaultGroup(tableName, groupHandle);

  if (status == 0) {
    NS_LOG_INFO("Set default group " << groupHandle
                                     << " for indirect WS table [" << tableName
                                     << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to set default group for table ["
                 << tableName << "] on switch " << index);
  }
}

// ========= Flow Table Entry Retrieval Operations ==========
void P4Controller::PrintFlowEntries(uint32_t index,
                                    const std::string &tableName) {
  NS_LOG_FUNCTION(this << index << tableName);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  std::vector<bm::MatchTable::Entry> entries = core->GetFlowEntries(tableName);

  NS_LOG_INFO("Flow entries in table [" << tableName << "] on switch " << index
                                        << ":");

  for (const auto &entry : entries) {

    std::cout << "  Handle: " << entry.handle
              << ", Priority: " << entry.priority
              << ", Action: " << entry.action_fn->get_name() << std::endl;
  }

  if (entries.empty()) {
    NS_LOG_INFO("  [No entries found]");
  }
}

void P4Controller::PrintIndirectFlowEntries(uint32_t index,
                                            const std::string &tableName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("No V1Model core for switch " << index);
    return;
  }

  std::vector<bm::MatchTableIndirect::Entry> entries =
      core->GetIndirectFlowEntries(tableName);
  NS_LOG_INFO("Indirect entries in [" << tableName << "] on switch " << index
                                      << ":");
  NS_LOG_INFO("The size of table is" << entries.size());

  for (const auto &e : entries) {
    NS_LOG_INFO("  Handle: " << e.handle << ", Mbr Handle: " << e.mbr
                             << ", Priority: " << e.priority);
  }
}

void P4Controller::PrintIndirectWsFlowEntries(uint32_t index,
                                              const std::string &tableName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("No V1Model core for switch " << index);
    return;
  }

  std::vector<bm::MatchTableIndirectWS::Entry> entries =
      core->GetIndirectWsFlowEntries(tableName);
  NS_LOG_INFO("WS Indirect entries in [" << tableName << "] on switch " << index
                                         << ":");
  NS_LOG_INFO("The size of table is" << entries.size());
  for (const auto &e : entries) {
    NS_LOG_INFO("The control flow is reaching here");
    NS_LOG_INFO("  Handle: " << e.handle << ", Group Handle: " << e.grp
                             << ", Priority: " << e.priority);
  }
}

void P4Controller::PrintEntry(uint32_t index, const std::string &tableName,
                              bm::entry_handle_t handle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("No V1Model core for switch " << index);
    return;
  }

  bm::MatchTable::Entry entry;
  int rc = core->GetEntry(tableName, handle, &entry);
  if (rc == 0) {
    std::string actionName = entry.action_fn->get_name();
    NS_LOG_INFO("Entry for handle " << handle << ": action = " << actionName
                                    << ", priority = " << entry.priority);

    // Print action parameters
    //     const auto& actionData = entry.action_data;
    //    NS_LOG_INFO(actionData);
  } else {
    NS_LOG_WARN("Failed to get entry for handle " << handle << " from table "
                                                  << tableName);
  }
}

void P4Controller::PrintDefaultEntry(uint32_t index,
                                     const std::string &tableName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("No V1Model core for switch " << index);
    return;
  }

  bm::MatchTable::Entry entry;
  int rc = core->GetDefaultEntry(tableName, &entry);
  if (rc != 0) {
    NS_LOG_WARN("Failed to get default entry from table: " << tableName);
    return;
  }

  std::string actionName = entry.action_fn->get_name();
  std::cout << "Default entry for table " << tableName
            << ": action = " << actionName;
}

void P4Controller::PrintIndirectDefaultEntry(uint32_t index,
                                             const std::string &tableName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("No V1Model core for switch " << index);
    return;
  }

  bm::MatchTableIndirect::Entry entry;
  int rc = core->GetIndirectDefaultEntry(tableName, &entry);
  if (rc != 0) {
    NS_LOG_WARN(
        "Failed to get indirect default entry for table: " << tableName);
    return;
  }

  NS_LOG_INFO("Indirect default entry for table "
              << tableName << ": mbr_handle = " << entry.mbr);
}

void P4Controller::PrintIndirectWsDefaultEntry(uint32_t index,
                                               const std::string &tableName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("No V1Model core for switch " << index);
    return;
  }

  bm::MatchTableIndirectWS::Entry entry;
  int rc = core->GetIndirectWsDefaultEntry(tableName, &entry);
  if (rc != 0) {
    NS_LOG_WARN(
        "Failed to get indirect WS default entry for table: " << tableName);
    return;
  }

  NS_LOG_INFO("Indirect WS default entry for table "
              << tableName << ": grp_handle = " << entry.grp);
}

void P4Controller::PrintEntryFromKey(
    uint32_t index, const std::string &tableName,
    const std::vector<bm::MatchKeyParam> &matchKey) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("No V1Model core for switch " << index);
    return;
  }

  bm::MatchTable::Entry entry;
  int rc = core->GetEntryFromKey(tableName, matchKey, &entry);
  if (rc != 0) {
    NS_LOG_WARN("No entry found for key in table " << tableName);
    return;
  }

  NS_LOG_INFO("Entry from key in "
              << tableName << ": action = " << entry.action_fn->get_name()
              << ", priority = " << entry.priority);
}

void P4Controller::PrintIndirectEntryFromKey(
    uint32_t index, const std::string &tableName,
    const std::vector<bm::MatchKeyParam> &matchKey) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("No V1Model core for switch " << index);
    return;
  }

  bm::MatchTableIndirect::Entry entry;
  int rc = core->GetIndirectEntryFromKey(tableName, matchKey, &entry);
  if (rc != 0) {
    NS_LOG_WARN("Indirect entry not found for key in table " << tableName);
    return;
  }

  NS_LOG_INFO("Indirect Entry from key in ["
              << tableName << "] on switch " << index << ": handle = "
              << entry.handle << ", member handle = " << entry.mbr
              << ", priority = " << entry.priority);
}

void P4Controller::PrintIndirectWsEntryFromKey(
    uint32_t index, const std::string &tableName,
    const std::vector<bm::MatchKeyParam> &matchKey) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("No V1Model core for switch " << index);
    return;
  }

  bm::MatchTableIndirectWS::Entry entry;
  int rc = core->GetIndirectWsEntryFromKey(tableName, matchKey, &entry);
  if (rc != 0) {
    NS_LOG_WARN("Indirect WS entry not found for key in table " << tableName);
    return;
  }

  NS_LOG_INFO("Indirect WS Entry from key in ["
              << tableName << "] on switch " << index << ": handle = "
              << entry.handle << ", member handle = " << entry.mbr
              << ", group handle = " << entry.grp
              << ", priority = " << entry.priority);
}

void P4Controller::ReadCounters(uint32_t index, const std::string &tableName,
                                bm::entry_handle_t handle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  uint64_t bytes = 0, packets = 0;
  if (core->ReadTableCounters(tableName, handle, &bytes, &packets) == 0) {
    NS_LOG_INFO("Switch " << index << ", Table " << tableName << ", Handle "
                          << handle << " → Packets: " << packets
                          << ", Bytes: " << bytes);
  }
}

void P4Controller::ResetCounters(uint32_t index, const std::string &tableName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->ResetTableCounters(tableName);
  if (status == 0) {
    NS_LOG_INFO("Reset counters for table [" << tableName << "] on switch "
                                             << index);
  } else {
    NS_LOG_ERROR("Failed to reset counters for table ["
                 << tableName << "] on switch " << index);
  }
}

void P4Controller::WriteCounters(uint32_t index, const std::string &tableName,
                                 bm::entry_handle_t handle, uint64_t bytes,
                                 uint64_t packets) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->WriteTableCounters(tableName, handle, bytes, packets);
  if (status == 0) {
    NS_LOG_INFO("Wrote counters for entry handle "
                << handle << " in table [" << tableName << "] on switch "
                << index << ": bytes = " << bytes << ", packets = " << packets);
  } else {
    NS_LOG_ERROR("Failed to write counters for entry handle "
                 << handle << " in table [" << tableName << "] on switch "
                 << index);
  }
}

void P4Controller::ReadCounter(uint32_t index, const std::string &counterName,
                               size_t counterIndex) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  bm::MatchTableAbstract::counter_value_t bytes, packets;
  auto rc = core->ReadCounter(counterName, counterIndex, &bytes, &packets);

  if (rc == bm::Counter::CounterErrorCode::SUCCESS) {
    NS_LOG_INFO("ReadCounter for [" << counterName << "] at index "
                                    << counterIndex << " on switch " << index
                                    << ": " << bytes << " bytes, " << packets
                                    << " packets");
  } else {
    NS_LOG_ERROR("Failed to read counter ["
                 << counterName << "] at index " << counterIndex
                 << " on switch " << index << ": " << static_cast<int>(rc));
  }
}

void P4Controller::ResetCounter(uint32_t index,
                                const std::string &counterName) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->ResetCounter(counterName);
  if (status == 0) {
    NS_LOG_INFO("Reset counter [" << counterName << "] on switch " << index);
  } else {
    NS_LOG_ERROR("Failed to reset counter [" << counterName << "] on switch "
                                             << index);
  }
}

void P4Controller::WriteCounter(
    uint32_t index, const std::string &counterName, size_t counterIndex,
    bm::MatchTableAbstract::counter_value_t bytes,
    bm::MatchTableAbstract::counter_value_t packets) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  int status = core->WriteCounter(counterName, counterIndex, bytes, packets);
  if (status == 0) {
    NS_LOG_INFO("Wrote counter [" << counterName << "] at index "
                                  << counterIndex << " on switch " << index
                                  << ": " << bytes << " bytes, " << packets
                                  << " packets");
  } else {
    NS_LOG_ERROR("Failed to write counter [" << counterName << "] at index "
                                             << counterIndex << " on switch "
                                             << index);
  }
}

// ========== Meter Operations ===========

void P4Controller::SetMeterRates(
    uint32_t index, const std::string &tableName, bm::entry_handle_t handle,
    const std::vector<bm::Meter::rate_config_t> &configs) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  bool success = core->SetMeterRates(tableName, handle, configs) == 0;
  if (success) {
    NS_LOG_INFO("SetMeterRates succeeded for table ["
                << tableName << "] on switch " << index);
  } else {
    NS_LOG_WARN("SetMeterRates failed for table [" << tableName
                                                   << "] on switch " << index);
  }
}

void P4Controller::GetMeterRates(uint32_t index, const std::string &tableName,
                                 bm::entry_handle_t handle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  std::vector<bm::Meter::rate_config_t> configs;
  bool success = core->GetMeterRates(tableName, handle, &configs) == 0;
  if (success) {
    NS_LOG_INFO("Meter rates for [" << tableName << "] handle " << handle
                                    << " on switch " << index << ":");
    for (const auto &cfg : configs) {
      NS_LOG_INFO("  CIR=" << cfg.info_rate << ", PBS=" << cfg.burst_size);
    }
  } else {
    NS_LOG_WARN("GetMeterRates failed for table [" << tableName
                                                   << "] on switch " << index);
  }
}

void P4Controller::ResetMeterRates(uint32_t index, const std::string &tableName,
                                   bm::entry_handle_t handle) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  bool success = core->ResetMeterRates(tableName, handle) == 0;
  if (success) {
    NS_LOG_INFO("ResetMeterRates succeeded for table ["
                << tableName << "] on switch " << index);
  } else {
    NS_LOG_WARN("ResetMeterRates failed for table ["
                << tableName << "] on switch " << index);
  }
}

void P4Controller::SetMeterArrayRates(
    uint32_t index, const std::string &meterName,
    const std::vector<bm::Meter::rate_config_t> &configs) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  bool success = core->SetMeterArrayRates(meterName, configs) == 0;
  if (success) {
    NS_LOG_INFO("SetMeterArrayRates succeeded for meter ["
                << meterName << "] on switch " << index);
  } else {
    NS_LOG_WARN("SetMeterArrayRates failed for meter ["
                << meterName << "] on switch " << index);
  }
}

void P4Controller::SetMeterRates(
    uint32_t index, const std::string &meterName, size_t idx,
    const std::vector<bm::Meter::rate_config_t> &configs) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  bool success = core->SetMeterRates(meterName, idx, configs) == 0;
  if (success) {
    NS_LOG_INFO("SetMeterRates succeeded for meter ["
                << meterName << "] index " << idx << " on switch " << index);
  } else {
    NS_LOG_WARN("SetMeterRates failed for meter ["
                << meterName << "] index " << idx << " on switch " << index);
  }
}

void P4Controller::GetMeterRates(uint32_t index, const std::string &meterName,
                                 size_t idx) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  std::vector<bm::Meter::rate_config_t> configs;
  bool success = core->GetMeterRates(meterName, idx, &configs) == 0;
  if (success) {
    NS_LOG_INFO("Meter rates for [" << meterName << "] index " << idx
                                    << " on switch " << index << ":");
    for (const auto &cfg : configs) {
      NS_LOG_INFO("  CIR=" << cfg.info_rate << ", PBS=" << cfg.burst_size);
    }
  } else {
    NS_LOG_WARN("GetMeterRates failed for meter ["
                << meterName << "] index " << idx << " on switch " << index);
  }
}

void P4Controller::ResetMeterRates(uint32_t index, const std::string &meterName,
                                   size_t idx) {
  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_WARN("No V1Model core found for switch " << index);
    return;
  }

  bool success = core->ResetMeterRates(meterName, idx) == 0;
  if (success) {
    NS_LOG_INFO("ResetMeterRates succeeded for meter ["
                << meterName << "] index " << idx << " on switch " << index);
  } else {
    NS_LOG_WARN("ResetMeterRates failed for meter ["
                << meterName << "] index " << idx << " on switch " << index);
  }
}

// ======= Register  Functions  =======
void P4Controller::RegisterRead(uint32_t index, const std::string &registerName,
                                size_t regIndex, bm::Data *value) {
  NS_LOG_FUNCTION(this << index << registerName << regIndex);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->RegisterRead(registerName, regIndex, value);

  if (status == 0) {
    NS_LOG_INFO("RegisterRead succeeded: switch "
                << index << ", register [" << registerName << "], index "
                << regIndex << ", value = " << value);
  } else {
    NS_LOG_ERROR("RegisterRead failed for switch "
                 << index << ", register [" << registerName << "], index "
                 << regIndex);
  }
}

void P4Controller::RegisterWrite(uint32_t index,
                                 const std::string &registerName,
                                 size_t regIndex, const bm::Data &value) {
  NS_LOG_FUNCTION(this << index << registerName << regIndex << value);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->RegisterWrite(registerName, regIndex, value);

  if (status == 0) {
    NS_LOG_INFO("RegisterWrite succeeded: switch "
                << index << ", register [" << registerName << "], index "
                << regIndex << ", value = " << value);
  } else {
    NS_LOG_ERROR("RegisterWrite failed for switch "
                 << index << ", register [" << registerName << "], index "
                 << regIndex);
  }
}

void P4Controller::RegisterReadAll(uint32_t index,
                                   const std::string &registerName) {
  NS_LOG_FUNCTION(this << index << registerName);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  std::vector<bm::Data> values = core->RegisterReadAll(registerName);

  if (!values.empty()) {
    NS_LOG_INFO("RegisterReadAll succeeded for register ["
                << registerName << "] on switch " << index
                << ". Number of values: " << values.size());
  } else {
    NS_LOG_ERROR("RegisterReadAll failed or returned empty for register ["
                 << registerName << "] on switch " << index);
  }
}

void P4Controller::RegisterWriteRange(uint32_t index,
                                      const std::string &registerName,
                                      size_t startIndex, size_t endIndex,
                                      const bm::Data &value) {
  NS_LOG_FUNCTION(this << index << registerName << startIndex << endIndex
                       << value);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status =
      core->RegisterWriteRange(registerName, startIndex, endIndex, value);

  if (status == 0) {
    NS_LOG_INFO("RegisterWriteRange succeeded: switch "
                << index << ", register [" << registerName << "], indices ["
                << startIndex << "-" << endIndex << "], value = " << value);
  } else {
    NS_LOG_ERROR("RegisterWriteRange failed for switch "
                 << index << ", register [" << registerName << "], indices ["
                 << startIndex << "-" << endIndex << "]");
  }
}

void P4Controller::RegisterReset(uint32_t index,
                                 const std::string &registerName) {
  NS_LOG_FUNCTION(this << index << registerName);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  Ptr<P4SwitchNetDevice> sw = m_connectedSwitches[index];
  P4CoreV1model *core = sw->GetV1ModelCore();

  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->RegisterReset(registerName);

  if (status == 0) {
    NS_LOG_INFO("RegisterReset succeeded for register ["
                << registerName << "] on switch " << index);
  } else {
    NS_LOG_ERROR("RegisterReset failed for register ["
                 << registerName << "] on switch " << index);
  }
}
void P4Controller::ParseVsetGet(uint32_t index, const std::string &vsetName) {
  NS_LOG_FUNCTION(this << index << vsetName);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  std::vector<bm::ByteContainer> values;
  int status = core->ParseVsetGet(vsetName, &values);

  if (status == 0) {
    NS_LOG_INFO("ParseVsetGet succeeded for switch "
                << index << ", vset [" << vsetName
                << "], count = " << values.size());
    for (size_t i = 0; i < values.size(); ++i) {
      NS_LOG_INFO("  Value[" << i << "] = " << values[i].to_hex());
    }
  } else {
    NS_LOG_ERROR("ParseVsetGet failed for switch " << index << ", vset ["
                                                   << vsetName << "]");
  }
}
void P4Controller::ParseVsetAdd(uint32_t index, const std::string &vsetName,
                                const bm::ByteContainer &value) {
  NS_LOG_FUNCTION(this << index << vsetName << value.to_hex());

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->ParseVsetAdd(vsetName, value);
  if (status == 0) {
    NS_LOG_INFO("ParseVsetAdd succeeded for switch "
                << index << ", vset [" << vsetName
                << "], value = " << value.to_hex());
  } else {
    NS_LOG_ERROR("ParseVsetAdd failed for switch " << index << ", vset ["
                                                   << vsetName << "]");
  }
}

void P4Controller::ParseVsetRemove(uint32_t index, const std::string &vsetName,
                                   const bm::ByteContainer &value) {
  NS_LOG_FUNCTION(this << index << vsetName << value.to_hex());

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->ParseVsetRemove(vsetName, value);
  if (status == 0) {
    NS_LOG_INFO("ParseVsetRemove succeeded for switch "
                << index << ", vset [" << vsetName
                << "], value = " << value.to_hex());
  } else {
    NS_LOG_ERROR("ParseVsetRemove failed for switch " << index << ", vset ["
                                                      << vsetName << "]");
  }
}

void P4Controller::ParseVsetClear(uint32_t index, const std::string &vsetName) {
  NS_LOG_FUNCTION(this << index << vsetName);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  auto core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->ParseVsetClear(vsetName);
  if (status == 0) {
    NS_LOG_INFO("ParseVsetClear succeeded for switch " << index << ", vset ["
                                                       << vsetName << "]");
  } else {
    NS_LOG_ERROR("ParseVsetClear failed for switch " << index << ", vset ["
                                                     << vsetName << "]");
  }
}

void P4Controller::ResetState(uint32_t index) {
  NS_LOG_FUNCTION(this << index);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->ResetState();
  if (status == 0) {
    NS_LOG_INFO("ResetState succeeded for switch " << index);
  } else {
    NS_LOG_ERROR("ResetState failed for switch " << index);
  }
}

void P4Controller::Serialize(uint32_t index, std::ostream *out) {
  NS_LOG_FUNCTION(this << index);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->Serialize(out);
  if (status == 0) {
    NS_LOG_INFO("Serialize succeeded for switch " << index);
  } else {
    NS_LOG_ERROR("Serialize failed for switch " << index);
  }
}

void P4Controller::LoadNewConfig(uint32_t index, const std::string &newConfig) {
  NS_LOG_FUNCTION(this << index);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  P4CoreV1model *core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->LoadNewConfig(newConfig);
  if (status == 0) {
    NS_LOG_INFO("LoadNewConfig succeeded for switch " << index);
  } else {
    NS_LOG_ERROR("LoadNewConfig failed for switch " << index);
  }
}

void P4Controller::SwapConfigs(uint32_t index) {
  NS_LOG_FUNCTION(this << index);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  auto core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  int status = core->SwapConfigs();
  if (status == 0) {
    NS_LOG_INFO("SwapConfigs succeeded on switch " << index);
  } else {
    NS_LOG_ERROR("SwapConfigs failed on switch " << index);
  }
}

void P4Controller::GetConfig(uint32_t index) {
  NS_LOG_FUNCTION(this << index);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  auto core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  std::string config;
  int status = core->GetConfig(&config);
  if (status == 0) {
    NS_LOG_INFO("GetConfig succeeded for switch " << index);
    NS_LOG_INFO("  Config string: " << config);
  } else {
    NS_LOG_ERROR("GetConfig failed for switch " << index);
  }
}

void P4Controller::GetConfigMd5(uint32_t index) {
  NS_LOG_FUNCTION(this << index);

  if (index >= m_connectedSwitches.size()) {
    NS_LOG_WARN("Invalid switch index " << index);
    return;
  }

  auto core = m_connectedSwitches[index]->GetV1ModelCore();
  if (!core) {
    NS_LOG_ERROR("V1Model core not found for switch " << index);
    return;
  }

  std::string md5;
  int status = core->GetConfigMd5(&md5);
  if (status == 0) {
    NS_LOG_INFO("GetConfigMd5 succeeded for switch " << index);
    NS_LOG_INFO("  Config MD5: " << md5);
  } else {
    NS_LOG_ERROR("GetConfigMd5 failed for switch " << index);
  }
}

void P4Controller::SetP4SwitchViewFlowTablePath(
    size_t index, const std::string &viewFlowTablePath) {}

void P4Controller::SetP4SwitchFlowTablePath(size_t index,
                                            const std::string &flowTablePath) {
  NS_LOG_FUNCTION(this << index << flowTablePath);
}

} // namespace ns3