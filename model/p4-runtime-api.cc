/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#include "ns3/p4-runtime-api.h"

#include "ns3/log.h"

#include <iostream>

NS_LOG_COMPONENT_DEFINE("P4RuntimeApi");

namespace ns3
{

static const char*
MatchErrorCodeToStr(bm::MatchErrorCode rcc)
{
    switch (rcc)
    {
    case bm::MatchErrorCode::SUCCESS:
        return "SUCCESS";
    case bm::MatchErrorCode::TABLE_FULL:
        return "TABLE_FULL";
    case bm::MatchErrorCode::INVALID_HANDLE:
        return "INVALID_HANDLE";
    case bm::MatchErrorCode::EXPIRED_HANDLE:
        return "EXPIRED_HANDLE";
    case bm::MatchErrorCode::COUNTERS_DISABLED:
        return "COUNTERS_DISABLED";
    case bm::MatchErrorCode::METERS_DISABLED:
        return "METERS_DISABLED";
    case bm::MatchErrorCode::AGEING_DISABLED:
        return "AGEING_DISABLED";
    case bm::MatchErrorCode::INVALID_TABLE_NAME:
        return "INVALID_TABLE_NAME";
    case bm::MatchErrorCode::INVALID_ACTION_NAME:
        return "INVALID_ACTION_NAME";
    case bm::MatchErrorCode::WRONG_TABLE_TYPE:
        return "WRONG_TABLE_TYPE";
    case bm::MatchErrorCode::INVALID_MBR_HANDLE:
        return "INVALID_MBR_HANDLE";
    case bm::MatchErrorCode::MBR_STILL_USED:
        return "MBR_STILL_USED";
    case bm::MatchErrorCode::MBR_ALREADY_IN_GRP:
        return "MBR_ALREADY_IN_GRP";
    case bm::MatchErrorCode::MBR_NOT_IN_GRP:
        return "MBR_NOT_IN_GRP";
    case bm::MatchErrorCode::INVALID_GRP_HANDLE:
        return "INVALID_GRP_HANDLE";
    case bm::MatchErrorCode::GRP_STILL_USED:
        return "GRP_STILL_USED";
    case bm::MatchErrorCode::EMPTY_GRP:
        return "EMPTY_GRP";
    case bm::MatchErrorCode::DUPLICATE_ENTRY:
        return "DUPLICATE_ENTRY";
    case bm::MatchErrorCode::BAD_MATCH_KEY:
        return "BAD_MATCH_KEY";
    case bm::MatchErrorCode::INVALID_METER_OPERATION:
        return "INVALID_METER_OPERATION";
    case bm::MatchErrorCode::DEFAULT_ACTION_IS_CONST:
        return "DEFAULT_ACTION_IS_CONST";
    case bm::MatchErrorCode::DEFAULT_ENTRY_IS_CONST:
        return "DEFAULT_ENTRY_IS_CONST";
    case bm::MatchErrorCode::NO_DEFAULT_ENTRY:
        return "NO_DEFAULT_ENTRY";
    case bm::MatchErrorCode::INVALID_ACTION_PROFILE_NAME:
        return "INVALID_ACTION_PROFILE_NAME";
    case bm::MatchErrorCode::NO_ACTION_PROFILE_SELECTION:
        return "NO_ACTION_PROFILE_SELECTION";
    case bm::MatchErrorCode::IMMUTABLE_TABLE_ENTRIES:
        return "IMMUTABLE_TABLE_ENTRIES";
    case bm::MatchErrorCode::BAD_ACTION_DATA:
        return "BAD_ACTION_DATA";
    case bm::MatchErrorCode::NO_TABLE_KEY:
        return "NO_TABLE_KEY";
    case bm::MatchErrorCode::ERROR:
        return "GENERIC_ERROR";
    default:
        return "UNKNOWN_ERROR_CODE";
    }
}

static const char*
CounterErrorCodeToStr(bm::Counter::CounterErrorCode code)
{
    switch (code)
    {
    case bm::Counter::CounterErrorCode::SUCCESS:
        return "SUCCESS";
    case bm::Counter::CounterErrorCode::INVALID_COUNTER_NAME:
        return "INVALID_COUNTER_NAME";
    case bm::Counter::CounterErrorCode::INVALID_INDEX:
        return "INVALID_INDEX";
    case bm::Counter::CounterErrorCode::ERROR:
        return "GENERIC_ERROR";
    default:
        return "UNKNOWN_ERROR_CODE";
    }
}

static const char*
MeterErrorCodeToStr(bm::Meter::MeterErrorCode code)
{
    switch (code)
    {
    case bm::Meter::MeterErrorCode::SUCCESS:
        return "SUCCESS";
    case bm::Meter::MeterErrorCode::INVALID_METER_NAME:
        return "INVALID_METER_NAME";
    case bm::Meter::MeterErrorCode::INVALID_INDEX:
        return "INVALID_INDEX";
    case bm::Meter::MeterErrorCode::BAD_RATES_LIST:
        return "BAD_RATES_LIST";
    case bm::Meter::MeterErrorCode::INVALID_INFO_RATE_VALUE:
        return "INVALID_INFO_RATE_VALUE";
    case bm::Meter::MeterErrorCode::INVALID_BURST_SIZE_VALUE:
        return "INVALID_BURST_SIZE_VALUE";
    case bm::Meter::MeterErrorCode::ERROR:
        return "GENERIC_ERROR";
    default:
        return "UNKNOWN_ERROR_CODE";
    }
}

static const char*
RegisterErrorCodeToStr(bm::Register::RegisterErrorCode rc)
{
    switch (rc)
    {
    case bm::Register::RegisterErrorCode::SUCCESS:
        return "SUCCESS";
    case bm::Register::RegisterErrorCode::INVALID_REGISTER_NAME:
        return "INVALID_REGISTER_NAME";
    case bm::Register::RegisterErrorCode::INVALID_INDEX:
        return "INVALID_INDEX";
    case bm::Register::RegisterErrorCode::ERROR:
        return "ERROR";
    default:
        return "UNKNOWN_REGISTER_ERROR_CODE";
    }
}

static const char*
RuntimeErrorCodeToStr(bm::RuntimeInterface::ErrorCode rc)
{
    switch (rc)
    {
    case bm::RuntimeInterface::SUCCESS:
        return "SUCCESS";
    case bm::RuntimeInterface::CONFIG_SWAP_DISABLED:
        return "CONFIG_SWAP_DISABLED";
    case bm::RuntimeInterface::ONGOING_SWAP:
        return "ONGOING_SWAP";
    case bm::RuntimeInterface::NO_ONGOING_SWAP:
        return "NO_ONGOING_SWAP";
    default:
        return "UNKNOWN_RUNTIME_ERROR_CODE";
    }
}

P4RuntimeApi::P4RuntimeApi(bm::RuntimeInterface& sw)
    : m_sw(sw)
{
}

int
P4RuntimeApi::GetNumEntries(const std::string& tableName)
{
    size_t num = 0;
    bm::MatchErrorCode rc = m_sw.mt_get_num_entries(0, tableName, &num); // cxt_id = 0
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetNumEntries failed for table " << tableName);
        return -1;
    }
    return static_cast<int>(num);
}

int
P4RuntimeApi::ClearFlowTableEntries(const std::string& tableName, bool resetDefault)
{
    bm::MatchErrorCode rc = m_sw.mt_clear_entries(0, tableName, resetDefault); // cxt_id = 0
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ClearFlowTableEntries failed for table " << tableName);
        return -1;
    }
    return 0; // success
}

int
P4RuntimeApi::AddFlowEntry(const std::string& tableName,
                           const std::vector<bm::MatchKeyParam>& matchKey,
                           const std::string& actionName,
                           bm::ActionData&& actionData,
                           bm::entry_handle_t* handle,
                           int priority)
{
    bm::MatchErrorCode rc = m_sw.mt_add_entry(0, // context ID
                                              tableName,
                                              matchKey,
                                              actionName,
                                              std::move(actionData),
                                              handle,
                                              priority);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        std::cout << "AddFlowEntry failed for table " << tableName << " with error code "
                  << MatchErrorCodeToStr(rc);
        return -1;
    }

    return 0; // success
}

int
P4RuntimeApi::SetDefaultAction(const std::string& tableName,
                               const std::string& actionName,
                               bm::ActionData&& actionData)
{
    bm::MatchErrorCode rc =
        m_sw.mt_set_default_action(0, tableName, actionName, std::move(actionData));

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetDefaultAction failed for table " << tableName << " action " << actionName);
        NS_LOG_WARN("mt_set_default_action() failed with code: " << static_cast<int>(rc) << " ("
                                                                 << MatchErrorCodeToStr(rc) << ")");

        return -1;
    }

    return 0;
}

int
P4RuntimeApi::ResetDefaultEntry(const std::string& tableName)
{
    bm::MatchErrorCode rc = m_sw.mt_reset_default_entry(0, tableName);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ResetDefaultEntry failed for table " << tableName << " with code "
                                                          << static_cast<int>(rc) << " ("
                                                          << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0; // success
}

int
P4RuntimeApi::DeleteFlowEntry(const std::string& tableName, bm::entry_handle_t handle)
{
    bm::MatchErrorCode rc = m_sw.mt_delete_entry(0, tableName, handle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        std::cout << "DeleteFlowEntry failed for table " << tableName << " and handle " << handle
                  << " with code " << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc)
                  << ")";
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::ModifyFlowEntry(const std::string& tableName,
                              bm::entry_handle_t handle,
                              const std::string& actionName,
                              bm::ActionData actionData)
{
    bm::MatchErrorCode rc =
        m_sw.mt_modify_entry(0, tableName, handle, actionName, std::move(actionData));

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ModifyFlowEntry failed for table " << tableName << ", handle " << handle
                                                        << " with code " << static_cast<int>(rc)
                                                        << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::SetEntryTtl(const std::string& tableName,
                          bm::entry_handle_t handle,
                          unsigned int ttlMs)
{
    bm::MatchErrorCode rc = m_sw.mt_set_entry_ttl(0, tableName, handle, ttlMs);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        std::cout << "SetEntryTtl failed for table " << tableName << ", handle " << handle
                  << " with code " << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc)
                  << ")";
        return -1;
    }

    return 0;
}

// ======== Action Profile Operations ===========

int
P4RuntimeApi::AddActionProfileMember(const std::string& profileName,
                                     const std::string& actionName,
                                     bm::ActionData&& actionData,
                                     bm::ActionProfile::mbr_hdl_t* outHandle)
{
    bm::MatchErrorCode rc =
        m_sw.mt_act_prof_add_member(0, profileName, actionName, std::move(actionData), outHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("AddActionProfileMember failed for profile " << profileName << ", action "
                                                                 << actionName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::DeleteActionProfileMember(const std::string& profileName,
                                        bm::ActionProfile::mbr_hdl_t memberHandle)
{
    bm::MatchErrorCode rc = m_sw.mt_act_prof_delete_member(0, profileName, memberHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("DeleteActionProfileMember failed for profile "
                    << profileName << ", member handle " << memberHandle);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::ModifyActionProfileMember(const std::string& profileName,
                                        bm::ActionProfile::mbr_hdl_t memberHandle,
                                        const std::string& actionName,
                                        bm::ActionData&& actionData)
{
    bm::MatchErrorCode rc = m_sw.mt_act_prof_modify_member(0,
                                                           profileName,
                                                           memberHandle,
                                                           actionName,
                                                           std::move(actionData));

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ModifyActionProfileMember failed for profile "
                    << profileName << ", member handle " << memberHandle << ", action "
                    << actionName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::CreateActionProfileGroup(const std::string& profileName,
                                       bm::ActionProfile::grp_hdl_t* outHandle)
{
    bm::MatchErrorCode rc = m_sw.mt_act_prof_create_group(0, profileName, outHandle);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("CreateActionProfileGroup failed for profile " << profileName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::DeleteActionProfileGroup(const std::string& profileName,
                                       bm::ActionProfile::grp_hdl_t groupHandle)
{
    bm::MatchErrorCode rc = m_sw.mt_act_prof_delete_group(0, profileName, groupHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("DeleteActionProfileGroup failed for profile " << profileName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::AddMemberToGroup(const std::string& profileName,
                               bm::ActionProfile::mbr_hdl_t memberHandle,
                               bm::ActionProfile::grp_hdl_t groupHandle)
{
    bm::MatchErrorCode rc =
        m_sw.mt_act_prof_add_member_to_group(0, profileName, memberHandle, groupHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("AddMemberToGroup failed for profile " << profileName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::RemoveMemberFromGroup(const std::string& profileName,
                                    bm::ActionProfile::mbr_hdl_t memberHandle,
                                    bm::ActionProfile::grp_hdl_t groupHandle)
{
    bm::MatchErrorCode rc =
        m_sw.mt_act_prof_remove_member_from_group(0, profileName, memberHandle, groupHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("RemoveMemberFromGroup failed for profile " << profileName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::GetActionProfileMembers(const std::string& profileName,
                                      std::vector<bm::ActionProfile::Member>* members)
{
    *members = m_sw.mt_act_prof_get_members(0, profileName);
    return 0;
}

int
P4RuntimeApi::GetActionProfileMember(const std::string& profileName,
                                     bm::ActionProfile::mbr_hdl_t memberHandle,
                                     bm::ActionProfile::Member* member)
{
    bm::MatchErrorCode rc = m_sw.mt_act_prof_get_member(0, profileName, memberHandle, member);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetActionProfileMember failed for profile " << profileName);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::GetActionProfileGroups(const std::string& profileName,
                                     std::vector<bm::ActionProfile::Group>* groups)
{
    *groups = m_sw.mt_act_prof_get_groups(0, profileName);
    return 0;
}

int
P4RuntimeApi::GetActionProfileGroup(const std::string& profileName,
                                    bm::ActionProfile::grp_hdl_t groupHandle,
                                    bm::ActionProfile::Group* group)
{
    bm::MatchErrorCode rc = m_sw.mt_act_prof_get_group(0, profileName, groupHandle, group);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetActionProfileGroup failed for profile "
                    << profileName << " and group handle " << groupHandle);
        NS_LOG_WARN("Error: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

// =========== Indirect Table Operations ============
int
P4RuntimeApi::AddIndirectEntry(const std::string& tableName,
                               const std::vector<bm::MatchKeyParam>& matchKey,
                               bm::ActionProfile::mbr_hdl_t memberHandle,
                               bm::entry_handle_t* outHandle,
                               int priority)
{
    bm::MatchErrorCode rc =
        m_sw.mt_indirect_add_entry(0, tableName, matchKey, memberHandle, outHandle, priority);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("AddIndirectEntry failed for table " << tableName);
        NS_LOG_WARN("mt_indirect_add_entry() failed with code: " << static_cast<int>(rc) << " ("
                                                                 << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::ModifyIndirectEntry(const std::string& tableName,
                                  bm::entry_handle_t entryHandle,
                                  bm::ActionProfile::mbr_hdl_t memberHandle)
{
    bm::MatchErrorCode rc = m_sw.mt_indirect_modify_entry(0, tableName, entryHandle, memberHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ModifyIndirectEntry failed for table " << tableName << " and entry handle "
                                                            << entryHandle);
        NS_LOG_WARN("mt_indirect_modify_entry() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::DeleteIndirectEntry(const std::string& tableName, bm::entry_handle_t entryHandle)
{
    bm::MatchErrorCode rc = m_sw.mt_indirect_delete_entry(0, tableName, entryHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("DeleteIndirectEntry failed for table " << tableName << " and entry handle "
                                                            << entryHandle);
        NS_LOG_WARN("mt_indirect_delete_entry() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::SetIndirectEntryTtl(const std::string& tableName,
                                  bm::entry_handle_t handle,
                                  unsigned int ttlMs)
{
    bm::MatchErrorCode rc = m_sw.mt_indirect_set_entry_ttl(0, tableName, handle, ttlMs);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetIndirectEntryTtl failed for table " << tableName << ", handle " << handle);
        NS_LOG_WARN("mt_indirect_set_entry_ttl() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::SetIndirectDefaultMember(const std::string& tableName,
                                       bm::ActionProfile::mbr_hdl_t memberHandle)
{
    bm::MatchErrorCode rc = m_sw.mt_indirect_set_default_member(0, tableName, memberHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetIndirectDefaultMember failed for table " << tableName << ", member "
                                                                 << memberHandle);
        NS_LOG_WARN("mt_indirect_set_default_member() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::ResetIndirectDefaultEntry(const std::string& tableName)
{
    bm::MatchErrorCode rc = m_sw.mt_indirect_reset_default_entry(0, tableName);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ResetIndirectDefaultEntry failed for table " << tableName);
        NS_LOG_WARN("mt_indirect_reset_default_entry() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::AddIndirectWsEntry(const std::string& tableName,
                                 const std::vector<bm::MatchKeyParam>& matchKey,
                                 bm::ActionProfile::grp_hdl_t groupHandle,
                                 bm::entry_handle_t* outHandle,
                                 int priority)
{
    bm::MatchErrorCode rc =
        m_sw.mt_indirect_ws_add_entry(0, tableName, matchKey, groupHandle, outHandle, priority);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("AddIndirectWsEntry failed for table " << tableName
                                                           << ", group = " << groupHandle);
        NS_LOG_WARN("mt_indirect_ws_add_entry() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::ModifyIndirectWsEntry(const std::string& tableName,
                                    bm::entry_handle_t handle,
                                    bm::ActionProfile::grp_hdl_t groupHandle)
{
    bm::MatchErrorCode rc = m_sw.mt_indirect_ws_modify_entry(0, tableName, handle, groupHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ModifyIndirectWsEntry failed for table "
                    << tableName << ", handle = " << handle << ", group = " << groupHandle);
        NS_LOG_WARN("mt_indirect_ws_modify_entry() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::SetIndirectWsDefaultGroup(const std::string& tableName,
                                        bm::ActionProfile::grp_hdl_t groupHandle)
{
    bm::MatchErrorCode rc = m_sw.mt_indirect_ws_set_default_group(0, tableName, groupHandle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetIndirectWsDefaultGroup failed for table " << tableName
                                                                  << ", group = " << groupHandle);
        NS_LOG_WARN("mt_indirect_ws_set_default_group() failed with code: "
                    << static_cast<int>(rc) << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }

    return 0;
}

// ======== Flow Table Entry Retrieval Operations ===========
std::vector<bm::MatchTable::Entry>
P4RuntimeApi::GetFlowEntries(const std::string& tableName)
{
    try
    {
        return m_sw.mt_get_entries(0, tableName); // cxt_id = 0
    }
    catch (const std::exception& e)
    {
        NS_LOG_ERROR("Exception in GetFlowEntries: " << e.what());
        return {}; // empty vector
    }
}

std::vector<bm::MatchTableIndirect::Entry>
P4RuntimeApi::GetIndirectFlowEntries(const std::string& tableName)
{
    try
    {
        return m_sw.mt_indirect_get_entries(0, tableName); // cxt_id = 0
    }
    catch (const std::exception& e)
    {
        NS_LOG_ERROR("Error in GetIndirectFlowEntries: " << e.what());
        return {};
    }
}

std::vector<bm::MatchTableIndirectWS::Entry>
P4RuntimeApi::GetIndirectWsFlowEntries(const std::string& tableName)
{
    try
    {
        return m_sw.mt_indirect_ws_get_entries(0, tableName); // cxt_id = 0
    }
    catch (const std::exception& e)
    {
        NS_LOG_ERROR("Error in GetIndirectWsFlowEntries: " << e.what());
        return {};
    }
}

int
P4RuntimeApi::GetEntry(const std::string& tableName,
                       bm::entry_handle_t handle,
                       bm::MatchTable::Entry* entry)
{
    bm::MatchErrorCode rc = m_sw.mt_get_entry(0, tableName, handle, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetEntry failed for table: " << tableName << ", handle: " << handle
                                                  << ", code: " << static_cast<int>(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::GetIndirectEntry(const std::string& tableName,
                               bm::entry_handle_t handle,
                               bm::MatchTableIndirect::Entry* entry)
{
    bm::MatchErrorCode rc = m_sw.mt_indirect_get_entry(0, tableName, handle, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetIndirectEntry failed for table: " << tableName << ", handle: " << handle
                                                          << ", code: " << static_cast<int>(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::GetIndirectWsEntry(const std::string& tableName,
                                 bm::entry_handle_t handle,
                                 bm::MatchTableIndirectWS::Entry* entry)
{
    bm::MatchErrorCode rc = m_sw.mt_indirect_ws_get_entry(0, tableName, handle, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetIndirectWsEntry failed for table: " << tableName << ", handle: " << handle
                                                            << ", code: " << static_cast<int>(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::GetDefaultEntry(const std::string& tableName, bm::MatchTable::Entry* entry)
{
    bm::MatchErrorCode rc = m_sw.mt_get_default_entry(0, tableName, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetDefaultEntry failed for table: " << tableName
                                                         << ", code: " << static_cast<int>(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::GetIndirectDefaultEntry(const std::string& tableName,
                                      bm::MatchTableIndirect::Entry* entry)
{
    bm::MatchErrorCode rc = m_sw.mt_indirect_get_default_entry(0, tableName, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("Indirect default entry fn failed with code: "
                    << " (" << MatchErrorCodeToStr(rc) << ")");
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::GetIndirectWsDefaultEntry(const std::string& tableName,
                                        bm::MatchTableIndirectWS::Entry* entry)
{
    bm::MatchErrorCode rc = m_sw.mt_indirect_ws_get_default_entry(0, tableName, entry);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetIndirectWsDefaultEntry failed for table: " << tableName << ", code: "
                                                                   << static_cast<int>(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::GetEntryFromKey(const std::string& tableName,
                              const std::vector<bm::MatchKeyParam>& matchKey,
                              bm::MatchTable::Entry* entry,
                              int priority)
{
    bm::MatchErrorCode rc = m_sw.mt_get_entry_from_key(0, tableName, matchKey, entry, priority);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetEntryFromKey failed for table: " << tableName
                                                         << ", error: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::GetIndirectEntryFromKey(const std::string& tableName,
                                      const std::vector<bm::MatchKeyParam>& matchKey,
                                      bm::MatchTableIndirect::Entry* entry,
                                      int priority)
{
    bm::MatchErrorCode rc =
        m_sw.mt_indirect_get_entry_from_key(0, tableName, matchKey, entry, priority);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetIndirectEntryFromKey failed for table: " << tableName << ", error: "
                                                                 << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::GetIndirectWsEntryFromKey(const std::string& tableName,
                                        const std::vector<bm::MatchKeyParam>& matchKey,
                                        bm::MatchTableIndirectWS::Entry* entry,
                                        int priority)
{
    bm::MatchErrorCode rc =
        m_sw.mt_indirect_ws_get_entry_from_key(0, tableName, matchKey, entry, priority);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetIndirectWsEntryFromKey failed for table: " << tableName << ", error: "
                                                                   << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

// ========== Counter Operations ============
int
P4RuntimeApi::ReadTableCounters(const std::string& tableName,
                                bm::entry_handle_t handle,
                                uint64_t* bytes,
                                uint64_t* packets)
{
    bm::MatchErrorCode rc = m_sw.mt_read_counters(0, tableName, handle, bytes, packets);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ReadTableCounters failed for table "
                    << tableName << ", handle " << handle
                    << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::ResetTableCounters(const std::string& tableName)
{
    bm::MatchErrorCode rc = m_sw.mt_reset_counters(0, tableName);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ResetTableCounters failed for table "
                    << tableName << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::WriteTableCounters(const std::string& tableName,
                                 bm::entry_handle_t handle,
                                 uint64_t bytes,
                                 uint64_t packets)
{
    bm::MatchErrorCode rc = m_sw.mt_write_counters(0, tableName, handle, bytes, packets);
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("WriteTableCounters failed for table "
                    << tableName << ", handle " << handle
                    << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::ReadCounter(const std::string& counterName,
                          size_t index,
                          bm::MatchTableAbstract::counter_value_t* bytes,
                          bm::MatchTableAbstract::counter_value_t* packets)
{
    auto rc = m_sw.read_counters(0, counterName, index, bytes, packets); // cxt_id = 0
    if (rc == bm::Counter::CounterErrorCode::SUCCESS)
    {
        NS_LOG_INFO("ReadCounter succeeded for counter [" << counterName << "] at index " << index
                                                          << ": " << *bytes << " bytes, "
                                                          << *packets << " packets");
        return 0;
    }
    else
    {
        NS_LOG_WARN("ReadCounter failed for counter ["
                    << counterName << "] at index " << index
                    << ", reason: " << CounterErrorCodeToStr(rc));
        return -1;
    }
}

int
P4RuntimeApi::ResetCounter(const std::string& counterName)
{
    auto rc = m_sw.reset_counters(0, counterName); // cxt_id = 0
    if (rc == bm::Counter::CounterErrorCode::SUCCESS)
    {
        NS_LOG_INFO("ResetCounter succeeded for counter [" << counterName << "]");
        return 0;
    }
    else
    {
        NS_LOG_WARN("ResetCounter failed for counter ["
                    << counterName << "], reason: " << CounterErrorCodeToStr(rc));
        return -1;
    }
}

int
P4RuntimeApi::WriteCounter(const std::string& counterName,
                           size_t index,
                           bm::MatchTableAbstract::counter_value_t bytes,
                           bm::MatchTableAbstract::counter_value_t packets)
{
    auto rc = m_sw.write_counters(0, counterName, index, bytes, packets); // cxt_id = 0
    if (rc == bm::Counter::CounterErrorCode::SUCCESS)
    {
        NS_LOG_INFO("WriteCounter succeeded for counter [" << counterName << "] at index " << index
                                                           << ": " << bytes << " bytes, " << packets
                                                           << " packets");
        return 0;
    }
    else
    {
        NS_LOG_WARN("WriteCounter failed for counter ["
                    << counterName << "] at index " << index
                    << ", reason: " << CounterErrorCodeToStr(rc));
        return -1;
    }
}

// ============= Meter Operations ============

int
P4RuntimeApi::SetMeterRates(const std::string& tableName,
                            bm::entry_handle_t handle,
                            const std::vector<bm::Meter::rate_config_t>& configs)
{
    bm::MatchErrorCode rc = m_sw.mt_set_meter_rates(0, tableName, handle, configs);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetMeterRates failed for table " << tableName << ", handle " << handle
                                                      << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::GetMeterRates(const std::string& tableName,
                            bm::entry_handle_t handle,
                            std::vector<bm::Meter::rate_config_t>* configs)
{
    bm::MatchErrorCode rc = m_sw.mt_get_meter_rates(0, tableName, handle, configs);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetMeterRates failed for table " << tableName << ", handle " << handle
                                                      << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::ResetMeterRates(const std::string& tableName, bm::entry_handle_t handle)
{
    bm::MatchErrorCode rc = m_sw.mt_reset_meter_rates(0, tableName, handle);

    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ResetMeterRates failed for table " << tableName << ", handle " << handle
                                                        << ", reason: " << MatchErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::SetMeterArrayRates(const std::string& meterName,
                                 const std::vector<bm::Meter::rate_config_t>& configs)
{
    bm::Meter::MeterErrorCode rc = m_sw.meter_array_set_rates(0, meterName, configs);

    if (rc != bm::Meter::MeterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetMeterArrayRates failed for meter "
                    << meterName << ", reason: " << MeterErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::MeterSetRates(const std::string& meterName,
                            size_t idx,
                            const std::vector<bm::Meter::rate_config_t>& configs)
{
    bm::Meter::MeterErrorCode rc = m_sw.meter_set_rates(0, meterName, idx, configs);

    if (rc != bm::Meter::MeterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("SetMeterRates failed for meter " << meterName << ", index " << idx
                                                      << ", reason: " << MeterErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::MeterGetRates(const std::string& meterName,
                            size_t idx,
                            std::vector<bm::Meter::rate_config_t>* configs)
{
    bm::Meter::MeterErrorCode rc = m_sw.meter_get_rates(0, meterName, idx, configs);

    if (rc != bm::Meter::MeterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("GetMeterRates failed for meter " << meterName << ", index " << idx
                                                      << ", reason: " << MeterErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

int
P4RuntimeApi::MeterResetRates(const std::string& meterName, size_t idx)
{
    bm::Meter::MeterErrorCode rc = m_sw.meter_reset_rates(0, meterName, idx);

    if (rc != bm::Meter::MeterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("ResetMeterRates failed for meter " << meterName << ", index " << idx
                                                        << ", reason: " << MeterErrorCodeToStr(rc));
        return -1;
    }

    return 0;
}

// ============ Register Operations =============
int
P4RuntimeApi::RegisterRead(const std::string& registerName, size_t index, bm::Data* value)
{
    bm::Register::RegisterErrorCode rc = m_sw.register_read(0, registerName, index, value);
    if (rc != bm::Register::RegisterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("RegisterRead failed for register "
                    << registerName << " at index " << index
                    << " with error: " << RegisterErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::RegisterWrite(const std::string& registerName, size_t index, const bm::Data& value)
{
    bm::Register::RegisterErrorCode rc = m_sw.register_write(0, registerName, index, value);
    if (rc != bm::Register::RegisterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("RegisterWrite failed for register "
                    << registerName << " at index " << index
                    << " with error: " << RegisterErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

std::vector<bm::Data>
P4RuntimeApi::RegisterReadAll(const std::string& registerName)
{
    return m_sw.register_read_all(0, registerName);
}

int
P4RuntimeApi::RegisterWriteRange(const std::string& registerName,
                                 size_t startIndex,
                                 size_t endIndex,
                                 const bm::Data& value)
{
    bm::Register::RegisterErrorCode rc =
        m_sw.register_write_range(0, registerName, startIndex, endIndex, value);
    if (rc != bm::Register::RegisterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("RegisterWriteRange failed for register "
                    << registerName << " from index " << startIndex << " to " << endIndex
                    << " with error: " << RegisterErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::RegisterReset(const std::string& registerName)
{
    bm::Register::RegisterErrorCode rc = m_sw.register_reset(0, registerName);
    if (rc != bm::Register::RegisterErrorCode::SUCCESS)
    {
        NS_LOG_WARN("RegisterReset failed for register "
                    << registerName << " with error: " << RegisterErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::ParseVsetAdd(const std::string& vsetName, const bm::ByteContainer& value)
{
    bm::ParseVSet::ErrorCode rc = m_sw.parse_vset_add(0, vsetName, value);
    if (rc != bm::ParseVSet::SUCCESS)
    {
        NS_LOG_WARN("ParseVsetAdd failed for set '" << vsetName << "' with error code " << rc);
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::ParseVsetRemove(const std::string& vsetName, const bm::ByteContainer& value)
{
    bm::ParseVSet::ErrorCode rc = m_sw.parse_vset_remove(0, vsetName, value);
    if (rc != bm::ParseVSet::SUCCESS)
    {
        NS_LOG_WARN("ParseVsetRemove failed for set '" << vsetName << "' with error code " << rc);
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::ParseVsetGet(const std::string& vsetName, std::vector<bm::ByteContainer>* values)
{
    bm::ParseVSet::ErrorCode rc = m_sw.parse_vset_get(0, vsetName, values);
    if (rc != bm::ParseVSet::SUCCESS)
    {
        NS_LOG_WARN("ParseVsetGet failed for set '" << vsetName << "' with error code " << rc);
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::ParseVsetClear(const std::string& vsetName)
{
    bm::ParseVSet::ErrorCode rc = m_sw.parse_vset_clear(0, vsetName);
    if (rc != bm::ParseVSet::SUCCESS)
    {
        NS_LOG_WARN("ParseVsetClear failed for set '" << vsetName << "' with error code " << rc);
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::ResetState()
{
    bm::RuntimeInterface::ErrorCode rc = m_sw.reset_state();
    if (rc != bm::RuntimeInterface::SUCCESS)
    {
        NS_LOG_WARN("ResetState failed with error: " << RuntimeErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::Serialize(std::ostream* out)
{
    bm::RuntimeInterface::ErrorCode rc = m_sw.serialize(out);
    if (rc != bm::RuntimeInterface::SUCCESS)
    {
        NS_LOG_WARN("Serialize failed with error: " << RuntimeErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::LoadNewConfig(const std::string& newConfig)
{
    bm::RuntimeInterface::ErrorCode rc = m_sw.load_new_config(newConfig);
    if (rc != bm::RuntimeInterface::SUCCESS)
    {
        NS_LOG_WARN("LoadNewConfig failed with error: " << RuntimeErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::SwapConfigs()
{
    bm::RuntimeInterface::ErrorCode rc = m_sw.swap_configs();
    if (rc != bm::RuntimeInterface::SUCCESS)
    {
        NS_LOG_WARN("SwapConfigs failed with error: " << RuntimeErrorCodeToStr(rc));
        return -1;
    }
    return 0;
}

int
P4RuntimeApi::GetConfig(std::string* configOut)
{
    if (!configOut)
        return -1;
    *configOut = m_sw.get_config();
    return 0;
}

int
P4RuntimeApi::GetConfigMd5(std::string* md5Out)
{
    if (!md5Out)
        return -1;
    *md5Out = m_sw.get_config_md5();
    return 0;
}

} // namespace ns3
