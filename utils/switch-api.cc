/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#include "ns3/switch-api.h"

namespace ns3
{

// Define the static member
std::unordered_map<std::string, unsigned int> SwitchApi::g_apiMap;

// Initialize the API map
void
SwitchApi::InitApiMap()
{
    // Flow Table Operations
    g_apiMap["mt_get_num_entries"] = MT_GET_NUM_ENTRIES;
    g_apiMap["mt_clear_entries"] = MT_CLEAR_ENTRIES;
    g_apiMap["mt_add_entry"] = MT_ADD_ENTRY;
    g_apiMap["mt_set_default_action"] = MT_SET_DEFAULT_ACTION;
    g_apiMap["mt_reset_default_entry"] = MT_RESET_DEFAULT_ENTRY;
    g_apiMap["mt_delete_entry"] = MT_DELETE_ENTRY;
    g_apiMap["mt_modify_entry"] = MT_MODIFY_ENTRY;
    g_apiMap["mt_set_entry_ttl"] = MT_SET_ENTRY_TTL;

    // Action Profile Operations
    g_apiMap["mt_act_prof_add_member"] = MT_ACT_PROF_ADD_MEMBER;
    g_apiMap["mt_act_prof_delete_member"] = MT_ACT_PROF_DELETE_MEMBER;
    g_apiMap["mt_act_prof_modify_member"] = MT_ACT_PROF_MODIFY_MEMBER;
    g_apiMap["mt_act_prof_create_group"] = MT_ACT_PROF_CREATE_GROUP;
    g_apiMap["mt_act_prof_delete_group"] = MT_ACT_PROF_DELETE_GROUP;
    g_apiMap["mt_act_prof_add_member_to_group"] = MT_ACT_PROF_ADD_MEMBER_TO_GROUP;
    g_apiMap["mt_act_prof_remove_member_from_group"] = MT_ACT_PROF_REMOVE_MEMBER_FROM_GROUP;
    g_apiMap["mt_act_prof_get_members"] = MT_ACT_PROF_GET_MEMBERS;
    g_apiMap["mt_act_prof_get_member"] = MT_ACT_PROF_GET_MEMBER;
    g_apiMap["mt_act_prof_get_groups"] = MT_ACT_PROF_GET_GROUPS;
    g_apiMap["mt_act_prof_get_group"] = MT_ACT_PROF_GET_GROUP;

    // Indirect Table Operations
    g_apiMap["mt_indirect_add_entry"] = MT_INDIRECT_ADD_ENTRY;
    g_apiMap["mt_indirect_modify_entry"] = MT_INDIRECT_MODIFY_ENTRY;
    g_apiMap["mt_indirect_delete_entry"] = MT_INDIRECT_DELETE_ENTRY;
    g_apiMap["mt_indirect_set_entry_ttl"] = MT_INDIRECT_SET_ENTRY_TTL;
    g_apiMap["mt_indirect_set_default_member"] = MT_INDIRECT_SET_DEFAULT_MEMBER;
    g_apiMap["mt_indirect_reset_default_entry"] = MT_INDIRECT_RESET_DEFAULT_ENTRY;
    g_apiMap["mt_indirect_ws_add_entry"] = MT_INDIRECT_WS_ADD_ENTRY;
    g_apiMap["mt_indirect_ws_modify_entry"] = MT_INDIRECT_WS_MODIFY_ENTRY;
    g_apiMap["mt_indirect_ws_set_default_group"] = MT_INDIRECT_WS_SET_DEFAULT_GROUP;

    // Flow Table Entry Retrieval
    g_apiMap["mt_get_entries"] = MT_GET_ENTRIES;
    g_apiMap["mt_indirect_get_entries"] = MT_INDIRECT_GET_ENTRIES;
    g_apiMap["mt_indirect_ws_get_entries"] = MT_INDIRECT_WS_GET_ENTRIES;
    g_apiMap["mt_get_entry"] = MT_GET_ENTRY;
    g_apiMap["mt_indirect_get_entry"] = MT_INDIRECT_GET_ENTRY;
    g_apiMap["mt_indirect_ws_get_entry"] = MT_INDIRECT_WS_GET_ENTRY;
    g_apiMap["mt_get_default_entry"] = MT_GET_DEFAULT_ENTRY;
    g_apiMap["mt_indirect_get_default_entry"] = MT_INDIRECT_GET_DEFAULT_ENTRY;
    g_apiMap["mt_indirect_ws_get_default_entry"] = MT_INDIRECT_WS_GET_DEFAULT_ENTRY;
    g_apiMap["mt_get_entry_from_key"] = MT_GET_ENTRY_FROM_KEY;
    g_apiMap["mt_indirect_get_entry_from_key"] = MT_INDIRECT_GET_ENTRY_FROM_KEY;
    g_apiMap["mt_indirect_ws_get_entry_from_key"] = MT_INDIRECT_WS_GET_ENTRY_FROM_KEY;

    // Counter Operations
    g_apiMap["mt_read_counters"] = MT_READ_COUNTERS;
    g_apiMap["mt_reset_counters"] = MT_RESET_COUNTERS;
    g_apiMap["mt_write_counters"] = MT_WRITE_COUNTERS;
    g_apiMap["read_counters"] = READ_COUNTERS;
    g_apiMap["reset_counters"] = RESET_COUNTERS;
    g_apiMap["write_counters"] = WRITE_COUNTERS;

    // Meter Operations
    g_apiMap["mt_set_meter_rates"] = MT_SET_METER_RATES;
    g_apiMap["mt_get_meter_rates"] = MT_GET_METER_RATES;
    g_apiMap["mt_reset_meter_rates"] = MT_RESET_METER_RATES;
    g_apiMap["meter_array_set_rates"] = METER_ARRAY_SET_RATES;
    g_apiMap["meter_set_rates"] = METER_SET_RATES;
    g_apiMap["meter_get_rates"] = METER_GET_RATES;
    g_apiMap["meter_reset_rates"] = METER_RESET_RATES;

    // Register Operations
    g_apiMap["register_read"] = REGISTER_READ;
    g_apiMap["register_read_all"] = REGISTER_READ_ALL;
    g_apiMap["register_write"] = REGISTER_WRITE;
    g_apiMap["register_write_range"] = REGISTER_WRITE_RANGE;
    g_apiMap["register_reset"] = REGISTER_RESET;

    // Parse Value Set Operations
    g_apiMap["parse_vset_add"] = PARSE_VSET_ADD;
    g_apiMap["parse_vset_remove"] = PARSE_VSET_REMOVE;
    g_apiMap["parse_vset_get"] = PARSE_VSET_GET;
    g_apiMap["parse_vset_clear"] = PARSE_VSET_CLEAR;

    // Runtime State Management
    g_apiMap["reset_state"] = RESET_STATE;
    g_apiMap["serialize"] = SERIALIZE;
    g_apiMap["load_new_config"] = LOAD_NEW_CONFIG;
    g_apiMap["swap_configs"] = SWAP_CONFIGS;
    g_apiMap["get_config"] = GET_CONFIG;
    g_apiMap["get_config_md5"] = GET_CONFIG_MD5;
}

} // namespace ns3
