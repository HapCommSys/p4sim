/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#ifndef SWITCH_API_H
#define SWITCH_API_H

#include <string>
#include <unordered_map>

namespace ns3
{

/**
 * The `switch_api` is an enumeration class that defines various API operations for the switch at
 * runtime. It is used to identify the type of API, including flow table operations, action
 * configuration, indirect table operations, flow table entry retrieval, counter operations, meter
 * operations, register operations, parsing value set operations, and runtime state management.
 */
class SwitchApi
{
  public:
    // Enums for categorizing APIs
    enum ApiCategory
    {
        FLOW_TABLE_OPERATIONS = 0,  // APIs for managing flow tables
        ACTION_PROFILE_OPERATIONS,  // APIs for managing action profiles
        INDIRECT_TABLE_OPERATIONS,  // APIs for indirect tables
        FLOW_TABLE_ENTRY_RETRIEVAL, // APIs for querying flow table entries
        COUNTER_OPERATIONS,         // APIs for managing counters
        METER_OPERATIONS,           // APIs for configuring/querying meters
        REGISTER_OPERATIONS,        // APIs for managing registers
        PARSE_VALUE_SET_OPERATIONS, // APIs for parse value sets
        RUNTIME_STATE_MANAGEMENT    // APIs for managing runtime state
    };

    // Enums for specific APIs
    enum ApiType
    {
        // Flow Table Operations
        MT_GET_NUM_ENTRIES = FLOW_TABLE_OPERATIONS * 100,
        MT_CLEAR_ENTRIES,
        MT_ADD_ENTRY,
        MT_SET_DEFAULT_ACTION,
        MT_RESET_DEFAULT_ENTRY,
        MT_DELETE_ENTRY,
        MT_MODIFY_ENTRY,
        MT_SET_ENTRY_TTL,

        // Action Profile Operations
        MT_ACT_PROF_ADD_MEMBER = ACTION_PROFILE_OPERATIONS * 100,
        MT_ACT_PROF_DELETE_MEMBER,
        MT_ACT_PROF_MODIFY_MEMBER,
        MT_ACT_PROF_CREATE_GROUP,
        MT_ACT_PROF_DELETE_GROUP,
        MT_ACT_PROF_ADD_MEMBER_TO_GROUP,
        MT_ACT_PROF_REMOVE_MEMBER_FROM_GROUP,
        MT_ACT_PROF_GET_MEMBERS,
        MT_ACT_PROF_GET_MEMBER,
        MT_ACT_PROF_GET_GROUPS,
        MT_ACT_PROF_GET_GROUP,

        // Indirect Table Operations
        MT_INDIRECT_ADD_ENTRY = INDIRECT_TABLE_OPERATIONS * 100,
        MT_INDIRECT_MODIFY_ENTRY,
        MT_INDIRECT_DELETE_ENTRY,
        MT_INDIRECT_SET_ENTRY_TTL,
        MT_INDIRECT_SET_DEFAULT_MEMBER,
        MT_INDIRECT_RESET_DEFAULT_ENTRY,
        MT_INDIRECT_WS_ADD_ENTRY,
        MT_INDIRECT_WS_MODIFY_ENTRY,
        MT_INDIRECT_WS_SET_DEFAULT_GROUP,

        // Flow Table Entry Retrieval
        MT_GET_ENTRIES = FLOW_TABLE_ENTRY_RETRIEVAL * 100,
        MT_INDIRECT_GET_ENTRIES,
        MT_INDIRECT_WS_GET_ENTRIES,
        MT_GET_ENTRY,
        MT_INDIRECT_GET_ENTRY,
        MT_INDIRECT_WS_GET_ENTRY,
        MT_GET_DEFAULT_ENTRY,
        MT_INDIRECT_GET_DEFAULT_ENTRY,
        MT_INDIRECT_WS_GET_DEFAULT_ENTRY,
        MT_GET_ENTRY_FROM_KEY,
        MT_INDIRECT_GET_ENTRY_FROM_KEY,
        MT_INDIRECT_WS_GET_ENTRY_FROM_KEY,

        // Counter Operations
        MT_READ_COUNTERS = COUNTER_OPERATIONS * 100,
        MT_RESET_COUNTERS,
        MT_WRITE_COUNTERS,
        READ_COUNTERS,
        RESET_COUNTERS,
        WRITE_COUNTERS,

        // Meter Operations
        MT_SET_METER_RATES = METER_OPERATIONS * 100,
        MT_GET_METER_RATES,
        MT_RESET_METER_RATES,
        METER_ARRAY_SET_RATES,
        METER_SET_RATES,
        METER_GET_RATES,
        METER_RESET_RATES,

        // Register Operations
        REGISTER_READ = REGISTER_OPERATIONS * 100,
        REGISTER_READ_ALL,
        REGISTER_WRITE,
        REGISTER_WRITE_RANGE,
        REGISTER_RESET,

        // Parse Value Set Operations
        PARSE_VSET_ADD = PARSE_VALUE_SET_OPERATIONS * 100,
        PARSE_VSET_REMOVE,
        PARSE_VSET_GET,
        PARSE_VSET_CLEAR,

        // Runtime State Management
        RESET_STATE = RUNTIME_STATE_MANAGEMENT * 100,
        SERIALIZE,
        LOAD_NEW_CONFIG,
        SWAP_CONFIGS,
        GET_CONFIG,
        GET_CONFIG_MD5
    };

    // Static map to bind API names to their types
    static std::unordered_map<std::string, unsigned int> g_apiMap;

    // Function to initialize the API map
    static void InitApiMap();
};

} // namespace ns3

#endif
