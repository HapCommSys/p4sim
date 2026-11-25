/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#ifndef P4_RUNTIME_API_H
#define P4_RUNTIME_API_H

#include <bm/bm_sim/switch.h> // bm::RuntimeInterface, with all the types it uses
#include <ostream>
#include <string>
#include <vector>

#undef LOG_INFO
#undef LOG_ERROR
#undef LOG_DEBUG
#undef LOG_WARN
#undef LOG_LOGIC

namespace ns3
{

/**
 * @ingroup p4sim
 * @brief The BMv2 runtime calls on one switch: match tables, action profiles,
 * counters, meters, registers, parse value sets and program swaps.
 *
 * It works on the core of any architecture (v1model, PSA, PNA, pipeline),
 * through BMv2's bm::RuntimeInterface, on context 0. A call that returns an int
 * returns -1 on failure (GetNumEntries() the number of entries, the others 0 on
 * success) and logs the BMv2 error code; a null output argument is a failure
 * too. P4Controller uses it; a simulation
 * can also use it directly:
 *
 * @code
 * P4RuntimeApi api(*p4Device->GetCore());
 * int entries = api.GetNumEntries("MyIngress.ipv4_lpm");
 * @endcode
 *
 * It holds only a reference: create it where it is used, and do not keep it
 * longer than the switch.
 */
class P4RuntimeApi
{
  public:
    /**
     * @brief Constructor.
     * @param sw The switch, normally P4SwitchNetDevice::GetCore().
     */
    explicit P4RuntimeApi(bm::RuntimeInterface& sw);

    //========== Flow Table Operations =========
    /**
     * @brief Retrieves the number of entries in a match table
     * @param tableName Name of the match table
     */
    int GetNumEntries(const std::string& tableName);
    /**
     * @brief Clears all entries in a match table
     * @param tableName Name of the match table
     * @param resetDefault Whether to also reset the default entry
     */
    int ClearFlowTableEntries(const std::string& tableName, bool resetDefault);
    /**
     * @brief Adds an entry to a match table with a match key, action, and
     * optional priority
     * @param tableName Name of the match table
     * @param matchKey Match key for the entry
     * @param actionName Name of the action to invoke
     * @param actionData Parameters for the action
     * @param handleOut Pointer to store the resulting entry handle
     * @param priority Optional priority value (used for ternary/LPM tables)
     */
    int AddFlowEntry(const std::string& tableName,
                     const std::vector<bm::MatchKeyParam>& matchKey,
                     const std::string& actionName,
                     bm::ActionData&& actionData,
                     bm::entry_handle_t* handle,
                     int priority = -1);
    /**
     * @brief Sets the default action for a match table
     * @param tableName Name of the match table
     * @param actionName Name of the default action to apply
     * @param actionData Parameters for the default action
     */
    int SetDefaultAction(const std::string& tableName,
                         const std::string& actionName,
                         bm::ActionData&& actionData);
    /**
     * @brief Resets the default entry for a match table to its original
     * configuration
     * @param tableName Name of the match table
     */
    int ResetDefaultEntry(const std::string& tableName);
    /**
     * @brief Deletes a specific entry from a match table
     * @param tableName Name of the match table
     * @param handle Entry handle identifying the rule to delete
     */
    int DeleteFlowEntry(const std::string& tableName, bm::entry_handle_t handle);
    /**
     * @brief Modifies an existing match table entry with a new action and
     * parameters
     * @param tableName Name of the match table
     * @param handle Entry handle identifying the rule to modify
     * @param actionName Name of the new action to assign
     * @param actionData Parameters for the new action
     */
    int ModifyFlowEntry(const std::string& tableName,
                        bm::entry_handle_t handle,
                        const std::string& actionName,
                        bm::ActionData actionData);
    /**
     * @brief Sets a time-to-live (TTL) in milliseconds for a specific match table
     * entry
     * @param tableName Name of the match table
     * @param handle Entry handle identifying the rule
     * @param ttlMs Timeout duration in milliseconds
     */
    int SetEntryTtl(const std::string& tableName, bm::entry_handle_t handle, unsigned int ttlMs);

    //  ======== Action Profile Operations ===========

    /**
     * @brief Adds a member to an action profile.
     * @param profileName The name of the action profile.
     * @param actionName The name of the action.
     * @param actionData The action parameters.
     * @param[out] outHandle Pointer to store the resulting member handle.
     * @return 0 on success, -1 on failure.
     */
    int AddActionProfileMember(const std::string& profileName,
                               const std::string& actionName,
                               bm::ActionData&& actionData,
                               bm::ActionProfile::mbr_hdl_t* outHandle);

    /**
     * @brief Deletes a member from an action profile.
     * @param profileName The name of the action profile.
     * @param memberHandle The handle of the member to delete.
     * @return 0 on success, -1 on failure.
     */
    int DeleteActionProfileMember(const std::string& profileName,
                                  bm::ActionProfile::mbr_hdl_t memberHandle);

    /**
     * @brief Modifies an existing member in an action profile.
     * @param profileName The name of the action profile.
     * @param memberHandle The handle of the member to modify.
     * @param actionName The new action name.
     * @param actionData The new action parameters.
     * @return 0 on success, -1 on failure.
     */
    int ModifyActionProfileMember(const std::string& profileName,
                                  bm::ActionProfile::mbr_hdl_t memberHandle,
                                  const std::string& actionName,
                                  bm::ActionData&& actionData);

    /**
     * @brief Creates a group in an action profile.
     * @param profileName The name of the action profile.
     * @param[out] outHandle Pointer to store the resulting group handle.
     * @return 0 on success, -1 on failure.
     */
    int CreateActionProfileGroup(const std::string& profileName,
                                 bm::ActionProfile::grp_hdl_t* outHandle);

    /**
     * @brief Deletes a group from an action profile.
     * @param profileName The name of the action profile.
     * @param groupHandle The handle of the group to delete.
     * @return 0 on success, -1 on failure.
     */
    int DeleteActionProfileGroup(const std::string& profileName,
                                 bm::ActionProfile::grp_hdl_t groupHandle);

    /**
     * @brief Adds a member to a group in an action profile.
     * @param profileName The name of the action profile.
     * @param memberHandle The member handle to add.
     * @param groupHandle The group handle to add to.
     * @return 0 on success, -1 on failure.
     */
    int AddMemberToGroup(const std::string& profileName,
                         bm::ActionProfile::mbr_hdl_t memberHandle,
                         bm::ActionProfile::grp_hdl_t groupHandle);

    /**
     * @brief Removes a member from a group in an action profile.
     * @param profileName The name of the action profile.
     * @param memberHandle The member handle to remove.
     * @param groupHandle The group handle to remove from.
     * @return 0 on success, -1 on failure.
     */
    int RemoveMemberFromGroup(const std::string& profileName,
                              bm::ActionProfile::mbr_hdl_t memberHandle,
                              bm::ActionProfile::grp_hdl_t groupHandle);

    /**
     * @brief Retrieves all members in an action profile.
     * @param profileName The name of the action profile.
     * @param[out] members Pointer to a vector where members will be stored.
     * @return 0 on success, -1 on failure.
     */
    int GetActionProfileMembers(const std::string& profileName,
                                std::vector<bm::ActionProfile::Member>* members);

    /**
     * @brief Retrieves a specific member from an action profile.
     * @param profileName The name of the action profile.
     * @param memberHandle The handle of the member to retrieve.
     * @param[out] member Pointer to the member structure to populate.
     * @return 0 on success, -1 on failure.
     */
    int GetActionProfileMember(const std::string& profileName,
                               bm::ActionProfile::mbr_hdl_t memberHandle,
                               bm::ActionProfile::Member* member);

    /**
     * @brief Retrieves all groups in an action profile.
     * @param profileName The name of the action profile.
     * @param[out] groups Pointer to a vector where groups will be stored.
     * @return 0 on success, -1 on failure.
     */
    int GetActionProfileGroups(const std::string& profileName,
                               std::vector<bm::ActionProfile::Group>* groups);

    /**
     * @brief Retrieves a specific group in an action profile.
     * @param profileName The name of the action profile.
     * @param groupHandle The handle of the group to retrieve.
     * @param[out] group Pointer to the group structure to populate.
     * @return 0 on success, -1 on failure.
     */
    int GetActionProfileGroup(const std::string& profileName,
                              bm::ActionProfile::grp_hdl_t groupHandle,
                              bm::ActionProfile::Group* group);

    // =========== Indirect Table Operations ==============
    /**
     * @brief Adds an entry to an indirect match table using a member handle.
     * @param tableName Name of the indirect match table.
     * @param matchKey Match key for the entry.
     * @param memberHandle Handle to the action profile member.
     * @param[out] outHandle Pointer to store the generated entry handle.
     * @param priority Priority of the match entry (default is 1).
     * @return 0 on success, -1 on failure.
     */
    int AddIndirectEntry(const std::string& tableName,
                         const std::vector<bm::MatchKeyParam>& matchKey,
                         bm::ActionProfile::mbr_hdl_t memberHandle,
                         bm::entry_handle_t* outHandle,
                         int priority = 1);

    /**
     * @brief Modifies an existing indirect match table entry to update its
     * member.
     * @param tableName Name of the indirect match table.
     * @param entryHandle Handle of the entry to modify.
     * @param memberHandle New member handle to assign to the entry.
     * @return 0 on success, -1 on failure.
     */
    int ModifyIndirectEntry(const std::string& tableName,
                            bm::entry_handle_t entryHandle,
                            bm::ActionProfile::mbr_hdl_t memberHandle);

    /**
     * @brief Deletes an entry from an indirect match table.
     * @param tableName Name of the indirect match table.
     * @param entryHandle Handle of the entry to delete.
     * @return 0 on success, -1 on failure.
     */
    int DeleteIndirectEntry(const std::string& tableName, bm::entry_handle_t entryHandle);

    /**
     * @brief Sets a timeout (TTL) in milliseconds for an indirect table entry.
     * @param tableName Name of the table.
     * @param handle Handle of the entry.
     * @param ttlMs Timeout value in milliseconds.
     * @return 0 on success, -1 on failure.
     */
    int SetIndirectEntryTtl(const std::string& tableName,
                            bm::entry_handle_t handle,
                            unsigned int ttlMs);

    /**
     * @brief Sets the default member to be used when no match is found in an
     * indirect match table.
     * @param tableName Name of the table.
     * @param memberHandle Handle of the member to be set as default.
     * @return 0 on success, -1 on failure.
     */
    int SetIndirectDefaultMember(const std::string& tableName,
                                 bm::ActionProfile::mbr_hdl_t memberHandle);

    /**
     * @brief Resets the default entry of an indirect match table.
     * @param tableName Name of the table.
     * @return 0 on success, -1 on failure.
     */
    int ResetIndirectDefaultEntry(const std::string& tableName);

    /**
     * @brief Adds an entry to an indirect wide-switch (WS) match table using a
     * group handle.
     * @param tableName Name of the indirect WS match table.
     * @param matchKey Match key for the entry.
     * @param groupHandle Group handle to associate with the entry.
     * @param[out] outHandle Pointer to store the generated entry handle.
     * @param priority Priority of the match entry (default is 1).
     * @return 0 on success, -1 on failure.
     */
    int AddIndirectWsEntry(const std::string& tableName,
                           const std::vector<bm::MatchKeyParam>& matchKey,
                           bm::ActionProfile::grp_hdl_t groupHandle,
                           bm::entry_handle_t* outHandle,
                           int priority = 1);

    /**
     * @brief Modifies an entry in an indirect WS match table with a new group
     * handle.
     * @param tableName Name of the indirect WS match table.
     * @param handle Handle of the entry to modify.
     * @param groupHandle New group handle to assign.
     * @return 0 on success, -1 on failure.
     */
    int ModifyIndirectWsEntry(const std::string& tableName,
                              bm::entry_handle_t handle,
                              bm::ActionProfile::grp_hdl_t groupHandle);

    /**
     * @brief Sets the default group for an indirect wide-switch match table.
     * @param tableName Name of the table.
     * @param groupHandle Group handle to set as default.
     * @return 0 on success, -1 on failure.
     */
    int SetIndirectWsDefaultGroup(const std::string& tableName,
                                  bm::ActionProfile::grp_hdl_t groupHandle);

    // ======== Flow Table Entry Retrieval Operations ===========

    /**
     * @brief Retrieves all entries from a match table
     * @param tableName Name of the match table
     * @param entriesOut Pointer to a vector where the retrieved entries will be
     * stored
     * @return 0 on success, -1 on failure
     */
    std::vector<bm::MatchTable::Entry> GetFlowEntries(const std::string& tableName);
    /**
     * @brief Retrieves all entries from an indirect match table
     * @param tableName Name of the indirect match table
     * @param entriesOut Pointer to a vector where the retrieved entries will be
     * stored
     * @return 0 on success, -1 on failure
     */
    std::vector<bm::MatchTableIndirect::Entry> GetIndirectFlowEntries(const std::string& tableName);
    /**
     * @brief Retrieves all entries from an indirect wide-switch match table
     * @param tableName Name of the indirect wide-switch match table
     * @param entriesOut Pointer to a vector where the retrieved entries will be
     * stored
     * @return 0 on success, -1 on failure
     */
    std::vector<bm::MatchTableIndirectWS::Entry> GetIndirectWsFlowEntries(
        const std::string& tableName);
    /**
     * @brief Retrieves a specific entry from a match table by handle
     * @param tableName Name of the match table
     * @param handle Entry handle identifying the rule
     * @param entryOut Pointer to store the retrieved entry
     * @return 0 on success, -1 on failure
     */
    /**
     * @brief Retrieves a direct match table entry from the specified table.
     * @param tableName  Name of the match table to query.
     * @param handle     Handle (ID) of the entry within the match table.
     * @param entry      Pointer to a MatchTable::Entry object where the retrieved
     *                   entry data will be stored.
     * @return 0 on success, or a non-zero error code on failure.
     */
    int GetEntry(const std::string& tableName,
                 bm::entry_handle_t handle,
                 bm::MatchTable::Entry* entry);

    /**
     * @brief Retrieves an entry from an indirect match table.
     * @param tableName  Name of the indirect match table to query.
     * @param handle     Handle (ID) of the entry within the indirect match table.
     * @param entry      Pointer to a MatchTableIndirect::Entry object where the
     *                   retrieved entry data will be stored.
     * @return 0 on success, or a non-zero error code on failure.
     */
    int GetIndirectEntry(const std::string& tableName,
                         bm::entry_handle_t handle,
                         bm::MatchTableIndirect::Entry* entry);

    /**
     * @brief Retrieves an entry from an indirect match table with selector (WS).
     * @param tableName  Name of the indirect match table with selector.
     * @param handle     Handle (ID) of the entry within the table.
     * @param entry      Pointer to a MatchTableIndirectWS::Entry object where the
     *                   retrieved entry data will be stored.
     * @return 0 on success, or a non-zero error code on failure.
     */
    int GetIndirectWsEntry(const std::string& tableName,
                           bm::entry_handle_t handle,
                           bm::MatchTableIndirectWS::Entry* entry);

    /**
     * @brief Retrieve the default entry from a direct match-action table.
     * @param tableName Name of the match-action table.
     * @param entry Pointer to a MatchTable::Entry object where the retrieved
     * entry will be stored.
     * @return 0 on success, non-zero on failure.
     */
    int GetDefaultEntry(const std::string& tableName, bm::MatchTable::Entry* entry);

    /**
     * @brief Retrieve the default entry from an indirect match-action table.
     * @param tableName Name of the match-action table.
     * @param entry Pointer to a MatchTableIndirect::Entry object where the
     * retrieved entry will be stored.
     * @return 0 on success, non-zero on failure.
     */
    int GetIndirectDefaultEntry(const std::string& tableName, bm::MatchTableIndirect::Entry* entry);

    /**
     * @brief Retrieve the default entry from an indirect-with-selector
     * match-action table.
     * @param tableName Name of the match-action table.
     * @param entry Pointer to a MatchTableIndirectWS::Entry object where the
     * retrieved entry will be stored.
     * @return 0 on success, non-zero on failure.
     */
    int GetIndirectWsDefaultEntry(const std::string& tableName,
                                  bm::MatchTableIndirectWS::Entry* entry);
    /**
     * @brief Retrieve a direct table entry using a specific match key.
     * @param tableName Name of the match-action table.
     * @param matchKey Match key parameters to locate the entry.
     * @param entry Pointer to a MatchTable::Entry object where the retrieved
     * entry will be stored.
     * @param priority Priority of the match (default is 1).
     * @return 0 on success, non-zero on failure.
     */
    int GetEntryFromKey(const std::string& tableName,
                        const std::vector<bm::MatchKeyParam>& matchKey,
                        bm::MatchTable::Entry* entry,
                        int priority = 1);
    /**
     * @brief Retrieve an entry from an indirect match-action table using a
     * specific match key.
     * @param tableName Name of the match-action table.
     * @param matchKey Match key parameters to locate the entry.
     * @param entry Pointer to a MatchTableIndirect::Entry object where the
     * retrieved entry will be stored.
     * @param priority Priority of the match (default is 1).
     * @return 0 on success, non-zero on failure.
     */
    int GetIndirectEntryFromKey(const std::string& tableName,
                                const std::vector<bm::MatchKeyParam>& matchKey,
                                bm::MatchTableIndirect::Entry* entry,
                                int priority = 1);
    /**
     * @brief Retrieve an entry from an indirect-with-selector match-action table
     * using a specific match key.
     * @param tableName Name of the match-action table.
     * @param matchKey Match key parameters to locate the entry.
     * @param entry Pointer to a MatchTableIndirectWS::Entry object where the
     * retrieved entry will be stored.
     * @param priority Priority of the match (default is 1).
     * @return 0 on success, non-zero on failure.
     */
    int GetIndirectWsEntryFromKey(const std::string& tableName,
                                  const std::vector<bm::MatchKeyParam>& matchKey,
                                  bm::MatchTableIndirectWS::Entry* entry,
                                  int priority = 1);

    // === Counter Functions ===

    /**
     * @brief Read packet and byte counters for a specific table entry.
     * @param tableName The name of the table.
     * @param handle The entry handle.
     * @param bytes Output: number of bytes.
     * @param packets Output: number of packets.
     * @return 0 on success, -1 on failure.
     */
    int ReadTableCounters(const std::string& tableName,
                          bm::entry_handle_t handle,
                          uint64_t* bytes,
                          uint64_t* packets);

    /**
     * @brief Reset all counters in the specified match-action table.
     * @param tableName The name of the table.
     * @return 0 on success, -1 on failure.
     */
    int ResetTableCounters(const std::string& tableName);

    /**
     * @brief Write counters for a specific table entry.
     * @param tableName The name of the table.
     * @param handle The entry handle.
     * @param bytes Number of bytes to set.
     * @param packets Number of packets to set.
     * @return 0 on success, -1 on failure.
     */
    int WriteTableCounters(const std::string& tableName,
                           bm::entry_handle_t handle,
                           uint64_t bytes,
                           uint64_t packets);
    /**

    *@brief Read the byte and packet count from a named counter at a given index.
    *@param counterName Name of the counter array.
    *@param index Index within the counter array.
    *@param[out] bytes Pointer to store the byte count.
    *@param[out] packets Pointer to store the packet count.
    *@return 0 on success, -1 on failure.
    */
    int ReadCounter(const std::string& counterName,
                    size_t index,
                    bm::MatchTableAbstract::counter_value_t* bytes,
                    bm::MatchTableAbstract::counter_value_t* packets);

    /**
     *@brief Reset all values in a named counter array to zero.
     *@param counterName Name of the counter array to reset.
     *@return 0 on success, -1 on failure.
     */
    int ResetCounter(const std::string& counterName);

    /**
     *@brief Manually write values to a counter array at a given index.
     *@param counterName Name of the counter array.
     *@param index Index within the counter array.
     *@param bytes Number of bytes to write.
     *@param packets Number of packets to write
     *@return 0 on success, -1 on failure.
     */
    int WriteCounter(const std::string& counterName,
                     size_t index,
                     bm::MatchTableAbstract::counter_value_t bytes,
                     bm::MatchTableAbstract::counter_value_t packets);

    // ============= Meter Operations ============

    /**
     *@brief Set meter rates for a specific match table entry.
     *@param tableName Name of the match table.
     *@param handle Entry handle in the table.
     *@param configs Rate configuration vector.
     *@return 0 on success, -1 on failure.
     */
    int SetMeterRates(const std::string& tableName,
                      bm::entry_handle_t handle,
                      const std::vector<bm::Meter::rate_config_t>& configs);

    /**
     *@brief Get meter rates for a specific match table entry.
     *@param tableName Name of the match table.
     *@param handle Entry handle in the table.
     *@param[out] configs Pointer to hold the retrieved rate configurations.
     *@return 0 on success, -1 on failure.
     */
    int GetMeterRates(const std::string& tableName,
                      bm::entry_handle_t handle,
                      std::vector<bm::Meter::rate_config_t>* configs);

    /**
     *@brief Reset meter rates for a specific match table entry.
     *@param tableName Name of the match table.
     *@param handle Entry handle in the table.
     *@return 0 on success, -1 on failure.
     */
    int ResetMeterRates(const std::string& tableName, bm::entry_handle_t handle);

    /**
     *@brief Set the rate configuration for an entire meter array.
     *@param meterName Name of the meter array.
     *@param configs Rate configuration vector to apply.
     *@return 0 on success, -1 on failure.
     */
    int SetMeterArrayRates(const std::string& meterName,
                           const std::vector<bm::Meter::rate_config_t>& configs);

    /**
     *@brief Set meter rates for a specific index in a meter array.
     *@param meterName Name of the meter array.
     *@param idx Index within the meter array.
     *@param configs Rate configuration vector.
     *@return 0 on success, -1 on failure.
     */
    int MeterSetRates(const std::string& meterName,
                      size_t idx,
                      const std::vector<bm::Meter::rate_config_t>& configs);

    /**
     *@brief Get meter rate configuration for a specific index in a meter array.
     *@param meterName Name of the meter array.
     *@param idx Index within the meter array.
     *@param[out] configs Pointer to store the retrieved rate configurations.
     *@return 0 on success, -1 on failure.
     */
    int MeterGetRates(const std::string& meterName,
                      size_t idx,
                      std::vector<bm::Meter::rate_config_t>* configs);

    /**
     *@brief Reset meter rate configuration at a given index in a meter array.
     *@param meterName Name of the meter array.
     *@param idx Index within the meter array.
     *@return 0 on success, -1 on failure.
     */
    int MeterResetRates(const std::string& meterName, size_t idx);

    // ======= Register Operations   =======
    /**
     * @brief Reads the value from a specific register index.
     * @param registerName Name of the register array to read from.
     * @param index Index within the register array to read.
     * @param value Pointer to a bm::Data object where the read value will be
     * stored.
     * @return 0 on success, non-zero on failure (e.g., invalid register name or
     * index).
     */
    int RegisterRead(const std::string& registerName, size_t index, bm::Data* value);

    /**
     * @brief Writes a value to a specific register index
     * @param registerName Name of the register array to write to.
     * @param index Index within the register array to write.
     * @param value Value to write (as bm::Data).
     * @return 0 on success, non-zero on failure.
     */
    int RegisterWrite(const std::string& registerName, size_t index, const bm::Data& value);

    /**
     * @brief Reads the entire register array.
     * @param registerName Name of the register array to read from.
     * @return A vector containing all register values (each as bm::Data).
     *         The vector will be empty if the register name is invalid.
     */
    std::vector<bm::Data> RegisterReadAll(const std::string& registerName);

    /**
     * @brief Writes the same value to a range of register indices.
     * @param registerName Name of the register array to write to.
     * @param startIndex Starting index of the range (inclusive).
     * @param endIndex Ending index of the range (inclusive).
     * @param value Value to write (as bm::Data) to all indices in the range.
     * @return 0 on success, non-zero on failure.
     */
    int RegisterWriteRange(const std::string& registerName,
                           size_t startIndex,
                           size_t endIndex,
                           const bm::Data& value);

    /**
     * @brief Resets all entries in the specified register array to zero.
     * @param registerName Name of the register array to reset.
     * @return 0 on success, non-zero on failure.
     */
    int RegisterReset(const std::string& registerName);

    // ======= Parse Value Set Functions  =======

    /**
     * @brief Adds a value to a parse value set.
     * @param vsetName Name of the parse value set.
     * @param value The value to add to the set.
     * @return 0 on success, -1 on failure.
     */
    int ParseVsetAdd(const std::string& vsetName, const bm::ByteContainer& value);

    /**
     * @brief Removes a value from a parse value set.
     * @param vsetName Name of the parse value set.
     * @param value The value to remove from the set.
     * @return 0 on success, -1 on failure.
     */
    int ParseVsetRemove(const std::string& vsetName, const bm::ByteContainer& value);

    /**
     * @brief Retrieves all values in a parse value set.
     * @param vsetName Name of the parse value set.
     * @param values Output vector to store retrieved ByteContainers.
     * @return 0 on success, -1 on failure.
     */
    int ParseVsetGet(const std::string& vsetName, std::vector<bm::ByteContainer>* values);

    /**
     * @brief Clears all values in a parse value set.
     * @param vsetName Name of the parse value set.
     * @return 0 on success, -1 on failure.
     */
    int ParseVsetClear(const std::string& vsetName);

    // ======= Runtime State Management ========
    /**
     * @brief Resets the runtime state of the switch to its initial configuration.
     * @return 0 on success, -1 on failure.
     */
    int ResetState();

    /**
     * @brief Serializes the current runtime state to an output stream.
     * @param[out] out Pointer to output stream to write the serialized
     * configuration.
     * @return 0 on success, -1 on failure.
     */
    int Serialize(std::ostream* out);

    /**
     * @brief Loads a new P4 program for SwapConfigs() (needs EnableSwap).
     * @param newConfig the BMv2 JSON of the program, as a string (not a path).
     * @return 0 on success, -1 on failure.
     */
    int LoadNewConfig(const std::string& newConfig);

    /**
     * @brief Swaps to the program loaded by LoadNewConfig(): at once if the
     * switch holds no packet, otherwise when its last packet has left; frames
     * that arrive meanwhile wait (see P4SwitchCore::swap_configs()).
     * @return 0 if the swap is done or waits, -1 on failure.
     */
    int SwapConfigs();

    /**
     * @brief Retrieves the current runtime configuration as a JSON string.
     * @param[out] configOut Pointer to a string to store the configuration.
     * @return 0 on success, -1 on failure.
     */
    int GetConfig(std::string* configOut);

    /**
     * @brief Retrieves the MD5 hash of the current runtime configuration.
     * @param[out] md5Out Pointer to a string to store the MD5 hash.
     * @return 0 on success, -1 on failure.
     */
    int GetConfigMd5(std::string* md5Out);

  private:
    bm::RuntimeInterface& m_sw; //!< The switch
};

} // namespace ns3

#endif // P4_RUNTIME_API_H
