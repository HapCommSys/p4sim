#ifndef P4_CONTROLLER_H
#define P4_CONTROLLER_H

#include "p4-switch-net-device.h"

#include "ns3/object.h"
#include "ns3/p4-core-v1model.h"
#include <ns3/network-module.h>

#include <string>
#include <vector>

namespace ns3 {

class P4CoreV1model;

/**
 * @brief Controller for managing multiple P4 switches in an NS-3 simulation.
 *
 * This class provides methods for:
 * - Viewing flow table information for all or specific P4 switches.
 * - Setting paths for flow table configuration and viewing.
 * - Managing a collection of P4 switches, including adding and retrieving
 * switches.
 */
class P4Controller : public Object {
public:
  /**
   * @brief Constructor for P4Controller.
   */
  P4Controller();

  /**
   * @brief Destructor for P4Controller.
   */
  ~P4Controller();

  /**
   * @brief Register the P4Controller class with the NS-3 type system.
   *
   * @return TypeId for the P4Controller class.
   */
  static TypeId GetTypeId(void);
  /**
   * @brief Register P4 Switch with the controller.
   */
  void RegisterSwitch(ns3::Ptr<ns3::P4SwitchNetDevice> sw);

  /**
   * @brief Connect controller to switch's trace sources
   * @param switchIndex Index of the switch in m_connectedSwitches
   */
  void ConnectToSwitchEvents(uint32_t switchIndex);
  void HandleSwitchEvent(uint32_t switchId, const std::string &message);
  /**
   * @brief Gives the count of the p4 switches registered with the controller
   */
  uint32_t GetN();

  /**
   * @brief View flow table information for all P4 switches managed by the
   * controller.
   */
  void ViewAllSwitchFlowTableInfo();

  /**
   * @brief View detailed flow table, counter, register, and meter information
   *        for a specific P4 switch.
   * @param index Index of the P4 switch in the controller's collection.
   */
  void ViewP4SwitchFlowTableInfo(uint32_t index);
  /**
   * @brief Set the path for viewing flow table information of a specific P4
   * switch.
   * @param index Index of the P4 switch in the controller's collection.
   * @param viewFlowTablePath File path for viewing flow table information.
   */
  void SetP4SwitchViewFlowTablePath(size_t index,
                                    const std::string &viewFlowTablePath);

  /**
   * @brief Set the path for populating the flow table of a specific P4 switch.
   * @param index Index of the P4 switch in the controller's collection.
   * @param flowTablePath File path for populating flow table entries.
   */
  void SetP4SwitchFlowTablePath(size_t index, const std::string &flowTablePath);

  /**
   * @brief Retrieves the number of entries currently present in a given match
   * table
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the match table whose entry count is to be
   * retrieved.
   * @return The number of entries in the specified table, or -1 if the table
   * name is invalid or the switch index is out of range.
   */
  int GetTableEntryCount(uint32_t index, const std::string &tableName);

  /**
   * @brief Logs the number of entries present in a given match table to the
   * ns-3 log.
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the match table whose entry count is to be
   * printed.
   */
  void PrintTableEntryCount(uint32_t index, const std::string &tableName);

  /**
   *  @brief Clears the table entries from the given switch and table
   */
  void ClearFlowTableEntries(uint32_t index, const std::string &tableName,
                             bool resetDefault = false);
  /**
   * @brief Adds a flow entry to a match-action table on the specified switch.
   * @param index The switch index.
   * @param tableName The name of the match-action table.
   * @param matchKey The list of match fields for the entry.
   * @param actionName The name of the action to apply.
   * @param actionData The action parameters.
   * @param priority Optional priority value (used for ternary/LPM matches).
   * Default is -1.
   */
  void AddFlowEntry(uint32_t index, const std::string &tableName,
                    const std::vector<bm::MatchKeyParam> &matchKey,
                    const std::string &actionName, bm::ActionData &&actionData,
                    bm::entry_handle_t &handle, int priority = -1);

  /**
   * @brief Sets the default action for a match-action table on the specified
   * switch.
   * @param index The switch index.
   * @param tableName The name of the table.
   * @param actionName The name of the default action.
   * @param actionData The action parameters.
   */
  void SetDefaultAction(uint32_t index, const std::string &tableName,
                        const std::string &actionName,
                        bm::ActionData &&actionData);

  /**
   * @brief Resets the default action for a match-action table to its original
   * state.
   * @param index The switch index.
   * @param tableName The name of the table.
   */
  void ResetDefaultEntry(uint32_t index, const std::string &tableName);

  /**
   * @brief Deletes a specific flow entry from a match-action table on the
   * specified switch.
   * @param index The switch index.
   * @param tableName The name of the table.
   * @param handle The handle of the entry to delete.
   */
  void DeleteFlowEntry(uint32_t index, const std::string &tableName,
                       bm::entry_handle_t handle);

  /**
   * @brief Modifies an existing flow entry in a match-action table.
   * @param index The switch index.
   * @param tableName The name of the table.
   * @param handle The handle of the entry to modify.
   * @param actionName The new action name.
   * @param actionData The new action parameters.
   */
  void ModifyFlowEntry(uint32_t index, const std::string &tableName,
                       bm::entry_handle_t handle, const std::string &actionName,
                       bm::ActionData actionData);

  /**
   * @brief Sets a timeout (TTL) for a specific flow entry in a match-action
   * table.
   * @param index The switch index.
   * @param tableName The name of the table.
   * @param handle The entry handle.
   * @param ttlMs The TTL value in milliseconds.
   */
  void SetEntryTtl(uint32_t index, const std::string &tableName,
                   bm::entry_handle_t handle, unsigned int ttlMs);

  // ======== Action Profile Operations ===========

  /**
   * @brief Adds a member to the specified action profile on a switch.
   * @param index The switch index.
   * @param profileName The name of the action profile.
   * @param actionName The name of the action associated with the member.
   * @param actionData The parameters for the action.
   * @param mbrHandle The handle of the member to add.
   */
  void AddActionProfileMember(uint32_t index, const std::string &profileName,
                              const std::string &actionName,
                              bm::ActionData &&actionData,
                              bm::ActionProfile::mbr_hdl_t mbrHandle);

  /**
   * @brief Deletes a member from an action profile on a switch.
   * @param index The switch index.
   * @param profileName The name of the action profile.
   * @param memberHandle The handle of the member to delete.
   */
  void DeleteActionProfileMember(uint32_t index, const std::string &profileName,
                                 bm::ActionProfile::mbr_hdl_t memberHandle);

  /**
   * @brief Modifies an existing member in an action profile.
   * @param index The switch index.
   * @param profileName The name of the action profile.
   * @param memberHandle The handle of the member to modify.
   * @param actionName The new action name.
   * @param actionData The new action parameters.
   */
  void ModifyActionProfileMember(uint32_t index, const std::string &profileName,
                                 bm::ActionProfile::mbr_hdl_t memberHandle,
                                 const std::string &actionName,
                                 bm::ActionData &&actionData);
  /**
   * @brief Creates a new group in the specified action profile.
   * @param index Index of the switch to operate on
   * @param profileName Name of the action profile
   * @param outHandle Pointer to the group handle that will be set on success
   */
  void CreateActionProfileGroup(uint32_t index, const std::string &profileName,
                                bm::ActionProfile::grp_hdl_t *outHandle);

  /**
   * @brief Deletes a group in the specified action profile.
   * @param index Index of the switch to operate on
   * @param profileName Name of the action profile
   * @param groupHandle Handle of the group to be deleted
   */
  void DeleteActionProfileGroup(uint32_t index, const std::string &profileName,
                                bm::ActionProfile::grp_hdl_t groupHandle);

  /**
   * @brief Adds a member to a group in an action profile.
   * @param index Index of the switch to operate on
   * @param profileName Name of the action profile
   * @param memberHandle Handle of the member to add
   * @param groupHandle Handle of the group to which the member should be added
   */
  void AddMemberToGroup(uint32_t index, const std::string &profileName,
                        bm::ActionProfile::mbr_hdl_t memberHandle,
                        bm::ActionProfile::grp_hdl_t groupHandle);
  /**
   * @brief Removes a member from a group in an action profile.
   * @param index Index of the switch to operate on
   * @param profileName Name of the action profile
   * @param memberHandle Handle of the member to remove
   * @param groupHandle Handle of the group from which the member is removed
   */
  void RemoveMemberFromGroup(uint32_t index, const std::string &profileName,
                             bm::ActionProfile::mbr_hdl_t memberHandle,
                             bm::ActionProfile::grp_hdl_t groupHandle);
  /**
   * @brief Prints all members in an action profile.
   * @param index Index of the switch to operate on
   * @param profileName Name of the action profile
   */
  void PrintActionProfileMembers(uint32_t index,
                                 const std::string &profileName);
  /**
   * @brief Retrieves all members in an action profile.
   * @param index Index of the switch to operate on
   * @param profileName Name of the action profile
   */
  std::vector<bm::ActionProfile::Member>
  GetActionProfileMembers(uint32_t index, const std::string &profileName);

  /**
   * @brief Retrieves a specific member from an action profile.
   * @param index Index of the switch to operate on
   * @param profileName Name of the action profile
   * @param memberHandle Handle of the member to retrieve
   */
  void GetActionProfileMember(uint32_t index, const std::string &profileName,
                              bm::ActionProfile::mbr_hdl_t memberHandle);
  /**
   * @brief Prints all groups in an action profile.
   * @param index Index of the switch to operate on
   * @param profileName Name of the action profile
   */
  void PrintActionProfileGroups(uint32_t index, const std::string &profileName);
  /**
   * @brief Retrieves all groups in an action profile.
   * @param index Index of the switch to operate on
   * @param profileName Name of the action profile
   */
  void GetActionProfileGroups(uint32_t index, const std::string &profileName);

  /**
   * @brief Retrieves a specific group from an action profile.
   * @param index Index of the switch to operate on
   * @param profileName Name of the action profile
   * @param groupHandle Handle of the group to retrieve
   */
  void GetActionProfileGroup(uint32_t index, const std::string &profileName,
                             bm::ActionProfile::grp_hdl_t groupHandle);

  // ========== Indirect Table Operations ============
  /**
   * @brief Adds an entry to an indirect match table.
   * @param index Switch index
   * @param tableName Match table name
   * @param matchKey Match key vector
   * @param memberHandle Handle of action profile member
   * @param outHandle Output entry handle
   * @param priority Optional priority value (default = 1)
   */
  void AddIndirectEntry(uint32_t index, const std::string &tableName,
                        const std::vector<bm::MatchKeyParam> &matchKey,
                        bm::ActionProfile::mbr_hdl_t memberHandle,
                        bm::entry_handle_t *outHandle, int priority = 1);

  /**
   * @brief Modifies an existing entry in an indirect match table.
   * @param index Switch index
   * @param tableName Match table name
   * @param entryHandle Entry handle to modify
   * @param memberHandle New member handle
   */
  void ModifyIndirectEntry(uint32_t index, const std::string &tableName,
                           bm::entry_handle_t entryHandle,
                           bm::ActionProfile::mbr_hdl_t memberHandle);

  /**
   * @brief Deletes an entry from an indirect match table.
   * @param index Switch index
   * @param tableName Match table name
   * @param entryHandle Handle of entry to delete
   */
  void DeleteIndirectEntry(uint32_t index, const std::string &tableName,
                           bm::entry_handle_t entryHandle);
  /**
   * @brief Sets the TTL (timeout in ms) for an indirect match table entry.
   * @param index Switch index
   * @param tableName Match table name
   * @param handle Entry handle
   * @param ttlMs Timeout in milliseconds
   */
  void SetIndirectEntryTtl(uint32_t index, const std::string &tableName,
                           bm::entry_handle_t handle, unsigned int ttlMs);

  /**
   * @brief Sets the default member for an indirect match table.
   * @param index Switch index
   * @param tableName Match table name
   * @param memberHandle Member handle to set as default
   */
  void SetIndirectDefaultMember(uint32_t index, const std::string &tableName,
                                bm::ActionProfile::mbr_hdl_t memberHandle);

  /**
   * @brief Resets the default entry in an indirect match table.
   * @param index Switch index
   * @param tableName Match table name
   */
  void ResetIndirectDefaultEntry(uint32_t index, const std::string &tableName);

  /**
   * @brief Adds an entry to an indirect wide-switch match table.
   * @param index Switch index
   * @param tableName Match table name
   * @param matchKey Match key vector
   * @param groupHandle Group handle to associate with the entry
   * @param outHandle Pointer to receive the assigned entry handle
   * @param priority Match priority (default = 1)
   */
  void AddIndirectWsEntry(uint32_t index, const std::string &tableName,
                          const std::vector<bm::MatchKeyParam> &matchKey,
                          bm::ActionProfile::grp_hdl_t groupHandle,
                          bm::entry_handle_t *outHandle, int priority = 1);
  /**
   * @brief Modifies an indirect WS entry to use a different group handle.
   * @param index Switch index
   * @param tableName Match table name
   * @param handle Entry handle to modify
   * @param groupHandle New group handle
   */
  void ModifyIndirectWsEntry(uint32_t index, const std::string &tableName,
                             bm::entry_handle_t handle,
                             bm::ActionProfile::grp_hdl_t groupHandle);

  /**
   * @brief Sets the default group for an indirect wide-switch match table.
   * @param index Switch index
   * @param tableName Match table name
   * @param groupHandle Group handle to use as default
   */
  void SetIndirectWsDefaultGroup(uint32_t index, const std::string &tableName,
                                 bm::ActionProfile::grp_hdl_t groupHandle);

  // ========= Flow Table Entry Retrieval Operations ========

  /**
   * @brief Logs all direct match table flow entries from the specified switch
   * and table.
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the match table whose entries are to be printed.
   */
  void PrintFlowEntries(uint32_t index, const std::string &tableName);

  /**
   * @brief Logs all indirect match table flow entries from the specified switch
   * and table.
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the indirect match table whose entries are to be
   * printed.
   */
  void PrintIndirectFlowEntries(uint32_t index, const std::string &tableName);

  /**
   * @brief Logs all indirect (with selector) match table flow entries from the
   * specified switch and table.
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the indirect-with-selector match table whose
   * entries are to be printed.
   */
  void PrintIndirectWsFlowEntries(uint32_t index, const std::string &tableName);

  /**
   * @brief Logs a specific direct match table entry by its handle.
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the match table containing the entry.
   * @param handle Handle of the entry to be printed.
   */
  void PrintEntry(uint32_t index, const std::string &tableName,
                  bm::entry_handle_t handle);

  /**
   * @brief Logs the default entry for a direct match table.
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the match table whose default entry is to be
   * printed.
   */
  void PrintDefaultEntry(uint32_t index, const std::string &tableName);

  /**
   * @brief Logs the default entry for an indirect match table.
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the indirect match table whose default entry is to
   * be printed.
   */
  void PrintIndirectDefaultEntry(uint32_t index, const std::string &tableName);

  /**
   * @brief Logs the default entry for an indirect (with selector) match table.
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the indirect-with-selector match table whose
   * default entry is to be printed.
   */
  void PrintIndirectWsDefaultEntry(uint32_t index,
                                   const std::string &tableName);

  /**
   * @brief Logs a direct match table entry found by matching on a given key.
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the match table to search in.
   * @param matchKey Vector of match key parameters used to locate the entry.
   */
  void PrintEntryFromKey(uint32_t index, const std::string &tableName,
                         const std::vector<bm::MatchKeyParam> &matchKey);

  /**
   * @brief Logs an indirect match table entry found by matching on a given key.
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the indirect match table to search in.
   * @param matchKey Vector of match key parameters used to locate the entry.
   */
  void
  PrintIndirectEntryFromKey(uint32_t index, const std::string &tableName,
                            const std::vector<bm::MatchKeyParam> &matchKey);

  /**
   * @brief Logs an indirect (with selector) match table entry found by matching
   * on a given key.
   * @param index Index of the target switch in the controller's connected
   * switches list.
   * @param tableName Name of the indirect-with-selector match table to search
   * in.
   * @param matchKey Vector of match key parameters used to locate the entry.
   */
  void
  PrintIndirectWsEntryFromKey(uint32_t index, const std::string &tableName,
                              const std::vector<bm::MatchKeyParam> &matchKey);

  // ================= Counter Operations ===================

  /**
   * @brief Reads the counter values (bytes and packets) for a specific table
   * entry.
   * @param index Index of the switch in the connected switches list.
   * @param tableName Name of the table containing the counter.
   * @param handle Entry handle identifying the specific table entry.
   */
  void ReadCounters(uint32_t index, const std::string &tableName,
                    bm::entry_handle_t handle);

  /**
   * @brief Resets all counters for a specific table to zero.
   * @param index Index of the switch in the connected switches list.
   * @param tableName Name of the table whose counters should be reset.
   */
  void ResetCounters(uint32_t index, const std::string &tableName);

  /**
   * @brief Writes specific counter values for a given table entry.
   * @param index Index of the switch in the connected switches list.
   * @param tableName Name of the table containing the counter.
   * @param handle Entry handle identifying the specific table entry.
   * @param bytes Number of bytes to set for the counter.
   * @param packets Number of packets to set for the counter.
   */
  void WriteCounters(uint32_t index, const std::string &tableName,
                     bm::entry_handle_t handle, uint64_t bytes,
                     uint64_t packets);

  /**
   * @brief Reads the counter value for a specific counter object by name and
   * index.
   * @param index Index of the switch in the connected switches list.
   * @param counterName Name of the counter to read.
   * @param counterIndex Index of the counter entry to read.
   */
  void ReadCounter(uint32_t index, const std::string &counterName,
                   size_t counterIndex);

  /**
   * @brief Resets the counter value for a specific counter object to zero.
   * @param index Index of the switch in the connected switches list.
   * @param counterName Name of the counter to reset.
   */
  void ResetCounter(uint32_t index, const std::string &counterName);

  /**
   * @brief Writes specific values to a counter object.
   * @param index Index of the switch in the connected switches list.
   * @param counterName Name of the counter to write to.
   * @param counterIndex Index of the counter entry to update.
   * @param bytes Number of bytes to set for the counter.
   * @param packets Number of packets to set for the counter.
   */
  void WriteCounter(uint32_t index, const std::string &counterName,
                    size_t counterIndex,
                    bm::MatchTableAbstract::counter_value_t bytes,
                    bm::MatchTableAbstract::counter_value_t packets);

  //  ======= Meter Functions  =======
  /**
   * @brief Set meter rates for a specific table entry.
   * @param index Index of the target switch.
   * @param tableName Name of the match-action table.
   * @param handle Entry handle to apply meter rates.
   * @param configs Vector of meter rate configurations.
   */
  void SetMeterRates(uint32_t index, const std::string &tableName,
                     bm::entry_handle_t handle,
                     const std::vector<bm::Meter::rate_config_t> &configs);

  /**
   * @brief Get meter rates for a specific table entry.
   * @param index Index of the target switch.
   * @param tableName Name of the match-action table.
   * @param handle Entry handle to retrieve meter rates from.
   */
  void GetMeterRates(uint32_t index, const std::string &tableName,
                     bm::entry_handle_t handle);

  /**
   * @brief Reset meter rates for a specific table entry.
   * @param index Index of the target switch.
   * @param tableName Name of the match-action table.
   * @param handle Entry handle to reset meter rates.
   */
  void ResetMeterRates(uint32_t index, const std::string &tableName,
                       bm::entry_handle_t handle);

  /**
   * @brief Set meter rates for an entire meter array.
   * @param index Index of the target switch.
   * @param meterName Name of the meter array.
   * @param configs Meter rate configuration vector.
   */
  void SetMeterArrayRates(uint32_t index, const std::string &meterName,
                          const std::vector<bm::Meter::rate_config_t> &configs);

  /**
   * @brief Set meter rates for a specific meter index.
   * @param index Index of the target switch.
   * @param meterName Name of the meter.
   * @param meterIndex Index within the meter array.
   * @param configs Meter rate configuration vector.
   */
  void SetMeterRates(uint32_t index, const std::string &meterName,
                     size_t meterIndex,
                     const std::vector<bm::Meter::rate_config_t> &configs);

  /**
   * @brief Get meter rates for a specific meter index.
   * @param index Index of the target switch.
   * @param meterName Name of the meter.
   * @param meterIndex Index within the meter array.
   */
  void GetMeterRates(uint32_t index, const std::string &meterName,
                     size_t meterIndex);

  /**
   * @brief Reset meter rates for a specific meter index.
   * @param index Index of the target switch.
   * @param meterName Name of the meter.
   * @param meterIndex Index within the meter array.
   */
  void ResetMeterRates(uint32_t index, const std::string &meterName,
                       size_t meterIndex);

  // ======= Register  Functions  =======

  /**
   * @brief Reads the value from a specific register index in the switch.
   * @param index Index of the target switch in the connected switches list.
   * @param registerName Name of the register to read from.
   * @param regIndex Index within the register array to read.
   * @param value Pointer to a bm::Data object where the read value will be
   * stored.
   */
  void RegisterRead(uint32_t index, const std::string &registerName,
                    size_t regIndex, bm::Data *value);

  /**
   * @brief Writes a value to a specific register index in the switch.
   * @param index Index of the target switch in the connected switches list.
   * @param registerName Name of the register to write to.
   * @param regIndex Index within the register array to write.
   * @param value The value to write into the specified register entry.
   */
  void RegisterWrite(uint32_t index, const std::string &registerName,
                     size_t regIndex, const bm::Data &value);

  /**
   * @brief Reads all entries from a register in the switch.
   * @param index Index of the target switch in the connected switches list.
   * @param registerName Name of the register to read from.
   */
  void RegisterReadAll(uint32_t index, const std::string &registerName);

  /**
   * @brief Writes the same value to a range of register indices in the switch.
   * @param index Index of the target switch in the connected switches list.
   * @param registerName Name of the register to write to.
   * @param startIndex Starting index of the range to write.
   * @param endIndex Ending index of the range to write.
   * @param value The value to write into each register entry in the specified
   * range.
   */
  void RegisterWriteRange(uint32_t index, const std::string &registerName,
                          size_t startIndex, size_t endIndex,
                          const bm::Data &value);

  /**
   * @brief Resets all entries in a register to their default values.
   * @param index Index of the target switch in the connected switches list.
   * @param registerName Name of the register to reset.
   */
  void RegisterReset(uint32_t index, const std::string &registerName);

  // ======= Parse Value Set Functions  =======
  /**
   * @brief Adds a value to a parse value set on a target switch.
   * @param index Index of the switch.
   * @param setName Name of the parse value set.
   * @param value ByteContainer representing the value to add.
   */
  void ParseVsetAdd(uint32_t index, const std::string &setName,
                    const bm::ByteContainer &value);

  /**
   * @brief Removes a value from a parse value set on a target switch.
   * @param index Index of the switch.
   * @param setName Name of the parse value set.
   * @param value ByteContainer representing the value to remove.
   */
  void ParseVsetRemove(uint32_t index, const std::string &setName,
                       const bm::ByteContainer &value);

  /**
   * @brief Retrieves all values from a parse value set on a target switch.
   * @param index Index of the switch.
   * @param setName Name of the parse value set.
   */
  void ParseVsetGet(uint32_t index, const std::string &setName);

  /**
   * @brief Clears all values from a parse value set on a target switch.
   * @param index Index of the switch.
   * @param setName Name of the parse value set.
   */
  void ParseVsetClear(uint32_t index, const std::string &setName);

  // ======== Runtime State Management Functions =======

  /**
   * @brief Resets the runtime state of the specified switch to its initial
   * configuration.
   * @param index The switch index.
   */
  void ResetState(uint32_t index);

  /**
   * @brief Serializes the runtime state of the specified switch to stdout.
   * @param index The switch index.
   */
  void Serialize(uint32_t index, std::ostream *out);

  /**
   * @brief Loads a new P4 configuration into the specified switch.
   * @param index The switch index.
   * @param newConfig A JSON string representing the new configuration.
   */
  void LoadNewConfig(uint32_t index, const std::string &newConfig);

  /**
   * @brief Swaps the currently active configuration with the newly loaded one
   * on the specified switch.
   * @param index The switch index.
   */
  void SwapConfigs(uint32_t index);

  /**
   * @brief Retrieves the current runtime configuration as a string and logs it.
   * @param index The switch index.
   */
  void GetConfig(uint32_t index);

  /**
   * @brief Retrieves and logs the MD5 hash of the current runtime
   * configuration.
   * @param index The switch index.
   */
  void GetConfigMd5(uint32_t index);

private:
  /**
   * @brief Collection of P4 switch interfaces managed by the controller.
   *        Each switch is identified by its index in this vector.
   */
  //   std::vector<P4SwitchInterface *> p4SwitchInterfaces_;

  // Disable copy constructor and assignment operator
  P4Controller(const P4Controller &) = delete;
  P4Controller &operator=(const P4Controller &) = delete;

  std::vector<ns3::Ptr<ns3::P4SwitchNetDevice>> m_connectedSwitches;
};

} // namespace ns3

#endif // P4_CONTROLLER_H
