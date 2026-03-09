/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors: Antonin Bas <antonin@barefootnetworks.com>
 * Modified: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#ifndef P4_CORE_V1MODEL_H
#define P4_CORE_V1MODEL_H

#include "ns3/p4-queue.h"
#include "ns3/p4-switch-core.h"
#include "ns3/traced-callback.h"

#include <bm/bm_sim/counters.h>
#include <unordered_map>

#define SSWITCH_VIRTUAL_QUEUE_NUM_V1MODEL 8

namespace ns3
{

class P4CoreV1model : public P4SwitchCore
{
  public:
    static TypeId GetTypeId(void);
    // === Constructor & Destructor ===
    P4CoreV1model(P4SwitchNetDevice* net_device,
                  bool enable_swap,
                  bool enableTracing,
                  uint64_t packet_rate,
                  size_t input_buffer_size_low,
                  size_t input_buffer_size_high,
                  size_t queue_buffer_size,
                  size_t nb_queues_per_port = SSWITCH_VIRTUAL_QUEUE_NUM_V1MODEL);
    ~P4CoreV1model();

    /**
     * @brief Different types of packet instances
     * @details The packet instance type is used to determine the processing
     * pipeline of the packet. PKT_INSTANCE_TYPE_NORMAL usually will have
     * lower priority than other types.
     */
    enum PktInstanceTypeV1model
    {
        PKT_INSTANCE_TYPE_NORMAL,
        PKT_INSTANCE_TYPE_INGRESS_CLONE,
        PKT_INSTANCE_TYPE_EGRESS_CLONE,
        PKT_INSTANCE_TYPE_COALESCED,
        PKT_INSTANCE_TYPE_RECIRC,
        PKT_INSTANCE_TYPE_REPLICATION,
        PKT_INSTANCE_TYPE_RESUBMIT,
    };

    // === Packet Processing ===
    /**
     * @brief Receive a packet from the switch net device
     * @details This function is called by the switch net device to pass a packet
     * to the switch core for processing.
     * @param packetIn The packet to be processed
     * @param inPort The ingress port of the packet
     * @param protocol The protocol of the packet
     * @param destination The destination address of the packet
     * @return int 0 if successful
     */
    int ReceivePacket(Ptr<Packet> packetIn,
                      int inPort,
                      uint16_t protocol,
                      const Address& destination) override;

    /**
     * @brief Notified of a config swap
     */
    void swap_notify_() override;

    /**
     * @brief Start the switch and return
     * Set the scheduler time with the switch rate
     */
    void start_and_return_() override;

    /**
     * @brief Reset the target state
     */
    void reset_target_state_() override;

    /**
     * @brief Handle the ingress pipeline
     */
    void HandleIngressPipeline() override;

    /**
     * @brief Enqueue a packet to the queue buffer between ingress and egress
     * @param egress_port The egress port of the packet
     * @param packet The packet to be enqueued
     * @return void
     */
    void Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet) override;

    /**
     * @brief Handle the egress pipeline
     * @param workerId The worker ID of the egress pipeline
     * @return bool True if the egress pipeline is handled successfully
     * @return bool False if the egress pipeline needs additional scheduling
     */
    bool HandleEgressPipeline(size_t workerId) override;

    /**
     * @brief Calculate the schedule time for the egress pipeline
     */
    void CalculateScheduleTime();

    /**
     * @brief Per-interval statistics logging callback.
     */
    void CalculatePacketsPerSecond();

    /**
     * @brief [Legacy / polling] Periodic egress drain callback.
     * @deprecated Replaced by the event-driven scheduler. Kept for reference
     * and may be removed in a future clean-up.
     */
    void SetEgressTimerEvent();

    // ---- Event-driven scheduler ----

    /**
     * @brief Attempt to dequeue and process one packet from the egress buffer.
     *
     * This is the core of the event-driven scheduler. It is invoked:
     *  - immediately after a packet is enqueued into a previously-empty queue
     *    (via ScheduleEgressIfNeeded()), and
     *  - after the output-port transmission of the previous packet completes
     *    (via PortTxComplete()).
     *
     * If a packet is eligible right now (its rate-limit timestamp has passed and
     * the output port is free), it is dequeued and processed through the egress
     * pipeline. Otherwise the next wake-up time is computed and a new event is
     * scheduled at that time.
     *
     * @param port  The egress port for which dequeue is being attempted.
     *              Pass UINT32_MAX to attempt a sweep across all ports (used when
     *              the caller does not know which port will be eligible first).
     */
    void EventDrivenEgressDequeue(uint32_t port);

    /**
     * @brief Schedule an egress-dequeue event for @p port if none is pending.
     *
     * Called from Enqueue() whenever a packet is placed into a queue.
     * If the output port is currently idle and no dequeue event is already
     * pending for that port, a new EventDrivenEgressDequeue event is scheduled
     * at the earliest time the queue's rate constraint is satisfied.
     *
     * @param port  The egress port that just received a new packet.
     */
    void ScheduleEgressIfNeeded(uint32_t port);

    /**
     * @brief Callback invoked when the link transmission of a packet finishes.
     *
     * Models the output-port serialization delay: the port is marked free and
     * EventDrivenEgressDequeue() is called to transmit the next waiting packet.
     *
     * @param port  The egress port whose transmission just completed.
     */
    void PortTxComplete(uint32_t port);

    /**
     * @brief Multicast a packet to a multicast group ID
     * @param packet The packet to be multicast
     * @param mgid The multicast group ID
     */
    void MulticastPacket(bm::Packet* packet, unsigned int mgid);

    /**
     * @brief Used for ingress cloning, resubmit
     */
    void CopyFieldList(const std::unique_ptr<bm::Packet>& packet,
                       const std::unique_ptr<bm::Packet>& packetCopy,
                       PktInstanceTypeV1model copyType,
                       int fieldListId);

    /**
     * @brief Set the depth of a priority queue
     * @param port The egress port
     * @param priority The priority of the queue
     * @param depthPkts The depth of the queue in packets
     * @return int 0 if successful
     */
    int SetEgressPriorityQueueDepth(size_t port, size_t priority, size_t depthPkts);

    /**
     * @brief Set the depth of a queue
     * @param port The egress port
     * @param depthPkts The depth of the queue in packets
     * @return int 0 if successful
     */
    int SetEgressQueueDepth(size_t port, size_t depthPkts);

    /**
     * @brief Set the depth of all queues
     * @param depthPkts The depth of the queue in packets
     * @return int 0 if successful
     */
    int SetAllEgressQueueDepths(size_t depthPkts);

    /**
     * @brief Set the rate of a priority queue
     * @param port The egress port
     * @param priority The priority of the queue
     * @param ratePps The rate of the queue in packets per second
     * @return int 0 if successful
     */
    int SetEgressPriorityQueueRate(size_t port, size_t priority, uint64_t ratePps);

    /**
     * @brief Set the rate of a virtual queue
     * @param port The egress port
     * @param ratePps The rate of the queue in packets per second
     * @return int 0 if successful
     */
    int SetEgressQueueRate(size_t port, uint64_t ratePps);

    /**
     * @brief Set the rate of all virtual queues
     * @param ratePps The rate of the queue in packets per second
     * @return int 0 if successful
     */
    int SetAllEgressQueueRates(uint64_t ratePps);

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
     * @brief Loads a new runtime configuration from a JSON string.
     * @param newConfig JSON string containing the new configuration.
     * @return 0 on success, -1 on failure.
     */
    int LoadNewConfig(const std::string& newConfig);

    /**
     * @brief Swaps the currently active configuration with a newly loaded one.
     * @return 0 on success, -1 on failure.
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

  protected:
    /**
     * @brief The egress thread mapper for dequeue process of queue buffer
     * bmv2 using 4u default, in ns-3 only single thread for processing
     */
    struct EgressThreadMapper
    {
        explicit EgressThreadMapper(size_t nb_threads)
            : nb_threads(nb_threads)
        {
        }

        size_t operator()(size_t egress_port) const
        {
            return egress_port % nb_threads;
        }

        size_t nb_threads;
    };

  private:
    uint64_t m_packetId;
    uint64_t m_switchRate;

    // enable tracing
    uint64_t m_inputBps;  // bps
    uint64_t m_inputBp;   // bp
    uint64_t m_inputPps;  // pps
    uint64_t m_inputPp;   // pp
    uint64_t m_egressBps; // bps
    uint64_t m_egressBp;  // bp
    uint64_t m_egressPps; // pps
    uint64_t m_egressPp;  // pp

    Time m_timeInterval;       // s
    double m_virtualQueueRate; // pps

    size_t m_nbQueuesPerPort;
    EventId m_egressTimeEvent; //!< Legacy polling event (unused in event-driven mode)
    Time m_egressTimeRef;      //!< Inter-packet gap derived from m_switchRate
    uint64_t m_startTimestamp; //!< Start time of the switch

    static constexpr size_t m_nbEgressThreads = 1u; // 4u default in bmv2

    std::unique_ptr<InputBuffer> input_buffer;
    NSQueueingLogicPriRL<std::unique_ptr<bm::Packet>, EgressThreadMapper> egress_buffer;
    bm::Queue<std::unique_ptr<bm::Packet>> output_buffer;

    bool m_firstPacket;

    // ---- Event-driven scheduler state ----

    /**
     * @brief Per-port transmission state for event-driven scheduling.
     *
     * busy      : true while a packet is being serialised on the link.
     * busyUntil : the simulation time at which the link becomes free again.
     * pendingEvent : the ns-3 EventId of the next scheduled dequeue attempt
     *                for this port; allows cancellation when a new packet
     *                arrives earlier.
     */
    struct PortTxState
    {
        bool busy{false};
        Time busyUntil{Time(0)};
        EventId pendingEvent{};
    };

    /// Indexed by egress port number; created on first use in ScheduleEgressIfNeeded().
    std::unordered_map<uint32_t, PortTxState> m_portTxState;

    /**
     * @brief Link rate used for transmission-delay modelling (bits per second).
     *
     * Set in CalculateScheduleTime() from m_switchRate and the per-port data
     * rate obtained from the underlying NetDevice (when available). Falls back
     * to a default of 1 Gbps.
     */
    uint64_t m_linkRateBps{1000000000ULL}; // default 1 Gbps
};

} // namespace ns3

#endif // P4_CORE_V1MODEL_H
