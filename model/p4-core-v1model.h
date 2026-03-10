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

#include <bm/bm_sim/counters.h>
#include <unordered_map>

#define SSWITCH_VIRTUAL_QUEUE_NUM_V1MODEL 8

namespace ns3
{

class P4CoreV1model : public P4SwitchCore
{
  public:
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
     * @brief Packet instance types used to distinguish processing paths.
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

    // === Packet Processing (P4SwitchCore overrides) ===
    int ReceivePacket(Ptr<Packet> packetIn,
                      int inPort,
                      uint16_t protocol,
                      const Address& destination) override;
    void swap_notify_() override;
    void start_and_return_() override;
    void reset_target_state_() override;
    void HandleIngressPipeline() override;
    void Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet) override;
    bool HandleEgressPipeline(size_t workerId) override;

    // === Scheduling ===
    void CalculateScheduleTime();
    void CalculatePacketsPerSecond();
    /** @deprecated Legacy polling callback – superseded by event-driven scheduler. */
    void SetEgressTimerEvent();
    void EventDrivenEgressDequeue(uint32_t port);
    void ScheduleEgressIfNeeded(uint32_t port);
    void PortTxComplete(uint32_t port);

    // === Internal helpers ===
    void MulticastPacket(bm::Packet* packet, unsigned int mgid);
    void CopyFieldList(const std::unique_ptr<bm::Packet>& packet,
                       const std::unique_ptr<bm::Packet>& packetCopy,
                       PktInstanceTypeV1model copyType,
                       int fieldListId);

    // === Queue configuration ===
    int SetEgressPriorityQueueDepth(size_t port, size_t priority, size_t depthPkts);
    int SetEgressQueueDepth(size_t port, size_t depthPkts);
    int SetAllEgressQueueDepths(size_t depthPkts);
    int SetEgressPriorityQueueRate(size_t port, size_t priority, uint64_t ratePps);
    int SetEgressQueueRate(size_t port, uint64_t ratePps);
    int SetAllEgressQueueRates(uint64_t ratePps);

    // =========================================================
    // Controller API – match/action table management
    // (called by P4Controller; wraps bm::SwitchWContexts methods)
    // =========================================================

    // --- Direct match tables ---
    int GetNumEntries(const std::string& tableName);
    int ClearFlowTableEntries(const std::string& tableName, bool resetDefault);
    int AddFlowEntry(const std::string& tableName,
                     const std::vector<bm::MatchKeyParam>& matchKey,
                     const std::string& actionName,
                     bm::ActionData&& actionData,
                     bm::entry_handle_t* handle,
                     int priority = -1);
    int SetDefaultAction(const std::string& tableName,
                         const std::string& actionName,
                         bm::ActionData&& actionData);
    int ResetDefaultEntry(const std::string& tableName);
    int DeleteFlowEntry(const std::string& tableName, bm::entry_handle_t handle);
    int ModifyFlowEntry(const std::string& tableName,
                        bm::entry_handle_t handle,
                        const std::string& actionName,
                        bm::ActionData actionData);
    int SetEntryTtl(const std::string& tableName, bm::entry_handle_t handle, unsigned int ttlMs);

    // --- Action profiles ---
    int AddActionProfileMember(const std::string& profileName,
                               const std::string& actionName,
                               bm::ActionData&& actionData,
                               bm::ActionProfile::mbr_hdl_t* outHandle);
    int DeleteActionProfileMember(const std::string& profileName,
                                  bm::ActionProfile::mbr_hdl_t memberHandle);
    int ModifyActionProfileMember(const std::string& profileName,
                                  bm::ActionProfile::mbr_hdl_t memberHandle,
                                  const std::string& actionName,
                                  bm::ActionData&& actionData);
    int CreateActionProfileGroup(const std::string& profileName,
                                 bm::ActionProfile::grp_hdl_t* outHandle);
    int DeleteActionProfileGroup(const std::string& profileName,
                                 bm::ActionProfile::grp_hdl_t groupHandle);
    int AddMemberToGroup(const std::string& profileName,
                         bm::ActionProfile::mbr_hdl_t memberHandle,
                         bm::ActionProfile::grp_hdl_t groupHandle);
    int RemoveMemberFromGroup(const std::string& profileName,
                              bm::ActionProfile::mbr_hdl_t memberHandle,
                              bm::ActionProfile::grp_hdl_t groupHandle);
    int GetActionProfileMembers(const std::string& profileName,
                                std::vector<bm::ActionProfile::Member>* members);
    int GetActionProfileMember(const std::string& profileName,
                               bm::ActionProfile::mbr_hdl_t memberHandle,
                               bm::ActionProfile::Member* member);
    int GetActionProfileGroups(const std::string& profileName,
                               std::vector<bm::ActionProfile::Group>* groups);
    int GetActionProfileGroup(const std::string& profileName,
                              bm::ActionProfile::grp_hdl_t groupHandle,
                              bm::ActionProfile::Group* group);

    // --- Indirect tables ---
    int AddIndirectEntry(const std::string& tableName,
                         const std::vector<bm::MatchKeyParam>& matchKey,
                         bm::ActionProfile::mbr_hdl_t memberHandle,
                         bm::entry_handle_t* outHandle,
                         int priority = 1);
    int ModifyIndirectEntry(const std::string& tableName,
                            bm::entry_handle_t entryHandle,
                            bm::ActionProfile::mbr_hdl_t memberHandle);
    int DeleteIndirectEntry(const std::string& tableName, bm::entry_handle_t entryHandle);
    int SetIndirectEntryTtl(const std::string& tableName,
                            bm::entry_handle_t handle,
                            unsigned int ttlMs);
    int SetIndirectDefaultMember(const std::string& tableName,
                                 bm::ActionProfile::mbr_hdl_t memberHandle);
    int ResetIndirectDefaultEntry(const std::string& tableName);
    int AddIndirectWsEntry(const std::string& tableName,
                           const std::vector<bm::MatchKeyParam>& matchKey,
                           bm::ActionProfile::grp_hdl_t groupHandle,
                           bm::entry_handle_t* outHandle,
                           int priority = 1);
    int ModifyIndirectWsEntry(const std::string& tableName,
                              bm::entry_handle_t handle,
                              bm::ActionProfile::grp_hdl_t groupHandle);
    int SetIndirectWsDefaultGroup(const std::string& tableName,
                                  bm::ActionProfile::grp_hdl_t groupHandle);

    // --- Entry retrieval ---
    std::vector<bm::MatchTable::Entry> GetFlowEntries(const std::string& tableName);
    std::vector<bm::MatchTableIndirect::Entry> GetIndirectFlowEntries(const std::string& tableName);
    std::vector<bm::MatchTableIndirectWS::Entry> GetIndirectWsFlowEntries(
        const std::string& tableName);
    int GetEntry(const std::string& tableName,
                 bm::entry_handle_t handle,
                 bm::MatchTable::Entry* entry);
    int GetIndirectEntry(const std::string& tableName,
                         bm::entry_handle_t handle,
                         bm::MatchTableIndirect::Entry* entry);
    int GetIndirectWsEntry(const std::string& tableName,
                           bm::entry_handle_t handle,
                           bm::MatchTableIndirectWS::Entry* entry);
    int GetDefaultEntry(const std::string& tableName, bm::MatchTable::Entry* entry);
    int GetIndirectDefaultEntry(const std::string& tableName, bm::MatchTableIndirect::Entry* entry);
    int GetIndirectWsDefaultEntry(const std::string& tableName,
                                  bm::MatchTableIndirectWS::Entry* entry);
    int GetEntryFromKey(const std::string& tableName,
                        const std::vector<bm::MatchKeyParam>& matchKey,
                        bm::MatchTable::Entry* entry,
                        int priority = 1);
    int GetIndirectEntryFromKey(const std::string& tableName,
                                const std::vector<bm::MatchKeyParam>& matchKey,
                                bm::MatchTableIndirect::Entry* entry,
                                int priority = 1);
    int GetIndirectWsEntryFromKey(const std::string& tableName,
                                  const std::vector<bm::MatchKeyParam>& matchKey,
                                  bm::MatchTableIndirectWS::Entry* entry,
                                  int priority = 1);

    // --- Counters ---
    int ReadTableCounters(const std::string& tableName,
                          bm::entry_handle_t handle,
                          uint64_t* bytes,
                          uint64_t* packets);
    int ResetTableCounters(const std::string& tableName);
    int WriteTableCounters(const std::string& tableName,
                           bm::entry_handle_t handle,
                           uint64_t bytes,
                           uint64_t packets);
    int ReadCounter(const std::string& counterName,
                    size_t index,
                    bm::MatchTableAbstract::counter_value_t* bytes,
                    bm::MatchTableAbstract::counter_value_t* packets);
    int ResetCounter(const std::string& counterName);
    int WriteCounter(const std::string& counterName,
                     size_t index,
                     bm::MatchTableAbstract::counter_value_t bytes,
                     bm::MatchTableAbstract::counter_value_t packets);

    // --- Meters ---
    int SetMeterRates(const std::string& tableName,
                      bm::entry_handle_t handle,
                      const std::vector<bm::Meter::rate_config_t>& configs);
    int GetMeterRates(const std::string& tableName,
                      bm::entry_handle_t handle,
                      std::vector<bm::Meter::rate_config_t>* configs);
    int ResetMeterRates(const std::string& tableName, bm::entry_handle_t handle);
    int SetMeterArrayRates(const std::string& meterName,
                           const std::vector<bm::Meter::rate_config_t>& configs);
    int MeterSetRates(const std::string& meterName,
                      size_t idx,
                      const std::vector<bm::Meter::rate_config_t>& configs);
    int MeterGetRates(const std::string& meterName,
                      size_t idx,
                      std::vector<bm::Meter::rate_config_t>* configs);
    int MeterResetRates(const std::string& meterName, size_t idx);

    // --- Registers ---
    int RegisterRead(const std::string& registerName, size_t index, bm::Data* value);
    int RegisterWrite(const std::string& registerName, size_t index, const bm::Data& value);
    std::vector<bm::Data> RegisterReadAll(const std::string& registerName);
    int RegisterWriteRange(const std::string& registerName,
                           size_t startIndex,
                           size_t endIndex,
                           const bm::Data& value);
    int RegisterReset(const std::string& registerName);

    // --- Parse value sets ---
    int ParseVsetAdd(const std::string& vsetName, const bm::ByteContainer& value);
    int ParseVsetRemove(const std::string& vsetName, const bm::ByteContainer& value);
    int ParseVsetGet(const std::string& vsetName, std::vector<bm::ByteContainer>* values);
    int ParseVsetClear(const std::string& vsetName);

    // --- Runtime state ---
    int ResetState();
    int Serialize(std::ostream* out);
    int LoadNewConfig(const std::string& newConfig);
    int SwapConfigs();
    int GetConfig(std::string* configOut);
    int GetConfigMd5(std::string* md5Out);

  protected:
    /**
     * @brief Maps an egress port to the worker thread index (single-threaded in ns-3).
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

    // Tracing statistics (per-interval counters)
    uint64_t m_inputBps;
    uint64_t m_inputBp;
    uint64_t m_inputPps;
    uint64_t m_inputPp;
    uint64_t m_egressBps;
    uint64_t m_egressBp;
    uint64_t m_egressPps;
    uint64_t m_egressPp;

    Time m_timeInterval;       ///< Statistics logging interval
    double m_virtualQueueRate; ///< Per-queue rate (pps)

    size_t m_nbQueuesPerPort;
    EventId m_egressTimeEvent; ///< Legacy polling event (unused in event-driven mode)
    Time m_egressTimeRef;      ///< Inter-packet gap derived from m_switchRate
    uint64_t m_startTimestamp; ///< Simulation start timestamp

    static constexpr size_t m_nbEgressThreads = 1u;

    std::unique_ptr<InputBuffer> input_buffer;
    NSQueueingLogicPriRL<std::unique_ptr<bm::Packet>, EgressThreadMapper> egress_buffer;
    bm::Queue<std::unique_ptr<bm::Packet>> output_buffer;

    bool m_firstPacket;

    // ---- Event-driven scheduler state ----

    /**
     * @brief Per-port transmission state.
     *
     * busy is set when a packet has been handed to the NetDevice and cleared
     * when the device signals PhyTxEnd via PortTxComplete().
     * pendingEvent allows cancellation of a stale dequeue timer.
     */
    struct PortTxState
    {
        bool busy{false};
        EventId pendingEvent{};
    };

    std::unordered_map<uint32_t, PortTxState> m_portTxState;

    /// Physical link rate read from port 0 at startup; used for logging/diagnostics only.
    /// Actual serialisation delay is now modelled by the port NetDevice itself.
    uint64_t m_linkRateBps{1000000000ULL};
};

} // namespace ns3

#endif // P4_CORE_V1MODEL_H
