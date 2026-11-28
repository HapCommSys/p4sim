// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

#ifndef P4SIM_P4_LEARNING_TABLE_H
#define P4SIM_P4_LEARNING_TABLE_H

#include "ns3/event-id.h"
#include "ns3/nstime.h"
#include "ns3/p4-digest.h"

#include <bm/bm_sim/match_tables.h>
#include <map>
#include <string>
#include <vector>

namespace ns3
{

class P4SwitchCore;

/**
 * \ingroup p4sim
 * \brief A table of the P4 program that the switch fills from its digests, with
 * the limits of a target: capacity, eviction, aging and the learning path
 * (doc/latency-model.md)
 *
 * Each digest of the P4 program gives one entry: its first field is the key of
 * an exact-match table, its other fields the parameters of an action. A key
 * that the table holds is refreshed (and gets the new parameters); a new key
 * takes a free entry or, in a full table that evicts, replaces the entry
 * refreshed least recently. The table is full at the target's capacity or
 * when the P4 table is, whichever comes first. An entry that is not refreshed
 * for the lifetime is removed. On the data-plane path the entry is installed
 * when the switch processes the digest, so the next frame sees it; on the
 * control-plane path, the control-plane delay later.
 */
class P4LearningTable
{
  public:
    /// What to learn into, and the target's limits
    struct Config
    {
        std::string table;       ///< the exact-match table
        std::string action;      ///< the action of its entries
        uint32_t capacity{0};    ///< entries; 0: the P4 table's size alone
        bool evictOldest{false}; ///< a full table replaces its oldest entry
        Time lifetime;           ///< 0: entries do not age
        bool dataPlane{true};    ///< false: installed after controlPlaneDelay
        Time controlPlaneDelay;  ///< digest to installed entry, on the control-plane path
    };

    /**
     * \param core the switch
     * \param config the table and the limits
     */
    P4LearningTable(P4SwitchCore& core, const Config& config);
    ~P4LearningTable();

    /**
     * \brief Learn from a digest of the P4 program
     * \param digest the digest
     */
    void OnDigest(const P4Digest& digest);

    /// \return the number of entries the table holds
    uint32_t GetNEntries() const;

    /**
     * \brief The parameters of the entry of a key
     * \param key the key, as the digest gives it (bytes, most significant first)
     * \param[out] params the action parameters
     * \return whether the table holds the key
     */
    bool Lookup(const std::string& key, std::vector<std::string>* params) const;

    /// \return the entries replaced because the table was full
    uint64_t GetNEvictions() const;

    /**
     * \return the digests not learned: the table was full and does not evict,
     * or BMv2 did not take the entry
     */
    uint64_t GetNRejected() const;

    /**
     * \brief Forget the learned entries, without removing them from BMv2: the
     * switch swapped its P4 program, whose tables start empty. Digests on
     * their way (control-plane path) are still installed, in the new table.
     */
    void Forget();

    P4LearningTable(const P4LearningTable&) = delete;
    P4LearningTable& operator=(const P4LearningTable&) = delete;

  private:
    /// One entry
    struct Entry
    {
        std::vector<std::string> params; ///< the action parameters
        bm::entry_handle_t handle{0};    ///< its handle in the BMv2 table
        Time lastSeen;                   ///< when it was installed or refreshed
        EventId expiry;                  ///< its aging
    };

    /// Install or refresh the entry of a digest
    void Apply(const P4Digest& digest);

    /// \return the action data of \p params
    static bm::ActionData MakeActionData(const std::vector<std::string>& params);

    /// Add the entry of \p key to the BMv2 table
    bm::MatchErrorCode Add(const std::string& key,
                           const std::vector<std::string>& params,
                           bm::entry_handle_t* handle);

    /// Replace: remove the entry refreshed least recently
    void EvictOldest();

    /// Remove an entry
    void Remove(const std::string& key);

    /// Remove an entry if it has not been refreshed for the lifetime
    void Age(const std::string& key);

    /// (Re)start the aging of an entry
    void StartAging(const std::string& key, Entry& entry);

    P4SwitchCore& m_core;                   ///< the switch
    Config m_config;                        ///< the table and the limits
    std::map<std::string, Entry> m_entries; ///< by key
    std::vector<EventId> m_pending;         ///< digests on their way (control-plane path)
    uint64_t m_evictions{0};                ///< see GetNEvictions()
    uint64_t m_rejected{0};                 ///< see GetNRejected()
};

} // namespace ns3

#endif // P4SIM_P4_LEARNING_TABLE_H
