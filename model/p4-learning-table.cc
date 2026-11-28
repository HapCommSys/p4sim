// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

#include "ns3/p4-learning-table.h"

#include "ns3/log.h"
#include "ns3/p4-runtime-api.h"
#include "ns3/p4-switch-core.h"
#include "ns3/p4sim-ns3-compat.h"
#include "ns3/simulator.h"

#include <algorithm>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("P4LearningTable");

P4LearningTable::P4LearningTable(P4SwitchCore& core, const Config& config)
    : m_core(core),
      m_config(config)
{
}

P4LearningTable::~P4LearningTable()
{
    for (auto& [key, entry] : m_entries)
    {
        Simulator::Cancel(entry.expiry);
    }
    for (EventId& event : m_pending)
    {
        Simulator::Cancel(event);
    }
}

void
P4LearningTable::OnDigest(const P4Digest& digest)
{
    if (digest.fields.size() < 2)
    {
        NS_LOG_WARN("Digest " << digest.listName << " has no field for the action; not learned");
        return;
    }
    if (m_config.dataPlane)
    {
        Apply(digest);
        return;
    }
    m_pending.erase(std::remove_if(m_pending.begin(),
                                   m_pending.end(),
                                   [](const EventId& event) { return !P4simIsPending(event); }),
                    m_pending.end());
    m_pending.push_back(
        Simulator::Schedule(m_config.controlPlaneDelay, &P4LearningTable::Apply, this, digest));
}

void
P4LearningTable::Apply(const P4Digest& digest)
{
    const std::string& key = digest.fields.front().value;
    std::vector<std::string> params;
    for (size_t i = 1; i < digest.fields.size(); i++)
    {
        params.push_back(digest.fields[i].value);
    }

    auto known = m_entries.find(key);
    if (known != m_entries.end())
    {
        // A known address: refresh its age and, if it moved, its parameters
        if (known->second.params != params)
        {
            if (P4RuntimeApi(m_core).ModifyFlowEntry(m_config.table,
                                                     known->second.handle,
                                                     m_config.action,
                                                     MakeActionData(params)) != 0)
            {
                NS_LOG_WARN("Cannot change the entry of a learned key in " << m_config.table);
            }
            known->second.params = params;
        }
        known->second.lastSeen = Simulator::Now();
        StartAging(key, known->second);
        return;
    }

    if (m_config.capacity > 0 && m_entries.size() >= m_config.capacity)
    {
        if (!m_config.evictOldest)
        {
            m_rejected++;
            return;
        }
        EvictOldest();
    }

    Entry entry;
    entry.params = params;
    entry.lastSeen = Simulator::Now();
    bm::MatchErrorCode rc = Add(key, params, &entry.handle);
    if (rc == bm::MatchErrorCode::TABLE_FULL && m_config.evictOldest && !m_entries.empty())
    {
        // The P4 table is full before the target's capacity, or the target
        // gives none: it limits the learning table
        EvictOldest();
        rc = Add(key, params, &entry.handle);
    }
    if (rc != bm::MatchErrorCode::SUCCESS)
    {
        m_rejected++;
        NS_LOG_WARN("Cannot add a learned entry to " << m_config.table << " (BMv2 error "
                                                     << static_cast<int>(rc) << ")");
        return;
    }
    StartAging(key, m_entries.emplace(key, entry).first->second);
}

bm::ActionData
P4LearningTable::MakeActionData(const std::vector<std::string>& params)
{
    bm::ActionData data;
    for (const std::string& param : params)
    {
        data.push_back_action_data(param.data(), static_cast<int>(param.size()));
    }
    return data;
}

bm::MatchErrorCode
P4LearningTable::Add(const std::string& key,
                     const std::vector<std::string>& params,
                     bm::entry_handle_t* handle)
{
    std::vector<bm::MatchKeyParam> match = {bm::MatchKeyParam(bm::MatchKeyParam::Type::EXACT, key)};
    return m_core
        .mt_add_entry(0, m_config.table, match, m_config.action, MakeActionData(params), handle);
}

void
P4LearningTable::EvictOldest()
{
    auto oldest = m_entries.begin();
    for (auto it = m_entries.begin(); it != m_entries.end(); ++it)
    {
        if (it->second.lastSeen < oldest->second.lastSeen)
        {
            oldest = it;
        }
    }
    if (oldest != m_entries.end())
    {
        m_evictions++;
        Remove(oldest->first);
    }
}

void
P4LearningTable::Forget()
{
    for (auto& [key, entry] : m_entries)
    {
        Simulator::Cancel(entry.expiry);
    }
    m_entries.clear();
}

void
P4LearningTable::StartAging(const std::string& key, Entry& entry)
{
    Simulator::Cancel(entry.expiry);
    if (m_config.lifetime.IsStrictlyPositive())
    {
        entry.expiry = Simulator::Schedule(m_config.lifetime, &P4LearningTable::Age, this, key);
    }
}

void
P4LearningTable::Age(const std::string& key)
{
    auto it = m_entries.find(key);
    if (it != m_entries.end() && Simulator::Now() - it->second.lastSeen >= m_config.lifetime)
    {
        Remove(key);
    }
}

void
P4LearningTable::Remove(const std::string& key)
{
    auto it = m_entries.find(key);
    if (it == m_entries.end())
    {
        return;
    }
    Simulator::Cancel(it->second.expiry);
    P4RuntimeApi api(m_core);
    if (api.DeleteFlowEntry(m_config.table, it->second.handle) != 0)
    {
        NS_LOG_WARN("Cannot remove a learned entry from " << m_config.table);
    }
    m_entries.erase(it);
}

uint32_t
P4LearningTable::GetNEntries() const
{
    return static_cast<uint32_t>(m_entries.size());
}

bool
P4LearningTable::Lookup(const std::string& key, std::vector<std::string>* params) const
{
    auto it = m_entries.find(key);
    if (it == m_entries.end())
    {
        return false;
    }
    *params = it->second.params;
    return true;
}

uint64_t
P4LearningTable::GetNEvictions() const
{
    return m_evictions;
}

uint64_t
P4LearningTable::GetNRejected() const
{
    return m_rejected;
}

} // namespace ns3
