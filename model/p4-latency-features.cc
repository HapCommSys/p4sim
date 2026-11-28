// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

#include "ns3/p4-latency-features.h"

#include "ns3/bm-event-observer.h"
#include "ns3/log.h"

#include <algorithm>
#include <bm/bm_sim/match_tables.h>
#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/pipeline.h>
#include <fstream>
#include <json/json.h>
#include <sstream>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("P4LatencyFeatures");

bool
P4LatencyFeatures::LoadFile(const std::string& path, std::string* error)
{
    std::ifstream file(path);
    if (!file)
    {
        *error = "cannot open " + path;
        return false;
    }
    std::stringstream text;
    text << file.rdbuf();
    return Load(text.str(), error);
}

bool
P4LatencyFeatures::Load(const std::string& jsonText, std::string* error)
{
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream text(jsonText);
    if (!Json::parseFromStream(builder, text, &root, &errors) || !root.isObject())
    {
        *error = "not a BMv2 JSON: " + errors;
        return false;
    }
    m_headerNames.clear();
    m_headerBytes.clear();
    m_headerStacks.clear();
    m_parseStates.clear();
    m_tables.clear();

    // Header types: the width of each field (a varbit field counts 0 bits)
    std::map<std::string, std::map<std::string, uint32_t>> fieldBits;
    std::map<std::string, uint32_t> typeBits;
    for (const Json::Value& type : root["header_types"])
    {
        std::string typeName = type["name"].asString();
        uint32_t total = 0;
        for (const Json::Value& field : type["fields"])
        {
            uint32_t bits = field[1].isIntegral() ? field[1].asUInt() : 0;
            fieldBits[typeName][field[0].asString()] = bits;
            total += bits;
        }
        typeBits[typeName] = total;
    }
    // Headers and their types
    std::map<std::string, std::string> headerTypes;
    for (const Json::Value& header : root["headers"])
    {
        int id = header["id"].asInt();
        std::string name = header["name"].asString();
        std::string type = header["header_type"].asString();
        m_headerNames[id] = name;
        m_headerBytes[id] = (typeBits[type] + 7) / 8;
        headerTypes[name] = type;
    }
    for (const Json::Value& stack : root["header_stacks"])
    {
        for (const Json::Value& id : stack["header_ids"])
        {
            m_headerStacks[id.asInt()] = stack["name"].asString();
        }
    }
    // Parse states: the headers (or stacks, for extracting the next element) they extract
    for (const Json::Value& parser : root["parsers"])
    {
        for (const Json::Value& state : parser["parse_states"])
        {
            ParseState s;
            s.parser = parser["name"].asString();
            s.name = state["name"].asString();
            for (const Json::Value& op : state["parser_ops"])
            {
                std::string kind = op["op"].asString();
                if ((kind == "extract" || kind == "extract_VL") && !op["parameters"].empty())
                {
                    s.extracts.push_back(op["parameters"][0]["value"].asString());
                }
            }
            m_parseStates.push_back(s);
        }
    }
    // Tables: match type, number of keys and their total width
    for (const Json::Value& pipeline : root["pipelines"])
    {
        for (const Json::Value& table : pipeline["tables"])
        {
            LatencyTableFeature t;
            t.name = table["name"].asString();
            t.matchType = table["match_type"].asString();
            for (const Json::Value& key : table["key"])
            {
                t.keyCount++;
                const Json::Value& target = key["target"];
                if (target.isArray() && target.size() == 2)
                {
                    const std::string& type = headerTypes[target[0].asString()];
                    auto field = fieldBits[type].find(target[1].asString());
                    if (field != fieldBits[type].end())
                    {
                        t.keyBits += field->second;
                    }
                    else if (target[1].asString() == "$valid$")
                    {
                        t.keyBits += 1;
                    }
                }
                else
                {
                    t.keyBits += 1; // a validity key on a header
                }
            }
            m_tables.push_back(t);
        }
    }
    return true;
}

const std::vector<P4LatencyFeatures::ParseState>&
P4LatencyFeatures::GetParseStates() const
{
    return m_parseStates;
}

const std::vector<LatencyTableFeature>&
P4LatencyFeatures::GetTables() const
{
    return m_tables;
}

const LatencyTableFeature*
P4LatencyFeatures::FindTable(const std::string& name) const
{
    for (const LatencyTableFeature& table : m_tables)
    {
        if (table.name == name)
        {
            return &table;
        }
    }
    return nullptr;
}

uint32_t
P4LatencyFeatures::GetHeaderBytes(int headerId) const
{
    auto it = m_headerBytes.find(headerId);
    return it == m_headerBytes.end() ? 0 : it->second;
}

std::string
P4LatencyFeatures::ExtractTarget(int headerId) const
{
    auto stack = m_headerStacks.find(headerId);
    if (stack != m_headerStacks.end())
    {
        return stack->second;
    }
    auto header = m_headerNames.find(headerId);
    return header == m_headerNames.end() ? "" : header->second;
}

std::vector<uint32_t>
P4LatencyFeatures::GetStateBytes(const std::string& parser, const std::vector<int>& headerIds) const
{
    std::vector<std::string> targets;
    for (int id : headerIds)
    {
        targets.push_back(ExtractTarget(id));
    }
    std::vector<uint32_t> states;
    size_t i = 0;
    while (i < targets.size())
    {
        // The longest state of this parser whose extracts are the next headers
        size_t visit = 1;
        for (const ParseState& state : m_parseStates)
        {
            const std::vector<std::string>& extracts = state.extracts;
            if (state.parser != parser || extracts.size() <= visit ||
                i + extracts.size() > targets.size())
            {
                continue;
            }
            if (std::equal(extracts.begin(), extracts.end(), targets.begin() + i))
            {
                visit = extracts.size();
            }
        }
        uint32_t bytes = 0;
        for (size_t j = i; j < i + visit; j++)
        {
            bytes += GetHeaderBytes(headerIds[j]);
        }
        states.push_back(bytes);
        i += visit;
    }
    return states;
}

std::vector<LatencyTableFeature>
P4LatencyFeatures::GetTableFeatures(const std::vector<std::string>& tableNames,
                                    std::vector<std::string>* unknown) const
{
    std::vector<LatencyTableFeature> features;
    for (const std::string& name : tableNames)
    {
        const LatencyTableFeature* table = FindTable(name);
        if (table && table->keyCount == 0)
        {
            continue; // no lookup: p4c's tbl_* tables run the actions of the control
        }
        if (table)
        {
            features.push_back(*table);
        }
        else
        {
            unknown->push_back(name);
        }
    }
    return features;
}

namespace
{

/// What the collector of this thread listens for
struct Collection
{
    PacketLatencyFeatures* features{nullptr}; ///< where to collect
    std::string parser;                       ///< the ingress parser
    std::string pipeline;                     ///< the ingress control
    bool inParser{false};                     ///< between parser_start and parser_done
    bool inPipeline{false};                   ///< between pipeline_start and pipeline_done
};

/// The collection of this thread, while a LatencyFeatureCollector is active
thread_local Collection* g_collection = nullptr;

/// Passes BMv2's pipeline events to the collection of the thread
class LatencyEventObserver : public bm::EventObserverIface
{
  public:
    void packet_in(const bm::Packet&) override
    {
    }

    void packet_out(const bm::Packet&) override
    {
    }

    void parser_start(const bm::Packet&, const bm::Parser& parser) override
    {
        if (g_collection)
        {
            g_collection->inParser = parser.get_name() == g_collection->parser;
        }
    }

    void parser_done(const bm::Packet&, const bm::Parser&) override
    {
        if (g_collection)
        {
            g_collection->inParser = false;
        }
    }

    void parser_extract(const bm::Packet&, bm::header_id_t header) override
    {
        if (g_collection && g_collection->inParser)
        {
            g_collection->features->extractedHeaders.push_back(static_cast<int>(header));
        }
    }

    void deparser_start(const bm::Packet&, const bm::Deparser&) override
    {
    }

    void deparser_done(const bm::Packet&, const bm::Deparser&) override
    {
    }

    void deparser_emit(const bm::Packet&, bm::header_id_t) override
    {
    }

    void checksum_update(const bm::Packet&, const bm::Checksum&) override
    {
    }

    void pipeline_start(const bm::Packet&, const bm::Pipeline& pipeline) override
    {
        if (g_collection)
        {
            g_collection->inPipeline = pipeline.get_name() == g_collection->pipeline;
        }
    }

    void pipeline_done(const bm::Packet&, const bm::Pipeline&) override
    {
        if (g_collection)
        {
            g_collection->inPipeline = false;
        }
    }

    void condition_eval(const bm::Packet&, const bm::Conditional&, bool) override
    {
    }

    void table_hit(const bm::Packet&,
                   const bm::MatchTableAbstract& table,
                   bm::entry_handle_t) override
    {
        if (g_collection && g_collection->inPipeline)
        {
            g_collection->features->hitTables.push_back(table.get_name());
        }
    }

    void table_miss(const bm::Packet&, const bm::MatchTableAbstract& table) override
    {
        if (g_collection && g_collection->inPipeline)
        {
            g_collection->features->missedTables.push_back(table.get_name());
        }
    }

    void action_execute(const bm::Packet&, const bm::ActionFn&, const bm::ActionData&) override
    {
    }

    void config_change() override
    {
    }
};

/// Registers the observer once; BMv2 has no way to remove it, so it lives as long as the process
void
RegisterObserver()
{
    static LatencyEventObserver observer;
    static bool registered = false;
    if (!registered)
    {
        bm::EventObserverRegistry::get()->register_observer(&observer);
        registered = true;
    }
}

} // namespace

LatencyFeatureCollector::LatencyFeatureCollector(PacketLatencyFeatures* features,
                                                 const std::string& parser,
                                                 const std::string& pipeline)
{
    RegisterObserver();
    // A resubmitted packet passes the ingress again while the first pass is
    // still on the stack: this collection replaces the earlier one until it stops
    m_previous = g_collection;
    g_collection = new Collection{features, parser, pipeline};
}

LatencyFeatureCollector::~LatencyFeatureCollector()
{
    Stop();
}

void
LatencyFeatureCollector::Stop()
{
    if (m_active)
    {
        delete g_collection;
        g_collection = static_cast<Collection*>(m_previous);
        m_active = false;
    }
}

bool
LatencyFeatureCollector::EventsAvailable()
{
#ifdef BM_ELOG_ON
    return true;
#else
    return false;
#endif
}

} // namespace ns3
