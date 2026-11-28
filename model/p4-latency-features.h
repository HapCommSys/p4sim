// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

#ifndef P4SIM_P4_LATENCY_FEATURES_H
#define P4SIM_P4_LATENCY_FEATURES_H

#include "ns3/target-profile.h"

#include <map>
#include <string>
#include <vector>

namespace ns3
{

/**
 * \ingroup p4sim
 * \brief What one packet did in the ingress: the headers its ingress parser
 * extracted and the tables its ingress control applied
 *
 * LatencyFeatureCollector fills it from BMv2's pipeline events.
 */
struct PacketLatencyFeatures
{
    std::vector<int> extractedHeaders;     ///< header IDs, in the order of extraction
    std::vector<std::string> hitTables;    ///< tables that matched an entry, in order
    std::vector<std::string> missedTables; ///< tables applied without a match
};

/**
 * \ingroup p4sim
 * \brief The latency features of a compiled P4 program, read from its BMv2 JSON:
 * the parse states with the header bytes they extract, and the tables with
 * their match type, key width and key count
 */
class P4LatencyFeatures
{
  public:
    /// A parse state
    struct ParseState
    {
        std::string parser;                ///< the parser it belongs to
        std::string name;                  ///< its name
        std::vector<std::string> extracts; ///< headers or header stacks, in order
    };

    /**
     * \brief Read the features of a program
     * \param jsonText the BMv2 JSON
     * \param[out] error why it failed
     * \return whether the JSON could be read
     */
    bool Load(const std::string& jsonText, std::string* error);

    /**
     * \brief Read the features of a program from a file
     * \param path the BMv2 JSON file
     * \param[out] error why it failed
     * \return whether the file could be read
     */
    bool LoadFile(const std::string& path, std::string* error);

    /// \return the parse states of all parsers, in the order of the JSON
    const std::vector<ParseState>& GetParseStates() const;

    /// \return the tables of all pipelines, in the order of the JSON
    const std::vector<LatencyTableFeature>& GetTables() const;

    /**
     * \brief The features of a table
     * \param name the table
     * \return the table, or nullptr if the program has none of that name
     */
    const LatencyTableFeature* FindTable(const std::string& name) const;

    /**
     * \brief The size of a header in bytes
     * \param headerId its ID in the JSON
     * \return the bytes of its fixed-width fields; 0 for an unknown ID
     */
    uint32_t GetHeaderBytes(int headerId) const;

    /**
     * \brief The parse states that a packet visited, with the header bytes each
     * extracted, from the headers that its parser extracted
     *
     * BMv2 reports each extracted header, not each state: consecutive headers
     * that one state of \p parser extracts form one state visit; a header that
     * no state extracts as its first header is a visit of its own.
     *
     * \param parser the parser
     * \param headerIds the headers it extracted, in order
     * \return the bytes extracted in each state visit, in order
     */
    std::vector<uint32_t> GetStateBytes(const std::string& parser,
                                        const std::vector<int>& headerIds) const;

    /**
     * \brief The features of the tables a packet matched
     *
     * Tables without a key are left out: they look nothing up (p4c creates
     * them, named tbl_*, for the actions that a control calls directly).
     *
     * \param tableNames the tables, in order
     * \param[out] unknown the names of tables the program does not have
     * \return their features
     */
    std::vector<LatencyTableFeature> GetTableFeatures(const std::vector<std::string>& tableNames,
                                                      std::vector<std::string>* unknown) const;

  private:
    /// \return the name of the header or header stack that \p headerId belongs to
    std::string ExtractTarget(int headerId) const;

    std::map<int, std::string> m_headerNames;  ///< header ID to name
    std::map<int, uint32_t> m_headerBytes;     ///< header ID to bytes
    std::map<int, std::string> m_headerStacks; ///< header ID to its stack, if in one
    std::vector<ParseState> m_parseStates;     ///< all parse states
    std::vector<LatencyTableFeature> m_tables; ///< all tables
};

/**
 * \ingroup p4sim
 * \brief Collects PacketLatencyFeatures while it exists
 *
 * It listens to BMv2's pipeline events (EventObserverRegistry) in the thread
 * that creates it: the headers extracted by the parser named \p parser and the
 * tables applied by the pipeline named \p pipeline. BMv2 sends these events only
 * when it was built with its event logger (BM_ELOG_ON, the default).
 */
class LatencyFeatureCollector
{
  public:
    /**
     * \param features where to collect
     * \param parser the ingress parser ("parser" in v1model)
     * \param pipeline the ingress control ("ingress" in v1model)
     */
    LatencyFeatureCollector(PacketLatencyFeatures* features,
                            const std::string& parser,
                            const std::string& pipeline);
    ~LatencyFeatureCollector();

    /// Stop collecting (e.g. at the end of the ingress control)
    void Stop();

    /// \return whether BMv2 sends the events (built with BM_ELOG_ON)
    static bool EventsAvailable();

    LatencyFeatureCollector(const LatencyFeatureCollector&) = delete;
    LatencyFeatureCollector& operator=(const LatencyFeatureCollector&) = delete;

  private:
    bool m_active{true};       ///< whether it still collects
    void* m_previous{nullptr}; ///< the collection it replaced, restored by Stop()
};

} // namespace ns3

#endif // P4SIM_P4_LATENCY_FEATURES_H
