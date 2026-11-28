// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

#include "ns3/target-profile.h"

#include "ns3/format-utils.h"
#include "ns3/log.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <json/json.h>
#include <sstream>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("TargetProfile");

namespace
{

/// Reads the fields of one JSON object and names the profile in its errors
class ProfileReader
{
  public:
    ProfileReader(const std::string& path)
        : m_path(path)
    {
    }

    [[noreturn]] void Fail(const std::string& what) const
    {
        NS_FATAL_ERROR("Target profile " << m_path << ": " << what);
    }

    /// \return whether \p key holds a value (missing and null do not)
    static bool Has(const Json::Value& object, const char* key)
    {
        return object.isObject() && object.isMember(key) && !object[key].isNull();
    }

    double Number(const Json::Value& object, const char* key) const
    {
        if (!Has(object, key) || !object[key].isNumeric())
        {
            Fail(std::string("\"") + key + "\" must be a number");
        }
        return object[key].asDouble();
    }

    uint32_t Count(const Json::Value& object, const char* key) const
    {
        double value = Number(object, key);
        if (value < 0 || value != std::floor(value))
        {
            Fail(std::string("\"") + key + "\" must be a whole number of 0 or more");
        }
        return static_cast<uint32_t>(value);
    }

    std::string Text(const Json::Value& object, const char* key) const
    {
        if (!Has(object, key) || !object[key].isString())
        {
            Fail(std::string("\"") + key + "\" must be a string");
        }
        return object[key].asString();
    }

    TargetProfile::MeasuredDelay Delay(const Json::Value& object, const char* key) const
    {
        TargetProfile::MeasuredDelay delay;
        if (!Has(object, key))
        {
            return delay;
        }
        const Json::Value& value = object[key];
        delay.given = true;
        delay.meanNs = Number(value, "mean");
        delay.minNs = Has(value, "min") ? Number(value, "min") : delay.meanNs;
        delay.maxNs = Has(value, "max") ? Number(value, "max") : delay.meanNs;
        delay.source = Has(value, "source") ? Text(value, "source") : "";
        delay.lineRateBps = Has(value, "line_rate_bps") ? Number(value, "line_rate_bps") : 0;
        if (delay.meanNs < 0)
        {
            Fail(std::string("\"") + key + "\": the mean must not be negative");
        }
        return delay;
    }

  private:
    std::string m_path; ///< the profile file
};

/// \return \p bps as text, e.g. "10 Gbps"
std::string
RateText(double bps)
{
    std::ostringstream text;
    if (bps >= 1e9)
    {
        text << bps / 1e9 << " Gbps";
    }
    else
    {
        text << bps / 1e6 << " Mbps";
    }
    return text.str();
}

} // namespace

std::shared_ptr<const TargetProfile>
TargetProfile::Load(const std::string& nameOrPath)
{
    std::string path = nameOrPath;
    if (path.find('/') == std::string::npos && path.find(".json") == std::string::npos)
    {
        path = GetP4SimDir() + "/profiles/" + nameOrPath + ".json";
    }
    ProfileReader reader(path);
    std::ifstream file(path);
    if (!file)
    {
        reader.Fail("cannot open the file");
    }
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    if (!Json::parseFromStream(builder, file, &root, &errors) || !root.isObject())
    {
        reader.Fail("not a JSON object: " + errors);
    }

    auto profile = std::make_shared<TargetProfile>();
    profile->path = path;
    profile->name = reader.Text(root, "name");

    std::string mode = reader.Text(root, "forwarding_mode");
    if (mode == "store_and_forward")
    {
        profile->forwardingMode = ForwardingMode::STORE_AND_FORWARD;
    }
    else if (mode == "cut_through")
    {
        profile->forwardingMode = ForwardingMode::CUT_THROUGH;
    }
    else
    {
        reader.Fail("\"forwarding_mode\" must be \"store_and_forward\" or \"cut_through\"");
    }

    if (ProfileReader::Has(root, "line_rate_bps"))
    {
        profile->lineRateBps = reader.Number(root, "line_rate_bps");
    }
    if (ProfileReader::Has(root, "clock_period_ns"))
    {
        profile->clockPeriod = NanoSeconds(reader.Count(root, "clock_period_ns"));
    }

    std::string model = reader.Text(root, "ingress_latency_model");
    if (model == "franco_linear")
    {
        profile->ingressModel = IngressModel::FRANCO_LINEAR;
        const Json::Value& franco = root["franco_linear"];
        if (!franco.isObject() || !franco["coefficients"].isArray() ||
            franco["coefficients"].empty())
        {
            reader.Fail("\"franco_linear\" needs a list \"coefficients\"");
        }
        for (const Json::Value& set : franco["coefficients"])
        {
            FrancoCoefficients k;
            k.lineRateBps = reader.Number(set, "line_rate_bps");
            k.a = reader.Number(set, "a_ns_per_packet_byte");
            k.b = reader.Number(set, "b_ns");
            k.c = reader.Number(set, "c_ns_per_header_byte");
            k.d = reader.Number(set, "d_ns_per_parse_state");
            const Json::Value& e = set["e_ns_per_table"];
            k.exactNarrow = reader.Number(e, "exact_narrow_key");
            k.exactWide = reader.Number(e, "exact_wide_key");
            k.lpmNarrow = reader.Number(e, "lpm_narrow_key");
            k.lpmWide = reader.Number(e, "lpm_wide_key");
            profile->franco.push_back(k);
        }
        const Json::Value& validity = franco["validity"];
        FrancoValidity& v = profile->francoValidity;
        v.wideKeyBits = reader.Count(franco, "wide_key_bits");
        v.packetBytesMin = reader.Count(validity, "packet_bytes_min");
        v.packetBytesMax = reader.Count(validity, "packet_bytes_max");
        v.parseStatesMax = reader.Count(validity, "parse_states_max");
        v.headerBytesPerStateMin = reader.Count(validity, "header_bytes_per_state_min");
        v.headerBytesPerStateMax = reader.Count(validity, "header_bytes_per_state_max");
        v.tablesMax = reader.Count(validity, "tables_max");
        v.keysPerTableMax = reader.Count(validity, "keys_per_table_max");
        for (const Json::Value& bits : validity["key_bits"])
        {
            v.keyBits.push_back(bits.asUInt());
        }
        for (const Json::Value& type : validity["match_types"])
        {
            v.matchTypes.push_back(type.asString());
        }
        for (const Json::Value& limit : validity["linear_limits"])
        {
            LinearLimit l;
            l.lineRateBps = reader.Number(limit, "line_rate_bps");
            l.packetBytesMax = reader.Count(limit, "packet_bytes_max");
            l.parseStatesMax = reader.Count(limit, "parse_states_max");
            l.headerBytesPerStateMax = reader.Count(limit, "header_bytes_per_state_max");
            v.linearLimits.push_back(l);
        }
    }
    else if (model == "fixed")
    {
        profile->ingressModel = IngressModel::FIXED;
        profile->fixedLatency = NanoSeconds(reader.Count(root, "fixed_latency_ns"));
    }
    else
    {
        reader.Fail("\"ingress_latency_model\" must be \"franco_linear\" or \"fixed\"");
    }

    if (ProfileReader::Has(root, "decision_header_bytes"))
    {
        profile->decisionHeaderBytes = reader.Count(root, "decision_header_bytes");
    }
    profile->macRxDelay = reader.Delay(root, "mac_rx_delay_ns");
    profile->egressDelay = reader.Delay(root, "egress_delay_ns");
    if (ProfileReader::Has(root, "queue_capacity"))
    {
        profile->queueCapacity = reader.Count(root, "queue_capacity");
    }
    profile->preambleBytes = reader.Count(root, "preamble_bytes");
    profile->ipgBytes = reader.Count(root, "ipg_bytes");
    if (ProfileReader::Has(root, "egress_guard_ns"))
    {
        profile->egressGuard = NanoSeconds(reader.Count(root, "egress_guard_ns"));
    }
    if (ProfileReader::Has(root, "lookups_per_cycle"))
    {
        profile->lookupsPerCycle = reader.Count(root, "lookups_per_cycle");
        if (profile->lookupsPerCycle == 0 || profile->clockPeriod.IsZero())
        {
            reader.Fail("\"lookups_per_cycle\" needs a value of 1 or more and a clock_period_ns");
        }
    }
    if (ProfileReader::Has(root, "table_capacity"))
    {
        profile->tableCapacity = reader.Count(root, "table_capacity");
    }
    if (ProfileReader::Has(root, "eviction"))
    {
        std::string eviction = reader.Text(root, "eviction");
        if (eviction != "replace_oldest")
        {
            reader.Fail("\"eviction\" must be \"replace_oldest\" or null");
        }
        profile->evictOldest = true;
    }
    if (ProfileReader::Has(root, "entry_lifetime_s"))
    {
        profile->entryLifetime = Seconds(reader.Number(root, "entry_lifetime_s"));
    }
    if (ProfileReader::Has(root, "learning_path"))
    {
        std::string learning = reader.Text(root, "learning_path");
        if (learning == "data_plane")
        {
            profile->learningPath = LearningPath::DATA_PLANE;
        }
        else if (learning == "control_plane")
        {
            profile->learningPath = LearningPath::CONTROL_PLANE;
        }
        else
        {
            reader.Fail("\"learning_path\" must be \"data_plane\" or \"control_plane\"");
        }
    }
    if (ProfileReader::Has(root, "control_plane_update_delay_ns"))
    {
        profile->controlPlaneDelayGiven = true;
        profile->controlPlaneDelay =
            NanoSeconds(reader.Count(root, "control_plane_update_delay_ns"));
    }
    if (ProfileReader::Has(root, "fcs_check"))
    {
        if (!root["fcs_check"].isBool())
        {
            reader.Fail("\"fcs_check\" must be true or false");
        }
        profile->fcsCheck = root["fcs_check"].asBool();
    }
    if (profile->forwardingMode == ForwardingMode::CUT_THROUGH && profile->decisionHeaderBytes == 0)
    {
        reader.Fail("cut_through needs \"decision_header_bytes\"");
    }
    return profile;
}

const TargetProfile::FrancoCoefficients&
TargetProfile::SelectFranco(double portSpeedBps, std::vector<std::string>* warnings) const
{
    NS_ABORT_MSG_IF(franco.empty(), "Target profile " << name << " has no Model A coefficients");
    const FrancoCoefficients* best = &franco.front();
    for (const FrancoCoefficients& k : franco)
    {
        if (std::fabs(std::log(k.lineRateBps / portSpeedBps)) <
            std::fabs(std::log(best->lineRateBps / portSpeedBps)))
        {
            best = &k;
        }
    }
    if (best->lineRateBps != portSpeedBps)
    {
        warnings->push_back("Model A has no coefficients for " + RateText(portSpeedBps) +
                            " ports; it uses those of " + RateText(best->lineRateBps) +
                            ", without interpolation");
    }
    return *best;
}

IngressLatencyEstimate
TargetProfile::TofinoIngressLatencyNs(uint32_t packetBytes,
                                      double portSpeedBps,
                                      const std::vector<uint32_t>& parseStateBytes,
                                      const std::vector<LatencyTableFeature>& tables) const
{
    IngressLatencyEstimate result;
    std::vector<std::string>& warnings = result.warnings;
    const FrancoCoefficients& k = SelectFranco(portSpeedBps, &warnings);
    const FrancoValidity& v = francoValidity;

    // L_B = a * p + b
    result.baseNs = k.a * packetBytes + k.b;
    if (packetBytes < v.packetBytesMin || packetBytes > v.packetBytesMax)
    {
        warnings.push_back("Model A was fitted on packets of " + std::to_string(v.packetBytesMin) +
                           " to " + std::to_string(v.packetBytesMax) + " bytes, not " +
                           std::to_string(packetBytes));
    }

    // L_PD = sum over the parse states after Ethernet of (c * h_n + d)
    for (uint32_t bytes : parseStateBytes)
    {
        result.parserNs += k.c * bytes + k.d;
        if (bytes < v.headerBytesPerStateMin || bytes > v.headerBytesPerStateMax)
        {
            warnings.push_back("Model A was fitted on " + std::to_string(v.headerBytesPerStateMin) +
                               " to " + std::to_string(v.headerBytesPerStateMax) +
                               " header bytes per parse state, not " + std::to_string(bytes));
        }
    }
    if (parseStateBytes.size() > v.parseStatesMax)
    {
        warnings.push_back("Model A was fitted on up to " + std::to_string(v.parseStatesMax) +
                           " parse states after Ethernet, not " +
                           std::to_string(parseStateBytes.size()));
    }

    // L_C = sum over the tables matched of e(m_j, k_j)
    for (const LatencyTableFeature& table : tables)
    {
        bool lpm = table.matchType == "lpm";
        if (table.matchType != "exact" && !lpm)
        {
            // (inference) Tofino matches LPM and ternary keys in TCAM
            warnings.push_back("Model A has no coefficient for " + table.matchType + " tables (" +
                               table.name + "); it uses the LPM one");
            lpm = true;
        }
        // Several keys: the narrow coefficient; one key of wideKeyBits or more: the wide one
        bool wide = table.keyCount == 1 && table.keyBits >= v.wideKeyBits;
        result.controlNs +=
            lpm ? (wide ? k.lpmWide : k.lpmNarrow) : (wide ? k.exactWide : k.exactNarrow);
        if (table.keyCount > v.keysPerTableMax)
        {
            warnings.push_back("Model A was fitted on tables with up to " +
                               std::to_string(v.keysPerTableMax) + " keys, not " +
                               std::to_string(table.keyCount) + " (" + table.name + ")");
        }
        if (table.keyCount > 1 && lpm)
        {
            warnings.push_back("Model A was fitted on exact-match tables with several keys "
                               "only, not on " +
                               table.name);
        }
        if (table.keyCount == 1 &&
            std::find(v.keyBits.begin(), v.keyBits.end(), table.keyBits) == v.keyBits.end())
        {
            std::string widths;
            for (uint32_t bits : v.keyBits)
            {
                widths += (widths.empty() ? "" : ", ") + std::to_string(bits);
            }
            warnings.push_back("Model A was fitted on keys of " + widths + " bits, not " +
                               std::to_string(table.keyBits) + " (" + table.name + ")");
        }
    }
    if (tables.size() > v.tablesMax)
    {
        warnings.push_back("Model A was fitted on up to " + std::to_string(v.tablesMax) +
                           " tables, not " + std::to_string(tables.size()));
    }
    if (tables.size() > 1)
    {
        for (const LatencyTableFeature& table : tables)
        {
            if (table.matchType != tables.front().matchType ||
                (table.keyCount == 1 && table.keyBits >= v.wideKeyBits) !=
                    (tables.front().keyCount == 1 && tables.front().keyBits >= v.wideKeyBits))
            {
                // (inference) the paper fits one coefficient per kind of table and
                // sums them in its generalized formula without testing a mix
                warnings.push_back("Model A sums the terms of different kinds of tables, which "
                                   "the paper did not fit on a mix");
                break;
            }
        }
    }

    // Where the data turn non-linear at this port speed
    for (const LinearLimit& limit : v.linearLimits)
    {
        if (limit.lineRateBps != k.lineRateBps)
        {
            continue;
        }
        bool nonLinear =
            packetBytes > limit.packetBytesMax || parseStateBytes.size() > limit.parseStatesMax;
        for (uint32_t bytes : parseStateBytes)
        {
            nonLinear = nonLinear || bytes > limit.headerBytesPerStateMax;
        }
        if (nonLinear)
        {
            warnings.push_back("at " + RateText(limit.lineRateBps) +
                               ", Model A is linear only up to " +
                               std::to_string(limit.packetBytesMax) + " bytes, " +
                               std::to_string(limit.parseStatesMax) + " parse states and " +
                               std::to_string(limit.headerBytesPerStateMax) +
                               " header bytes per state; this packet is beyond");
        }
    }
    return result;
}

} // namespace ns3
