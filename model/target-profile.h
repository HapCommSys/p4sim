// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

#ifndef P4SIM_TARGET_PROFILE_H
#define P4SIM_TARGET_PROFILE_H

#include "ns3/nstime.h"

#include <memory>
#include <string>
#include <vector>

namespace ns3
{

/**
 * \ingroup p4sim
 * \brief A table that a packet matched, as the ingress latency model needs it
 */
struct LatencyTableFeature
{
    std::string name;      ///< the table, as the BMv2 JSON names it
    std::string matchType; ///< "exact", "lpm", "ternary", "range", ... (BMv2 JSON)
    uint32_t keyBits{0};   ///< bits of the whole key
    uint32_t keyCount{0};  ///< number of key fields
};

/**
 * \ingroup p4sim
 * \brief The ingress pipeline latency of one packet, by Model A, in ns
 */
struct IngressLatencyEstimate
{
    double baseNs{0};                  ///< L_B: packet size and baseline (Ethernet extraction)
    double parserNs{0};                ///< L_PD: the parse states after Ethernet
    double controlNs{0};               ///< L_C: the tables matched
    std::vector<std::string> warnings; ///< inputs outside what the model was fitted on

    /// \return L_B + L_PD + L_C
    double TotalNs() const
    {
        return baseNs + parserNs + controlNs;
    }
};

/**
 * \ingroup p4sim
 * \brief The timing, buffering and table limits of a hardware target, kept apart
 * from the P4 program (doc/latency-model.md)
 *
 * A profile is a JSON file (the folder profiles/ ships two). Every number of a
 * latency model comes from it: no coefficient or cycle count is written in the
 * code.
 */
class TargetProfile
{
  public:
    /// When a switch starts to forward a frame
    enum class ForwardingMode
    {
        STORE_AND_FORWARD, ///< once its last bit has arrived
        CUT_THROUGH,       ///< once the headers needed for the decision have arrived
    };

    /// How the time from ingress to the traffic manager is computed
    enum class IngressModel
    {
        FRANCO_LINEAR, ///< Model A (Franco et al. 2024), per packet
        FIXED,         ///< a fixed time (fixed_latency_ns)
    };

    /// Where new entries of a learning table come from
    enum class LearningPath
    {
        NONE,          ///< the profile does not say
        DATA_PLANE,    ///< installed with the frame that taught them
        CONTROL_PLANE, ///< installed by a controller, after a delay
    };

    /// Model A's coefficients for one port speed (Franco et al., Table 2), in ns
    struct FrancoCoefficients
    {
        double lineRateBps{0}; ///< the port speed they were measured at
        double a{0};           ///< per packet byte
        double b{0};           ///< baseline, Ethernet extraction included
        double c{0};           ///< per extracted header byte
        double d{0};           ///< per parse state
        double exactNarrow{0}; ///< per exact-match table with a narrow key
        double exactWide{0};   ///< per exact-match table with a wide key
        double lpmNarrow{0};   ///< per LPM table with a narrow key
        double lpmWide{0};     ///< per LPM table with a wide key
    };

    /// Where Model A was fitted at one port speed only (linear range)
    struct LinearLimit
    {
        double lineRateBps{0};              ///< the port speed
        uint32_t packetBytesMax{0};         ///< larger packets: non-linear
        uint32_t parseStatesMax{0};         ///< more states: non-linear
        uint32_t headerBytesPerStateMax{0}; ///< more bytes per state: non-linear
    };

    /// The inputs Model A was fitted on
    struct FrancoValidity
    {
        uint32_t packetBytesMin{0};            ///< smallest packet
        uint32_t packetBytesMax{0};            ///< largest packet
        uint32_t parseStatesMax{0};            ///< parse states after Ethernet
        uint32_t headerBytesPerStateMin{0};    ///< smallest header per state
        uint32_t headerBytesPerStateMax{0};    ///< largest header per state
        uint32_t tablesMax{0};                 ///< tables matched
        std::vector<uint32_t> keyBits;         ///< key widths measured
        uint32_t keysPerTableMax{0};           ///< keys per table measured
        std::vector<std::string> matchTypes;   ///< match types measured
        std::vector<LinearLimit> linearLimits; ///< per port speed
        uint32_t wideKeyBits{0};               ///< a single key of this many bits or more is wide
    };

    /// A delay with its spread, as measured
    struct MeasuredDelay
    {
        bool given{false};     ///< false: the profile has no value
        double meanNs{0};      ///< the mean
        double minNs{0};       ///< the smallest value measured
        double maxNs{0};       ///< the largest value measured
        double lineRateBps{0}; ///< the port speed it was measured at; 0: not given
        std::string source;    ///< where it comes from
    };

    /**
     * \brief Read a profile
     * \param nameOrPath a file, or the name of a profile in profiles/ (without ".json")
     * \return the profile; the simulation ends with a message if it cannot be read
     */
    static std::shared_ptr<const TargetProfile> Load(const std::string& nameOrPath);

    /**
     * \brief Model A: the mean latency of the Tofino ingress pipeline (T1 to T2:
     * ingress parser, control and deparser) for one packet
     *
     * The rules of Franco et al.: a table with several keys uses the narrow
     * coefficient; a single key of wideKeyBits or more the wide one. A match type
     * other than exact and LPM uses the LPM coefficients (inference: both are
     * TCAM on Tofino), with a warning. Inputs outside what the model was fitted
     * on give warnings, not errors. A port speed without coefficients uses the
     * nearest set, without interpolation, with a warning.
     *
     * \param packetBytes p, the packet size in bytes
     * \param portSpeedBps the speed of the ingress port
     * \param parseStateBytes h_n, the header bytes extracted in each parse state
     *        after Ethernet
     * \param tables the tables the packet matched
     * \return the three terms and the warnings
     */
    IngressLatencyEstimate TofinoIngressLatencyNs(
        uint32_t packetBytes,
        double portSpeedBps,
        const std::vector<uint32_t>& parseStateBytes,
        const std::vector<LatencyTableFeature>& tables) const;

    std::string name;                                                 ///< the profile's name
    std::string path;                                                 ///< the file it was read from
    ForwardingMode forwardingMode{ForwardingMode::STORE_AND_FORWARD}; ///< forwarding mode
    double lineRateBps{0}; ///< the port speed it describes; 0: any
    Time clockPeriod;      ///< time quantum of arrivals and decisions; 0: continuous
    IngressModel ingressModel{IngressModel::FIXED}; ///< ingress latency model
    std::vector<FrancoCoefficients> franco;         ///< Model A, per port speed
    FrancoValidity francoValidity;                  ///< Model A's validity range
    Time fixedLatency;                              ///< first bit in to first bit out (FIXED)
    uint32_t decisionHeaderBytes{0}; ///< bytes, preamble included, before a cut-through decision
    MeasuredDelay macRxDelay;        ///< T0 to T1 (Model B)
    MeasuredDelay egressDelay;       ///< egress pipeline to the start of serialization (Model B)
    int64_t queueCapacity{-1};       ///< frames per egress port; -1: the simulator's queues
    uint32_t preambleBytes{0};       ///< preamble and start-of-frame delimiter
    uint32_t ipgBytes{0};            ///< interpacket gap
    Time egressGuard;                ///< idle time a port needs before a new frame; 0: none
    uint32_t lookupsPerCycle{0};     ///< lookups per clock period; 0: unlimited
    uint32_t tableCapacity{0};       ///< entries per learning table; 0: the P4 program's
    bool evictOldest{false};         ///< a full learning table replaces its oldest entry
    Time entryLifetime;              ///< an entry not refreshed for this long ages out; 0: never
    LearningPath learningPath{LearningPath::NONE}; ///< where learned entries come from
    bool controlPlaneDelayGiven{false}; ///< false: the profile has no control-plane delay
    Time controlPlaneDelay;             ///< digest to installed entry (CONTROL_PLANE)
    bool fcsCheck{false};               ///< whether the target drops corrupted frames

  private:
    /// \return the coefficients for \p portSpeedBps, or the nearest set with a warning
    const FrancoCoefficients& SelectFranco(double portSpeedBps,
                                           std::vector<std::string>* warnings) const;
};

} // namespace ns3

#endif // P4SIM_TARGET_PROFILE_H
