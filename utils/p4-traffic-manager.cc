/*
 * Copyright (c) 2025 TU Dresden
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Vineet Goel <vineetgoel692@gmail.com>
 */

#include "p4-traffic-manager.h"

#include "ns3/abort.h"
#include "ns3/boolean.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"

#include <algorithm>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("P4TrafficManager");

NS_OBJECT_ENSURE_REGISTERED(P4TrafficManager);

const char*
TmDropReasonToString(TmDropReason r)
{
    switch (r)
    {
    case TmDropReason::VOQ_GLOBAL_BUFFER_FULL:
        return "VOQ_GLOBAL_BUFFER_FULL";
    case TmDropReason::VOQ_INPUT_BUFFER_FULL:
        return "VOQ_INPUT_BUFFER_FULL";
    case TmDropReason::VOQ_QUEUE_FULL:
        return "VOQ_QUEUE_FULL";
    case TmDropReason::EGRESS_PORT_BUFFER_FULL:
        return "EGRESS_PORT_BUFFER_FULL";
    case TmDropReason::EGRESS_QUEUE_FULL:
        return "EGRESS_QUEUE_FULL";
    case TmDropReason::EGRESS_POST_DEQUEUE_DROP:
        return "EGRESS_POST_DEQUEUE_DROP";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// TmStats helpers
// ---------------------------------------------------------------------------

Time
P4TrafficManager::TmStats::AvgVoqDelay() const
{
    return (cntVoqDelay == 0) ? Time(0) : (sumVoqDelay / static_cast<int64_t>(cntVoqDelay));
}

Time
P4TrafficManager::TmStats::AvgEgressDelay() const
{
    return (cntEgressDelay == 0) ? Time(0) : (sumEgressDelay / static_cast<int64_t>(cntEgressDelay));
}

Time
P4TrafficManager::TmStats::AvgTotalDelay() const
{
    return (cntTotalDelay == 0) ? Time(0) : (sumTotalDelay / static_cast<int64_t>(cntTotalDelay));
}

// ---------------------------------------------------------------------------
// TypeId / construction
// ---------------------------------------------------------------------------

TypeId
P4TrafficManager::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::P4TrafficManager")
            .SetParent<Object>()
            .SetGroupName("P4sim")
            .AddConstructor<P4TrafficManager>()
            .AddAttribute("NumPorts",
                          "Number of switch ports N (allocates N*N*8 VOQs).",
                          UintegerValue(0),
                          MakeUintegerAccessor(&P4TrafficManager::SetNumPorts,
                                               &P4TrafficManager::GetNumPorts),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("GlobalBufferLimit",
                          "Global buffer limit in bytes across VOQ and egress (0 = unlimited).",
                          UintegerValue(0),
                          MakeUintegerAccessor(&P4TrafficManager::m_globalBufferLimit),
                          MakeUintegerChecker<uint64_t>())
            .AddAttribute("InputBufferLimit",
                          "Per-input-port buffer limit in bytes (0 = unlimited).",
                          UintegerValue(0),
                          MakeUintegerAccessor(&P4TrafficManager::m_inputBufferLimit),
                          MakeUintegerChecker<uint64_t>())
            .AddAttribute("VoqLimit",
                          "Per-VOQ[in][out][prio] limit in bytes (0 = unlimited).",
                          UintegerValue(0),
                          MakeUintegerAccessor(&P4TrafficManager::m_voqLimit),
                          MakeUintegerChecker<uint64_t>())
            .AddAttribute("EgressPortLimit",
                          "Per-output-port egress buffer limit in bytes (0 = unlimited).",
                          UintegerValue(0),
                          MakeUintegerAccessor(&P4TrafficManager::m_egressPortLimit),
                          MakeUintegerChecker<uint64_t>())
            .AddAttribute("EgressQueueLimit",
                          "Per-egress-queue[out][prio] limit in bytes (0 = unlimited).",
                          UintegerValue(0),
                          MakeUintegerAccessor(&P4TrafficManager::m_egressQueueLimit),
                          MakeUintegerChecker<uint64_t>())
            .AddAttribute("PortRate",
                          "Output-port serialization rate.",
                          DataRateValue(DataRate("1Gbps")),
                          MakeDataRateAccessor(&P4TrafficManager::m_portRate),
                          MakeDataRateChecker())
            .AddAttribute("FabricRate",
                          "Fabric transfer rate.",
                          DataRateValue(DataRate("10Gbps")),
                          MakeDataRateAccessor(&P4TrafficManager::m_fabricRate),
                          MakeDataRateChecker())
            .AddAttribute("IngressPipelineDelay",
                          "Fixed ingress pipeline processing delay.",
                          TimeValue(Time(0)),
                          MakeTimeAccessor(&P4TrafficManager::m_ingressPipelineDelay),
                          MakeTimeChecker())
            .AddAttribute("FabricArbitrationDelay",
                          "Fixed fabric arbitration delay per round.",
                          TimeValue(Time(0)),
                          MakeTimeAccessor(&P4TrafficManager::m_fabricArbitrationDelay),
                          MakeTimeChecker())
            .AddAttribute("EgressPipelineDelay",
                          "Fixed egress pipeline processing delay.",
                          TimeValue(Time(0)),
                          MakeTimeAccessor(&P4TrafficManager::m_egressPipelineDelay),
                          MakeTimeChecker())
            .AddAttribute("EventDriven",
                          "If true, EnqueueToVoq self-clocks the fabric + egress "
                          "scheduler via ns-3 events; if false, the fabric is driven "
                          "manually via RunFabricScheduler()/DequeueFromVoq().",
                          BooleanValue(false),
                          MakeBooleanAccessor(&P4TrafficManager::m_eventDriven),
                          MakeBooleanChecker())
            .AddAttribute("EgressCompletionDriven",
                          "If true (and EventDriven), the egress scheduler hands each "
                          "frame to the TransmitCallback and waits for "
                          "NotifyEgressTxComplete() before counting it transmitted and "
                          "serving the next frame (the datapath/PHY decides the timing). "
                          "If false, egress self-clocks serialisation at PortRate.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&P4TrafficManager::m_egressCompletionDriven),
                          MakeBooleanChecker())
            .AddTraceSource("VoqEnqueue",
                            "A packet was enqueued into a VOQ (in, out, prio, bytes).",
                            MakeTraceSourceAccessor(&P4TrafficManager::m_voqEnqueueTrace),
                            "ns3::P4TrafficManager::QueueOpCallback")
            .AddTraceSource("VoqDequeue",
                            "A packet was dequeued from a VOQ (in, out, prio, bytes).",
                            MakeTraceSourceAccessor(&P4TrafficManager::m_voqDequeueTrace),
                            "ns3::P4TrafficManager::QueueOpCallback")
            .AddTraceSource("EgressEnqueue",
                            "A packet was enqueued into an egress queue (in, out, prio, bytes).",
                            MakeTraceSourceAccessor(&P4TrafficManager::m_egressEnqueueTrace),
                            "ns3::P4TrafficManager::QueueOpCallback")
            .AddTraceSource("EgressDequeue",
                            "A packet was dequeued from an egress queue (in, out, prio, bytes).",
                            MakeTraceSourceAccessor(&P4TrafficManager::m_egressDequeueTrace),
                            "ns3::P4TrafficManager::QueueOpCallback")
            .AddTraceSource("Drop",
                            "A packet was dropped (reason, in, out, prio, bytes).",
                            MakeTraceSourceAccessor(&P4TrafficManager::m_dropTrace),
                            "ns3::P4TrafficManager::DropCallback")
            .AddTraceSource("VoqWaitingDelay",
                            "VOQ waiting delay of a dequeued packet.",
                            MakeTraceSourceAccessor(&P4TrafficManager::m_voqDelayTrace),
                            "ns3::P4TrafficManager::DelayCallback")
            .AddTraceSource("EgressWaitingDelay",
                            "Egress queue waiting delay of a dequeued packet.",
                            MakeTraceSourceAccessor(&P4TrafficManager::m_egressDelayTrace),
                            "ns3::P4TrafficManager::DelayCallback")
            .AddTraceSource("TotalDelay",
                            "Total Traffic Manager delay of a packet.",
                            MakeTraceSourceAccessor(&P4TrafficManager::m_totalDelayTrace),
                            "ns3::P4TrafficManager::DelayCallback");
    return tid;
}

P4TrafficManager::P4TrafficManager()
{
    NS_LOG_FUNCTION(this);
}

P4TrafficManager::~P4TrafficManager()
{
    NS_LOG_FUNCTION(this);
}

void
P4TrafficManager::DoDispose()
{
    NS_LOG_FUNCTION(this);
    m_fabricEvent.Cancel();
    for (auto& ev : m_egressEvent)
    {
        ev.Cancel();
    }
    m_transmitCallback = nullptr;
    m_voq.clear();
    m_egress.clear();
    m_voqBytes.clear();
    m_inputBufferBytes.clear();
    m_egressPortBytes.clear();
    m_egressQueueBytes.clear();
    m_egressInFlight.clear();
    m_inFlightBytes.clear();
    m_inFlightPrio.clear();
    Object::DoDispose();
}

void
P4TrafficManager::SetTransmitCallback(TransmitCallback cb)
{
    m_transmitCallback = std::move(cb);
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

void
P4TrafficManager::SetNumPorts(uint32_t numPorts)
{
    NS_LOG_FUNCTION(this << numPorts);
    m_numPorts = numPorts;
    AllocateStructures();
}

uint32_t
P4TrafficManager::GetNumPorts() const
{
    return m_numPorts;
}

void
P4TrafficManager::AllocateStructures()
{
    NS_LOG_FUNCTION(this << m_numPorts);

    const uint32_t n = m_numPorts;
    const size_t nn = static_cast<size_t>(n) * n;

    // Reallocating cancels any in-flight scheduling from a previous sizing.
    m_fabricEvent.Cancel();
    for (auto& ev : m_egressEvent)
    {
        ev.Cancel();
    }
    m_fabricScheduled = false;

    // TmItem is move-only, so the VOQ element type cannot be relocated by
    // vector::resize/assign (those instantiate a copy fallback).  Direct sized
    // construction value-initialises each element in place, which is fine.
    m_voq = std::vector<PriQueues>(nn);
    m_egress = std::vector<PriQueues>(n);
    m_voqBytes = std::vector<PriBytes>(nn, PriBytes{});
    m_inputBufferBytes.assign(n, 0);
    m_egressPortBytes.assign(n, 0);
    m_egressQueueBytes.assign(n, PriBytes{});
    m_egressBusy.assign(n, false);
    m_egressEvent = std::vector<EventId>(n);
    m_egressInFlight.assign(n, false);
    m_inFlightBytes.assign(n, 0);
    m_inFlightPrio.assign(n, 0);

    m_globalBufferBytes = 0;
    m_stats.perPortTxBytes.assign(n, 0);

    NS_LOG_INFO("Allocated " << (static_cast<uint64_t>(n) * n * P4_TM_NUM_PRIORITIES)
                             << " VOQs for " << n << " ports");
}

bool
P4TrafficManager::ValidPort(uint32_t p) const
{
    return p < m_numPorts;
}

bool
P4TrafficManager::ValidPriority(uint8_t prio) const
{
    return prio < P4_TM_NUM_PRIORITIES;
}

// ---------------------------------------------------------------------------
// Ingress boundary: EnqueueToVoq
// ---------------------------------------------------------------------------

bool
P4TrafficManager::EnqueueToVoq(std::unique_ptr<TmPayload> payload,
                               uint32_t sizeBytes,
                               uint32_t inPort,
                               uint32_t outPort,
                               uint8_t priority)
{
    NS_LOG_FUNCTION(this << sizeBytes << inPort << outPort << static_cast<uint32_t>(priority));

    NS_ABORT_MSG_IF(!ValidPort(inPort) || !ValidPort(outPort),
                    "EnqueueToVoq: port index out of range (numPorts=" << m_numPorts << ")");
    NS_ABORT_MSG_IF(!ValidPriority(priority), "EnqueueToVoq: priority must be 0..7");

    m_stats.totalReceived++;

    // Admission control, in order: global -> input -> VOQ.
    auto drop = [&](TmDropReason reason) {
        m_stats.totalDropped++;
        m_stats.dropsByReason[static_cast<size_t>(reason)]++;
        m_dropTrace(static_cast<uint8_t>(reason), inPort, outPort, priority, sizeBytes);
        NS_LOG_DEBUG("Dropped " << sizeBytes << "B pkt (" << TmDropReasonToString(reason)
                                << ") in=" << inPort << " out=" << outPort
                                << " prio=" << static_cast<uint32_t>(priority));
        // payload released on return (unique_ptr goes out of scope)
        return false;
    };

    if (m_globalBufferLimit != 0 && m_globalBufferBytes + sizeBytes > m_globalBufferLimit)
    {
        return drop(TmDropReason::VOQ_GLOBAL_BUFFER_FULL);
    }
    if (m_inputBufferLimit != 0 && m_inputBufferBytes[inPort] + sizeBytes > m_inputBufferLimit)
    {
        return drop(TmDropReason::VOQ_INPUT_BUFFER_FULL);
    }
    if (m_voqLimit != 0 && m_voqBytes[Idx(inPort, outPort)][priority] + sizeBytes > m_voqLimit)
    {
        return drop(TmDropReason::VOQ_QUEUE_FULL);
    }

    // Accept.
    TmItem item;
    item.payload = std::move(payload);
    item.sizeBytes = sizeBytes;
    item.inPort = inPort;
    item.outPort = outPort;
    item.priority = priority;
    item.voqEnqueueTime = Simulator::Now();
    item.uid = m_nextUid++;

    m_voq[Idx(inPort, outPort)][priority].push_back(std::move(item));
    m_voqBytes[Idx(inPort, outPort)][priority] += sizeBytes;
    m_inputBufferBytes[inPort] += sizeBytes;
    m_globalBufferBytes += sizeBytes;

    m_stats.totalVoqEnqueued++;
    m_voqEnqueueTrace(inPort, outPort, priority, sizeBytes);

    NS_LOG_DEBUG("Enqueued " << sizeBytes << "B into VOQ[" << inPort << "][" << outPort << "]["
                             << static_cast<uint32_t>(priority) << "]");

    // Event-driven mode: wake the fabric so this packet gets scheduled.
    ScheduleFabricRound();
    return true;
}

// ---------------------------------------------------------------------------
// Fabric scheduler
// ---------------------------------------------------------------------------

std::vector<Grant>
P4TrafficManager::RunFabricScheduler()
{
    return DoRunFabricScheduler();
}

std::vector<Grant>
P4TrafficManager::DoRunFabricScheduler()
{
    NS_LOG_FUNCTION(this);

    std::vector<Grant> grants;
    if (m_numPorts == 0)
    {
        return grants;
    }

    std::vector<bool> inputUsed(m_numPorts, false);
    std::vector<bool> outputUsed(m_numPorts, false);

    // Priority-first maximal matching: highest priority (7) first.
    for (int p = P4_TM_NUM_PRIORITIES - 1; p >= 0; --p)
    {
        for (uint32_t in = 0; in < m_numPorts; ++in)
        {
            if (inputUsed[in])
            {
                continue;
            }
            for (uint32_t out = 0; out < m_numPorts; ++out)
            {
                if (outputUsed[out])
                {
                    continue;
                }
                if (VoqNotEmpty(in, out, static_cast<uint8_t>(p)))
                {
                    grants.push_back({in, out, static_cast<uint8_t>(p)});
                    inputUsed[in] = true;
                    outputUsed[out] = true;
                    break; // this input is now used; move to next input
                }
            }
        }
    }

    NS_LOG_DEBUG("Fabric scheduler produced " << grants.size() << " grants");
    return grants;
}

bool
P4TrafficManager::DequeueFromVoq(uint32_t inPort,
                                 uint32_t outPort,
                                 uint8_t priority,
                                 TmItem& item)
{
    NS_LOG_FUNCTION(this << inPort << outPort << static_cast<uint32_t>(priority));

    NS_ABORT_MSG_IF(!ValidPort(inPort) || !ValidPort(outPort) || !ValidPriority(priority),
                    "DequeueFromVoq: index out of range");

    auto& q = m_voq[Idx(inPort, outPort)][priority];
    if (q.empty())
    {
        return false;
    }

    item = std::move(q.front());
    q.pop_front();

    const uint32_t sizeBytes = item.sizeBytes;
    m_voqBytes[Idx(inPort, outPort)][priority] -= sizeBytes;
    m_inputBufferBytes[inPort] -= sizeBytes;
    m_globalBufferBytes -= sizeBytes;

    m_stats.totalMovedToEgress++;

    Time voqDelay = Simulator::Now() - item.voqEnqueueTime;
    m_stats.sumVoqDelay += voqDelay;
    m_stats.cntVoqDelay++;
    if (voqDelay > m_stats.maxQueueingDelay)
    {
        m_stats.maxQueueingDelay = voqDelay;
    }

    m_voqDequeueTrace(inPort, outPort, priority, sizeBytes);
    m_voqDelayTrace(voqDelay);

    NS_LOG_DEBUG("Dequeued " << sizeBytes << "B from VOQ[" << inPort << "][" << outPort << "]["
                             << static_cast<uint32_t>(priority) << "] voqDelay="
                             << voqDelay.GetNanoSeconds() << "ns");
    return true;
}

// ---------------------------------------------------------------------------
// P3: event-driven fabric loop
// ---------------------------------------------------------------------------

void
P4TrafficManager::ScheduleFabricRound()
{
    if (!m_eventDriven || m_fabricScheduled)
    {
        return;
    }
    m_fabricScheduled = true;
    // A freshly arrived packet must traverse the ingress pipeline before it can
    // be arbitrated by the fabric, so the first round after the fabric goes idle
    // is delayed by the ingress pipeline delay in addition to the arbitration
    // delay.  (Re-arms from RunFabricRoundEvent add only the arbitration delay.)
    m_fabricEvent = Simulator::Schedule(m_ingressPipelineDelay + m_fabricArbitrationDelay,
                                        &P4TrafficManager::RunFabricRoundEvent,
                                        this);
}

void
P4TrafficManager::RunFabricRoundEvent()
{
    NS_LOG_FUNCTION(this);
    m_fabricScheduled = false;

    std::vector<Grant> grants = RunFabricScheduler();

    // Apply grants: move each granted head packet from its VOQ to egress.  The
    // fabric transfers all grants of a round in parallel, so its busy time is
    // the transfer time of the largest granted packet.
    uint32_t maxBytes = 0;
    for (const Grant& g : grants)
    {
        TmItem item;
        if (!DequeueFromVoq(g.inPort, g.outPort, g.priority, item))
        {
            continue; // defensive: VOQ emptied out from under the grant
        }
        maxBytes = std::max(maxBytes, item.sizeBytes);
        EnqueueToEgress(std::move(item));
    }

    // Re-arm the next round while there is still demand.  The next arbitration
    // happens after this round's fabric transfer plus the arbitration delay.
    if (AnyVoqNonEmpty())
    {
        Time transfer = (maxBytes > 0) ? m_fabricRate.CalculateBytesTxTime(maxBytes) : Time(0);
        m_fabricScheduled = true;
        m_fabricEvent = Simulator::Schedule(m_fabricArbitrationDelay + transfer,
                                            &P4TrafficManager::RunFabricRoundEvent,
                                            this);
    }
}

bool
P4TrafficManager::AnyVoqNonEmpty() const
{
    for (const PriQueues& pq : m_voq)
    {
        for (const std::deque<TmItem>& q : pq)
        {
            if (!q.empty())
            {
                return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// P4: egress queues + serialising egress scheduler
// ---------------------------------------------------------------------------

bool
P4TrafficManager::EnqueueToEgress(TmItem&& item)
{
    const uint32_t in = item.inPort;
    const uint32_t out = item.outPort;
    const uint8_t prio = item.priority;
    const uint32_t sizeBytes = item.sizeBytes;

    auto drop = [&](TmDropReason reason) {
        m_stats.totalDropped++;
        m_stats.dropsByReason[static_cast<size_t>(reason)]++;
        m_dropTrace(static_cast<uint8_t>(reason), in, out, prio, sizeBytes);
        NS_LOG_DEBUG("Egress drop " << sizeBytes << "B (" << TmDropReasonToString(reason)
                                    << ") out=" << out << " prio="
                                    << static_cast<uint32_t>(prio));
        // The packet has already been removed from the VOQ (global was
        // decremented there); dropping it here simply releases the payload.
        return false;
    };

    // Admission: per-output-port then per-egress-queue.  Global is NOT
    // re-checked: the VOQ->egress hand-off is byte-neutral for the global
    // counter (DequeueFromVoq subtracted these bytes, we add them back below),
    // so the packet was already counted globally throughout its residence.
    if (m_egressPortLimit != 0 && m_egressPortBytes[out] + sizeBytes > m_egressPortLimit)
    {
        return drop(TmDropReason::EGRESS_PORT_BUFFER_FULL);
    }
    if (m_egressQueueLimit != 0 && m_egressQueueBytes[out][prio] + sizeBytes > m_egressQueueLimit)
    {
        return drop(TmDropReason::EGRESS_QUEUE_FULL);
    }

    item.egressEnqueueTime = Simulator::Now();
    m_egress[out][prio].push_back(std::move(item));
    m_egressPortBytes[out] += sizeBytes;
    m_egressQueueBytes[out][prio] += sizeBytes;
    m_globalBufferBytes += sizeBytes;

    m_stats.totalEgressEnqueued++;
    m_egressEnqueueTrace(in, out, prio, sizeBytes);

    ScheduleEgressService(out);
    return true;
}

int
P4TrafficManager::SelectEgressPriority(uint32_t outPort) const
{
    for (int p = P4_TM_NUM_PRIORITIES - 1; p >= 0; --p)
    {
        if (!m_egress[outPort][static_cast<size_t>(p)].empty())
        {
            return p;
        }
    }
    return -1;
}

void
P4TrafficManager::ScheduleEgressService(uint32_t outPort)
{
    if (!m_eventDriven || m_egressBusy[outPort])
    {
        return;
    }
    m_egressBusy[outPort] = true;
    m_egressEvent[outPort] = Simulator::Schedule(m_egressPipelineDelay,
                                                 &P4TrafficManager::EgressServiceEvent,
                                                 this,
                                                 outPort);
}

void
P4TrafficManager::EgressServiceEvent(uint32_t outPort)
{
    NS_LOG_FUNCTION(this << outPort);

    const int prio = SelectEgressPriority(outPort);
    if (prio < 0)
    {
        m_egressBusy[outPort] = false; // nothing to send: the port goes idle
        return;
    }

    std::deque<TmItem>& q = m_egress[outPort][static_cast<size_t>(prio)];
    TmItem item = std::move(q.front());
    q.pop_front();

    const uint32_t sizeBytes = item.sizeBytes;
    const uint32_t inPort = item.inPort;

    // The packet leaves the egress queue now: release its buffer occupancy and
    // record its queueing delays.  The "on the wire" counters (totalTransmitted
    // etc.) are handled only once the frame is actually transmitted -- below in
    // self-clocked mode, or on NotifyEgressTxComplete() in completion-driven
    // mode.
    m_egressPortBytes[outPort] -= sizeBytes;
    m_egressQueueBytes[outPort][static_cast<size_t>(prio)] -= sizeBytes;
    m_globalBufferBytes -= sizeBytes;

    const Time now = Simulator::Now();
    const Time egressDelay = now - item.egressEnqueueTime;
    const Time totalDelay = now - item.voqEnqueueTime;

    m_stats.sumEgressDelay += egressDelay;
    m_stats.cntEgressDelay++;
    m_stats.sumTotalDelay += totalDelay;
    m_stats.cntTotalDelay++;
    if (totalDelay > m_stats.maxQueueingDelay)
    {
        m_stats.maxQueueingDelay = totalDelay;
    }

    m_egressDequeueTrace(inPort, outPort, static_cast<uint8_t>(prio), sizeBytes);
    m_egressDelayTrace(egressDelay);
    m_totalDelayTrace(totalDelay);

    // Hand the frame to the datapath FIRST; it is counted as transmitted only
    // after that (self-clocked below, or on the completion signal).
    if (m_transmitCallback)
    {
        m_transmitCallback(outPort, static_cast<uint8_t>(prio), std::move(item.payload));
    }

    if (m_egressCompletionDriven)
    {
        // Completion-driven: the datapath (PHY/MAC) decides when the frame has
        // finished serialising and calls NotifyEgressTxComplete(), which counts
        // it and serves the next frame.  The port stays marked busy meanwhile.
        m_egressInFlight[outPort] = true;
        m_inFlightBytes[outPort] = sizeBytes;
        m_inFlightPrio[outPort] = static_cast<uint8_t>(prio);
        return;
    }

    // Self-clocked: count the frame as transmitted and re-arm after this port's
    // serialisation time (PortRate).  The next service finding the port empty is
    // what finally clears m_egressBusy.
    m_stats.totalTransmitted++;
    m_stats.perPriorityTransmitted[static_cast<size_t>(prio)]++;
    m_stats.perPortTxBytes[outPort] += sizeBytes;

    const Time txTime = m_portRate.CalculateBytesTxTime(sizeBytes);
    m_egressEvent[outPort] = Simulator::Schedule(txTime,
                                                 &P4TrafficManager::EgressServiceEvent,
                                                 this,
                                                 outPort);
}

void
P4TrafficManager::NotifyEgressTxComplete(uint32_t outPort, TmTxOutcome outcome)
{
    NS_LOG_FUNCTION(this << outPort << static_cast<uint32_t>(outcome));

    if (!ValidPort(outPort) || !m_egressCompletionDriven || !m_egressInFlight[outPort])
    {
        // Nothing in flight for this port, or not in completion-driven mode.
        return;
    }

    const uint8_t prio = m_inFlightPrio[outPort];
    switch (outcome)
    {
    case TmTxOutcome::TRANSMITTED:
        // The frame reached the wire: count it toward the transmit totals.
        m_stats.totalTransmitted++;
        m_stats.perPriorityTransmitted[prio]++;
        m_stats.perPortTxBytes[outPort] += m_inFlightBytes[outPort];
        break;
    case TmTxOutcome::RECIRCULATED:
        // The frame went back to ingress rather than onto the wire.  Count it
        // separately so it is conflated with neither a transmit nor a drop (a
        // recirculated frame is sent for real on a later pass, and counting it
        // here as transmitted would double-count it).
        m_stats.totalRecirculated++;
        break;
    case TmTxOutcome::DROPPED:
        // The egress pipeline dropped the frame, or the datapath could not send
        // it; it never reached the wire.  Account for it as a drop instead of
        // silently losing it from the conservation totals.
        NS_LOG_WARN("Egress frame not sent on port " << outPort << " (dropped after dequeue)");
        m_stats.totalDropped++;
        m_stats.dropsByReason[static_cast<size_t>(TmDropReason::EGRESS_POST_DEQUEUE_DROP)]++;
        break;
    }

    m_egressInFlight[outPort] = false;

    // The datapath signalled us at the moment the port became free, so serve
    // the next frame now.  m_egressBusy stays true across the in-flight gap;
    // the next EgressServiceEvent clears it if the port has drained.
    m_egressEvent[outPort] =
        Simulator::ScheduleNow(&P4TrafficManager::EgressServiceEvent, this, outPort);
}

// ---------------------------------------------------------------------------
// Occupancy queries
// ---------------------------------------------------------------------------

size_t
P4TrafficManager::VoqLength(uint32_t inPort, uint32_t outPort, uint8_t priority) const
{
    if (!ValidPort(inPort) || !ValidPort(outPort) || !ValidPriority(priority))
    {
        return 0;
    }
    return m_voq[Idx(inPort, outPort)][priority].size();
}

bool
P4TrafficManager::VoqNotEmpty(uint32_t inPort, uint32_t outPort, uint8_t priority) const
{
    return VoqLength(inPort, outPort, priority) > 0;
}

uint64_t
P4TrafficManager::GlobalBufferBytes() const
{
    return m_globalBufferBytes;
}

uint64_t
P4TrafficManager::InputBufferBytes(uint32_t inPort) const
{
    return ValidPort(inPort) ? m_inputBufferBytes[inPort] : 0;
}

uint64_t
P4TrafficManager::VoqBytes(uint32_t inPort, uint32_t outPort, uint8_t priority) const
{
    if (!ValidPort(inPort) || !ValidPort(outPort) || !ValidPriority(priority))
    {
        return 0;
    }
    return m_voqBytes[Idx(inPort, outPort)][priority];
}

size_t
P4TrafficManager::EgressLength(uint32_t outPort, uint8_t priority) const
{
    if (!ValidPort(outPort) || !ValidPriority(priority))
    {
        return 0;
    }
    return m_egress[outPort][priority].size();
}

uint64_t
P4TrafficManager::EgressPortBytes(uint32_t outPort) const
{
    return ValidPort(outPort) ? m_egressPortBytes[outPort] : 0;
}

uint64_t
P4TrafficManager::EgressQueueBytes(uint32_t outPort, uint8_t priority) const
{
    if (!ValidPort(outPort) || !ValidPriority(priority))
    {
        return 0;
    }
    return m_egressQueueBytes[outPort][priority];
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

const P4TrafficManager::TmStats&
P4TrafficManager::GetStats() const
{
    return m_stats;
}

void
P4TrafficManager::ResetStats()
{
    const size_t nPorts = m_stats.perPortTxBytes.size();
    m_stats = TmStats{};
    m_stats.perPortTxBytes.assign(nPorts, 0);
}

} // namespace ns3
