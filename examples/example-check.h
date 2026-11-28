/*
 * Copyright (c) 2026 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * \file
 * The checks of the examples. An example prints "[PASS] ..." or "[FAIL] ..." and
 * exits with 1 if a check fails, so that test.py notices an example that runs but
 * does not do what it shows.
 */

#ifndef P4SIM_EXAMPLE_CHECK_H
#define P4SIM_EXAMPLE_CHECK_H

#include "ns3/config.h"
#include "ns3/double.h"
#include "ns3/global-value.h"
#include "ns3/packet.h"

#include <iostream>
#include <sstream>

namespace p4sim_example
{

/// --MinDelivery=<share>; 0 turns the check off, for experiments that lose packets on purpose
inline ns3::GlobalValue g_minDelivery(
    "MinDelivery",
    "Share of the sent bytes that the packet sinks must receive for exit code 0",
    ns3::DoubleValue(0.99),
    ns3::MakeDoubleChecker<double>(0, 1));

inline uint64_t g_txBytes = 0; ///< bytes sent by the OnOff applications
inline uint64_t g_rxBytes = 0; ///< bytes received by the packet sinks

inline void
CountTx(ns3::Ptr<const ns3::Packet> packet)
{
    g_txBytes += packet->GetSize();
}

inline void
CountRx(ns3::Ptr<const ns3::Packet> packet, const ns3::Address&)
{
    g_rxBytes += packet->GetSize();
}

/// Count the traffic of all OnOff applications and packet sinks. Call it when they are installed
inline void
CountTraffic()
{
    const std::string apps = "/NodeList/*/ApplicationList/*/";
    ns3::Config::ConnectWithoutContext(apps + "$ns3::OnOffApplication/Tx",
                                       ns3::MakeCallback(&CountTx));
    ns3::Config::ConnectWithoutContext(apps + "$ns3::PacketSink/Rx", ns3::MakeCallback(&CountRx));
}

/// Print the result of a check
/// \return 0 if it passed, 1 if not: the exit code of the example
inline int
Check(bool pass, const std::string& what)
{
    std::cout << (pass ? "[PASS] " : "[FAIL] ") << what << std::endl;
    return pass ? 0 : 1;
}

/// Check that \p rx, the bytes received, is at least the share MinDelivery of \p tx, the
/// bytes sent; \p who, if given, names the receiver in the output
/// \return 0 if it is, 1 if not: the exit code of the example
inline int
CheckDelivery(uint64_t tx, uint64_t rx, const std::string& who = "")
{
    ns3::DoubleValue minDelivery;
    g_minDelivery.GetValue(minDelivery);
    std::ostringstream what;
    what << who << (who.empty() ? "" : " ") << "received " << rx << " of " << tx << " bytes";
    if (minDelivery.Get() == 0)
    {
        std::cout << what.str() << " (not checked)" << std::endl;
        return 0;
    }
    return Check(tx > 0 && rx >= minDelivery.Get() * tx, what.str());
}

/// Check that the packet sinks received at least the share MinDelivery of the bytes that
/// the OnOff applications sent (CountTraffic())
/// \return 0 if they did, 1 if not: the exit code of the example
inline int
CheckDelivery()
{
    return CheckDelivery(g_txBytes, g_rxBytes);
}

} // namespace p4sim_example

#endif // P4SIM_EXAMPLE_CHECK_H
