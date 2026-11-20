/*
 * Copyright (c) 2026 TU Dresden
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * \file
 * The differences between the ns-3 releases that P4sim builds with, ns-3.39 to
 * ns-3.49. CMakeLists.txt sets P4SIM_NS3_MINOR to the minor version of ns-3
 * (39 for ns-3.39, 99 for a development tree).
 */

#ifndef P4SIM_NS3_COMPAT_H
#define P4SIM_NS3_COMPAT_H

#include "ns3/enum.h"
#include "ns3/event-id.h"

#ifndef P4SIM_NS3_MINOR
#error "P4SIM_NS3_MINOR is not set; contrib/p4sim/CMakeLists.txt sets it"
#endif

namespace ns3
{

/**
 * \brief Whether \p event is scheduled and has neither expired nor been cancelled
 *
 * EventId::IsRunning() up to ns-3.41, EventId::IsPending() from ns-3.42 on.
 */
inline bool
P4simIsPending(const EventId& event)
{
#if P4SIM_NS3_MINOR >= 42
    return event.IsPending();
#else
    return event.IsRunning();
#endif
}

} // namespace ns3

// EnumValue and MakeEnumAccessor take the enum type from ns-3.41 on
#if P4SIM_NS3_MINOR >= 41
#define P4SIM_ENUM_VALUE(T) ns3::EnumValue<T>
#define P4SIM_MAKE_ENUM_ACCESSOR(T, member) ns3::MakeEnumAccessor<T>(member)
#else
#define P4SIM_ENUM_VALUE(T) ns3::EnumValue
#define P4SIM_MAKE_ENUM_ACCESSOR(T, member) ns3::MakeEnumAccessor(member)
#endif

// The duration of a quick test case: TestCase::Duration::QUICK from ns-3.42 on
#if P4SIM_NS3_MINOR >= 42
#define P4SIM_TEST_QUICK ns3::TestCase::Duration::QUICK
#else
#define P4SIM_TEST_QUICK ns3::TestCase::QUICK
#endif

// The link type of Ethernet pcap files: iana::linktype::ETHERNET from ns-3.49 on
#if P4SIM_NS3_MINOR >= 49
#include "ns3/iana-link-type-numbers.h"
#define P4SIM_PCAP_ETHERNET ns3::iana::linktype::ETHERNET
#else
#define P4SIM_PCAP_ETHERNET ns3::PcapHelper::DLT_EN10MB
#endif

#endif // P4SIM_NS3_COMPAT_H
