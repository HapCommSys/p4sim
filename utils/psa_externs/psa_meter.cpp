// SPDX-FileCopyrightText: 2020 Cornell University
// Copyright 2020-present Cornell University
//
// SPDX-License-Identifier: Apache-2.0
/*
 * Yunhe Liu (yunheliu@cs.cornell.edu)
 *
 */

// P4sim: changed to measure simulation time instead of wall-clock time (see
// init() and execute()), and to check the index in every build; otherwise as
// in BMv2 1.15.8.

// P4sim: first, as BMv2's logger.h brings syslog.h's LOG_* macros, which
// clash with ns-3's log.h
#include "ns3/simulator.h"

#include "psa_meter.h"
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/packet.h>
#include <chrono>
#include <iostream>

namespace bm {

namespace psa {

namespace {

// P4sim: the current simulation time, on the clock of bm::Meter
Meter::clock::time_point
simulation_now() {
  return Meter::clock::time_point(std::chrono::duration_cast<Meter::clock::duration>(
      std::chrono::nanoseconds(ns3::Simulator::Now().GetNanoSeconds())));
}

}  // namespace

void
PSA_Meter::init() {
    bm::MeterArray::MeterType meter_type;
    if (type == "bytes") {
        meter_type = bm::MeterArray::MeterType::BYTES;
    } else {
        meter_type = bm::MeterArray::MeterType::PACKETS;
    }
    _meter = std::unique_ptr<MeterArray>(
        new MeterArray(get_name() + ".$impl",
                         spec_id,
                         meter_type,
                         rate_count.get<size_t>(),
                         n_meters.get<size_t>()));
    // P4sim: the meters count time from simulation time 0, see execute()
    for (size_t i = 0; i < _meter->size(); i++) {
      _meter->get_meter(i).reset_time_origin(Meter::clock::time_point());
    }
}

void
PSA_Meter::execute(const Data &index, Data &value) {
    auto idx = index.get<size_t>();
    // P4sim: checked in every build, not only without NDEBUG (BMv2 issue #1459)
    if (idx >= size()) {
        BMLOG_ERROR_PKT(get_packet(),
                        "Attempted to execute meter '{}' with size {}"
                        " at out-of-bounds index {}."
                        "  No meters were updated, and neither was"
                        " the value field.",
                        get_name(), size(), idx);
        return;
    }
    // P4sim: BMv2's execute_meter() reads the wall clock; the token buckets
    // must fill with simulation time instead
    BMLOG_DEBUG_PKT(get_packet(), "Executing meter {}[{}]", get_name(), idx);
    auto color_out = _meter->get_meter(idx).execute(
        get_packet(), static_cast<unsigned int>(0), simulation_now());

    // color adjustment for PSA:
    // bmv2 meter implementation assign higher value for busier flow:
    // (bmv2-meter) GREEN = 0, YELLOW = 1, RED = 2.
    // PSA specification order enums differently:
    // (see p4c/p4include/psa.p4)
    // (PSA-specification) RED = 0, GREEN = 1, YELLOW = 2.
    // The following code maps color_out (bmv2-meter) to
    // psa_color_out (PSA-specification).
    bm::Meter::color_t psa_color_out = 1;
    switch(color_out) {
        case 0 :
            psa_color_out = 1;
            break;
        case 1 :
            psa_color_out = 2;
            break;
        case 2 :
            psa_color_out = 0;
            break;
    }

    value.set(psa_color_out);
}

Meter &
PSA_Meter::get_meter(size_t idx) {
  return _meter->get_meter(idx);
}

const Meter &
PSA_Meter::get_meter(size_t idx) const {
  return _meter->get_meter(idx);
}

Meter::MeterErrorCode
PSA_Meter::set_rates(const std::vector<Meter::rate_config_t> &configs) {
    return _meter->set_rates(configs);
}

BM_REGISTER_EXTERN_W_NAME(Meter, PSA_Meter);
BM_REGISTER_EXTERN_W_NAME_METHOD(Meter, PSA_Meter, execute, const Data &, Data &);

}  // namespace bm::psa

}  // namespace bm

int import_meters(){
  return 0;
}
