// SPDX-FileCopyrightText: 2019 Derek So
// Copyright 2019-present Derek So
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Derek So (dts76@cornell.edu)
 *
 */

// P4sim: count() checks the index in every build; otherwise as in BMv2 1.15.8.


#include "psa_counter.h"
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/packet.h>

namespace bm {

namespace psa {

void
PSA_Counter::count(const Data &index) {
  auto idx = index.get<size_t>();
  // P4sim: checked in every build, not only without NDEBUG (BMv2 issue #1459):
  // an index out of range would write past the counter array
  if (idx >= size()) {
    BMLOG_ERROR_PKT(get_packet(),
                    "Attempted to update counter '{}' with size {}"
                    " at out-of-bounds index {}."
                    "  No counters were updated.",
                    get_name(), size(), idx);
    return;
  }
  _counter->get_counter(idx).increment_counter(get_packet());
}

Counter &
PSA_Counter::get_counter(size_t idx) {
  return _counter->get_counter(idx);
}

const Counter &
PSA_Counter::get_counter(size_t idx) const {
  return _counter->get_counter(idx);
}

Counter::CounterErrorCode
PSA_Counter::reset_counters(){
  return _counter->reset_counters();
}

BM_REGISTER_EXTERN_W_NAME(Counter, PSA_Counter);
BM_REGISTER_EXTERN_W_NAME_METHOD(Counter, PSA_Counter, count, const Data &);

}  // namespace bm::psa

}  // namespace bm

int import_counters(){
  return 0;
}
