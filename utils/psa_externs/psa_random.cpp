// SPDX-FileCopyrightText: 2020 Cornell University
// Copyright 2020-present Cornell University
//
// SPDX-License-Identifier: Apache-2.0
/*
 * Yunhe Liu (yunheliu@cs.cornell.edu)
 *
 */

// P4sim: before the BMv2 headers, as in psa_meter.cpp
#include "ns3/p4-switch-core.h"

#include "psa_random.h"
#include <bm/bm_sim/logger.h>

#include <random>
#include <iostream>

namespace bm {

namespace psa {

void
PSA_Random::init() {
  min_val = min.get_uint64();
  max_val = max.get_uint64();
  _BM_ASSERT((max_val > min_val) && "[Error] Random number range must be positive.");

  /* Note: Even though PSA spec mentioned range should be a power of 2 for
   * max portability, bmv2 does not impose this restriction.
   */

  // P4sim: BMv2 calls init() while the switch loads its program; keep the
  // engine of that switch, which follows ns-3's seed and run, as random() of
  // v1model does, instead of an engine seeded with the thread id
  engine = &ns3::P4SwitchCore::LoadingRandomEngine();
}

void
PSA_Random::read(Data &value) {
  using distrib64 = std::uniform_int_distribution<uint64_t>;
  distrib64 distribution(min_val, max_val);
  value.set(distribution(*engine));
}

BM_REGISTER_EXTERN_W_NAME(Random, PSA_Random);
BM_REGISTER_EXTERN_W_NAME_METHOD(Random, PSA_Random, read, Data &);

}  // namespace bm::psa

}  // namespace bm

int import_random(){
  return 0;
}
