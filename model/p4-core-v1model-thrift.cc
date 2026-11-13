/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors: Antonin Bas <antonin@barefootnetworks.com>
 * Modified: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

// The "simple_switch" Thrift service of BMv2's simple_switch, which
// simple_switch_CLI uses for its own commands (mirroring_add, set_queue_depth,
// get_time_elapsed, ...). The handler follows BMv2 1.15.8
// (targets/simple_switch/thrift/src/SimpleSwitch_server.cpp), on the v1model core.

#include "ns3/p4-core-v1model.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <bm/SimpleSwitch.h>
#include <bm/bm_runtime/bm_runtime.h>
#include <bm/thrift/stdcxx.h>

NS_LOG_COMPONENT_DEFINE("P4CoreV1modelThrift");

namespace ns3 {

namespace {

class SimpleSwitchHandler : virtual public sswitch_runtime::SimpleSwitchIf {
public:
  explicit SimpleSwitchHandler(P4CoreV1model *core) : m_core(core) {}

  // deprecated, use the mirroring_session_* RPCs instead
  int32_t mirroring_mapping_add(const int32_t mirror_id,
                                const int32_t egress_port) override {
    NS_LOG_FUNCTION(this << mirror_id << egress_port);
    P4SwitchCore::MirroringSessionConfig config{};
    config.egress_port = egress_port;
    config.egress_port_valid = true;
    return m_core->AddMirroringSession(mirror_id, config);
  }

  int32_t mirroring_mapping_delete(const int32_t mirror_id) override {
    NS_LOG_FUNCTION(this << mirror_id);
    return m_core->DeleteMirroringSession(mirror_id);
  }

  int32_t mirroring_mapping_get_egress_port(const int32_t mirror_id) override {
    NS_LOG_FUNCTION(this << mirror_id);
    P4SwitchCore::MirroringSessionConfig config{};
    if (m_core->GetMirroringSession(mirror_id, &config) &&
        config.egress_port_valid) {
      return config.egress_port;
    }
    return -1;
  }

  void mirroring_session_add(
      const int32_t mirror_id,
      const sswitch_runtime::MirroringSessionConfig &config) override {
    NS_LOG_FUNCTION(this << mirror_id);
    P4SwitchCore::MirroringSessionConfig session{};
    if (config.__isset.port) {
      session.egress_port = config.port;
      session.egress_port_valid = true;
    }
    if (config.__isset.mgid) {
      session.mgid = config.mgid;
      session.mgid_valid = true;
    }
    // As in simple_switch, an ID out of range adds no session and no error
    m_core->AddMirroringSession(mirror_id, session);
  }

  void mirroring_session_delete(const int32_t mirror_id) override {
    NS_LOG_FUNCTION(this << mirror_id);
    if (!m_core->DeleteMirroringSession(mirror_id)) {
      ThrowSessionNotFound();
    }
  }

  void mirroring_session_get(sswitch_runtime::MirroringSessionConfig &_return,
                             const int32_t mirror_id) override {
    NS_LOG_FUNCTION(this << mirror_id);
    P4SwitchCore::MirroringSessionConfig session{};
    if (!m_core->GetMirroringSession(mirror_id, &session)) {
      ThrowSessionNotFound();
    }
    if (session.egress_port_valid) {
      _return.__set_port(session.egress_port);
    }
    if (session.mgid_valid) {
      _return.__set_mgid(session.mgid);
    }
  }

  int32_t set_egress_priority_queue_depth(const int32_t port_num,
                                          const int32_t priority,
                                          const int32_t depth_pkts) override {
    NS_LOG_FUNCTION(this << port_num << priority << depth_pkts);
    return m_core->SetEgressPriorityQueueDepth(
        port_num, priority, static_cast<uint32_t>(depth_pkts));
  }

  int32_t set_egress_queue_depth(const int32_t port_num,
                                 const int32_t depth_pkts) override {
    NS_LOG_FUNCTION(this << port_num << depth_pkts);
    return m_core->SetEgressQueueDepth(port_num,
                                       static_cast<uint32_t>(depth_pkts));
  }

  int32_t set_all_egress_queue_depths(const int32_t depth_pkts) override {
    NS_LOG_FUNCTION(this << depth_pkts);
    return m_core->SetAllEgressQueueDepths(static_cast<uint32_t>(depth_pkts));
  }

  int32_t set_egress_priority_queue_rate(const int32_t port_num,
                                         const int32_t priority,
                                         const int64_t rate_pps) override {
    NS_LOG_FUNCTION(this << port_num << priority << rate_pps);
    return m_core->SetEgressPriorityQueueRate(port_num, priority,
                                              static_cast<uint64_t>(rate_pps));
  }

  int32_t set_egress_queue_rate(const int32_t port_num,
                                const int64_t rate_pps) override {
    NS_LOG_FUNCTION(this << port_num << rate_pps);
    return m_core->SetEgressQueueRate(port_num,
                                      static_cast<uint64_t>(rate_pps));
  }

  int32_t set_all_egress_queue_rates(const int64_t rate_pps) override {
    NS_LOG_FUNCTION(this << rate_pps);
    return m_core->SetAllEgressQueueRates(static_cast<uint64_t>(rate_pps));
  }

  // The clock of the switch is the simulation clock: the time since the switch
  // was created, and the time since the simulation started
  int64_t get_time_elapsed_us() override {
    NS_LOG_FUNCTION(this);
    return static_cast<int64_t>(m_core->GetTimeStamp() / 1000);
  }

  int64_t get_time_since_epoch_us() override {
    NS_LOG_FUNCTION(this);
    return Simulator::Now().GetMicroSeconds();
  }

private:
  static void ThrowSessionNotFound() {
    sswitch_runtime::InvalidMirroringOperation e;
    e.code = sswitch_runtime::MirroringOperationErrorCode::SESSION_NOT_FOUND;
    throw e;
  }

  P4CoreV1model *m_core;
};

} // namespace

void P4CoreV1model::AddThriftServices() {
  NS_LOG_FUNCTION(this);
  bm_runtime::add_service<sswitch_runtime::SimpleSwitchIf,
                          sswitch_runtime::SimpleSwitchProcessor>(
      "simple_switch", stdcxx::shared_ptr<sswitch_runtime::SimpleSwitchIf>(
                           new SimpleSwitchHandler(this)));
}

} // namespace ns3
