/*
 * SPDX-FileCopyrightText: 2026 Yuao Ma
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * P4sim: BMv2's EventObserverIface and EventObserverRegistry.
 *
 * BMv2 1.15.8 declares them in include/bm/bm_sim/event_observer.h, which its
 * event_logger.h includes, but it does not install that header (it is missing
 * from include/Makefile.am). If the BMv2 in use installs it, it is used.
 * Otherwise P4sim uses the copy below, from BMv2 1.15.8
 * (https://github.com/p4lang/behavioral-model, tag 1.15.8), changed only in its
 * includes (<bm/bm_sim/...> instead of "...", and without device_id.h and
 * transport.h, which it does not use) and without the BMELOG macro.
 *
 * The declarations must stay exactly as in BMv2: libbmall calls the observers
 * through these virtual functions, and EventObserverRegistry::get() is shared
 * with the library (its static instance is a unique symbol).
 */

#ifndef P4SIM_BM_EVENT_OBSERVER_H
#define P4SIM_BM_EVENT_OBSERVER_H

#if __has_include(<bm/bm_sim/event_observer.h>)
#include <bm/bm_sim/event_observer.h>
#elif !defined(BM_BM_SIM_EVENT_OBSERVER_H_)
#define BM_BM_SIM_EVENT_OBSERVER_H_

#include <bm/bm_sim/phv_forward.h>
#include <bm/config.h>

#include <cstdint>
#include <vector>

namespace bm {

// Forward declarations of P4 object classes. Don't need their full definitions
// because this file only uses references to them and doesn't require their
// implementation/layout details.
class ActionFn;
class Checksum;
class Conditional;
class Deparser;
class MatchEntry;
class MatchTableAbstract;
class Packet;
class Parser;
class Pipeline;
struct ActionData;

using entry_handle_t = uint32_t;

//! Abstract observer interface for pipeline events.
//! Each backend (nanomsg, trace, etc.) implements this interface.
class EventObserverIface {
 public:
  virtual ~EventObserverIface() = default;

  // we need the ingress / egress ports, but they are part of the Packet
  //! Signal that a packet was received by the switch
  virtual void packet_in(const Packet& packet) = 0;
  //! Signal that a packet was transmitted by the switch
  virtual void packet_out(const Packet& packet) = 0;

  virtual void parser_start(const Packet& packet, const Parser& parser) = 0;
  virtual void parser_done(const Packet& packet, const Parser& parser) = 0;
  virtual void parser_extract(const Packet& packet, header_id_t header) = 0;

  virtual void deparser_start(const Packet& packet,
                              const Deparser& deparser) = 0;
  virtual void deparser_done(const Packet& packet,
                             const Deparser& deparser) = 0;
  virtual void deparser_emit(const Packet& packet, header_id_t header) = 0;

  virtual void checksum_update(const Packet& packet,
                               const Checksum& checksum) = 0;

  virtual void pipeline_start(const Packet& packet,
                              const Pipeline& pipeline) = 0;
  virtual void pipeline_done(const Packet& packet,
                             const Pipeline& pipeline) = 0;

  virtual void condition_eval(const Packet& packet, const Conditional& cond,
                              bool result) = 0;
  virtual void table_hit(const Packet& packet, const MatchTableAbstract& table,
                         entry_handle_t handle) = 0;
  virtual void table_miss(const Packet& packet,
                          const MatchTableAbstract& table) = 0;

  virtual void action_execute(const Packet& packet, const ActionFn& action_fn,
                              const ActionData& action_data) = 0;

  virtual void config_change() = 0;
};

//! Singleton registry of event observers.
//! All registered observers receive every event via the BMELOG macro.
class EventObserverRegistry {
 public:
  static EventObserverRegistry* get() {
    static EventObserverRegistry instance;
    return &instance;
  }

  void register_observer(EventObserverIface* obs) {
    for (auto* existing : observers_) {
      if (existing == obs) return;
    }
    observers_.push_back(obs);
  }

  const std::vector<EventObserverIface*>& observers() const {
    return observers_;
  }

 private:
  EventObserverRegistry() = default;
  std::vector<EventObserverIface*> observers_;
};

}  // namespace bm

#endif

#endif // P4SIM_BM_EVENT_OBSERVER_H
