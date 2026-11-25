/*
 * Copyright (c) 2026 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

// The Thrift services of a switch, guarded. BMv2 starts one Thrift server per
// switch, in a thread of its own that runs until the process ends, and its
// handlers keep a plain pointer to the switch. So every service of a switch is
// registered behind a processor that runs a call only while the switch is
// alive, under one lock; a switch stops its services under the same lock
// before it is destroyed, and a call that runs then finishes first.

#include "ns3/log.h"
#include "ns3/p4-switch-core.h"

#include <bm/SimplePre.h>
#include <bm/SimplePreLAG.h>
#include <bm/Standard.h>
#include <bm/bm_runtime/bm_runtime.h>
#include <mutex>
#include <set>
#include <thrift/TApplicationException.h>
#include <thrift/TProcessor.h>

NS_LOG_COMPONENT_DEFINE("P4SwitchCoreThrift");

// The handlers of BMv2's own services (src/bm_runtime), which its server
// registers for every switch
namespace bm_runtime
{
namespace standard
{
std::shared_ptr<StandardIf> get_handler(bm::SwitchWContexts* sw);
} // namespace standard

namespace simple_pre
{
std::shared_ptr<SimplePreIf> get_handler(bm::SwitchWContexts* sw);
} // namespace simple_pre

namespace simple_pre_lag
{
std::shared_ptr<SimplePreLAGIf> get_handler(bm::SwitchWContexts* sw);
} // namespace simple_pre_lag
} // namespace bm_runtime

namespace ns3
{

namespace
{

/// Held while a Thrift call runs, and while a switch stops its services. Never
/// destroyed: the server threads may outlive the static objects at exit.
std::mutex&
ThriftMutex()
{
    static auto* mutex = new std::mutex;
    return *mutex;
}

/// The IDs of the switches whose Thrift services run calls (under ThriftMutex())
std::set<uint64_t>&
LiveSwitches()
{
    static auto* live = new std::set<uint64_t>;
    return *live;
}

/// The ID of the next switch that starts its Thrift services (under ThriftMutex())
uint64_t g_nextThriftId = 1;

/// A Thrift processor that runs a call only while its switch is alive
class GuardedProcessor : public apache::thrift::TProcessor
{
  public:
    /**
     * \param processor the processor of the service
     * \param id the ID of the switch
     */
    GuardedProcessor(std::shared_ptr<apache::thrift::TProcessor> processor, uint64_t id)
        : m_processor(std::move(processor)),
          m_id(id)
    {
    }

    bool process(std::shared_ptr<apache::thrift::protocol::TProtocol> in,
                 std::shared_ptr<apache::thrift::protocol::TProtocol> out,
                 void* connectionContext) override
    {
        std::lock_guard<std::mutex> lock(ThriftMutex());
        if (LiveSwitches().count(m_id) == 0)
        {
            return ReplyDestroyed(in, out);
        }
        return m_processor->process(in, out, connectionContext);
    }

  private:
    /// Reads the call and answers it with an exception, as a Thrift processor
    /// answers a call it cannot run
    static bool ReplyDestroyed(std::shared_ptr<apache::thrift::protocol::TProtocol> in,
                               std::shared_ptr<apache::thrift::protocol::TProtocol> out)
    {
        std::string name;
        apache::thrift::protocol::TMessageType type;
        int32_t seqid = 0;
        in->readMessageBegin(name, type, seqid);
        in->skip(apache::thrift::protocol::T_STRUCT);
        in->readMessageEnd();
        in->getTransport()->readEnd();
        if (type == apache::thrift::protocol::T_ONEWAY)
        {
            return true;
        }
        apache::thrift::TApplicationException error(
            apache::thrift::TApplicationException::INTERNAL_ERROR,
            "the P4sim switch of this Thrift port was destroyed");
        out->writeMessageBegin(name, apache::thrift::protocol::T_EXCEPTION, seqid);
        error.write(out.get());
        out->writeMessageEnd();
        out->getTransport()->writeEnd();
        out->getTransport()->flush();
        return true;
    }

    std::shared_ptr<apache::thrift::TProcessor> m_processor; ///< the processor of the service
    uint64_t m_id;                                           ///< the ID of the switch
};

} // namespace

void
P4SwitchCore::GuardThriftServices()
{
    NS_LOG_FUNCTION(this);
    {
        std::lock_guard<std::mutex> lock(ThriftMutex());
        m_thriftId = g_nextThriftId++;
        LiveSwitches().insert(m_thriftId);
    }
    // The server registered BMv2's services unguarded, as in bm_runtime::serve():
    // register them again, behind the guard
    AddThriftService("standard",
                     std::make_shared<bm_runtime::standard::StandardProcessor>(
                         bm_runtime::standard::get_handler(this)));
    if (get_cxt_component<bm::McSimplePre>(0) != nullptr)
    {
        AddThriftService("simple_pre",
                         std::make_shared<bm_runtime::simple_pre::SimplePreProcessor>(
                             bm_runtime::simple_pre::get_handler(this)));
    }
    if (get_cxt_component<bm::McSimplePreLAG>(0) != nullptr)
    {
        AddThriftService("simple_pre_lag",
                         std::make_shared<bm_runtime::simple_pre_lag::SimplePreLAGProcessor>(
                             bm_runtime::simple_pre_lag::get_handler(this)));
    }
    AddThriftServices();
}

void
P4SwitchCore::AddThriftService(const std::string& name,
                               std::shared_ptr<apache::thrift::TProcessor> processor)
{
    NS_LOG_FUNCTION(this << name);
    bm_runtime::processor_->registerProcessor(
        name,
        std::make_shared<GuardedProcessor>(std::move(processor), m_thriftId));
}

void
P4SwitchCore::StopThriftServices()
{
    NS_LOG_FUNCTION(this);
    // Waits for a call that runs now
    std::lock_guard<std::mutex> lock(ThriftMutex());
    LiveSwitches().erase(m_thriftId);
}

} // namespace ns3
