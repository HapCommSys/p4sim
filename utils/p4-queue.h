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
 * Author: Antonin Bas <antonin@barefootnetworks.com>
 */

#ifndef P4_QUEUE_H
#define P4_QUEUE_H

#include "ns3/simulator.h"

#include <bm/bm_sim/packet.h>
#include <condition_variable>
#include <map>
#include <mutex>
#include <queue>

namespace ns3
{

// Arbitrates which packets are processed by the ingress thread. Resubmit and
// recirculate packets go to a high priority queue, while normal packets go to a
// low priority queue. We assume that starvation is not going to be a problem.
// Resubmit packets are dropped if the queue is full in order to make sure the
// ingress thread cannot deadlock. We do the same for recirculate packets even
// though the same argument does not apply for them. Enqueueing normal packets
// is blocking (back pressure is applied to the interface).
class InputBuffer
{
  public:
    enum class PacketType
    {
        NORMAL,
        RESUBMIT,
        RECIRCULATE,
        SENTINEL // signal for the ingress thread to terminate
    };

    InputBuffer(size_t capacity_hi, size_t capacity_lo)
        : capacity_hi(capacity_hi),
          capacity_lo(capacity_lo)
    {
    }

    int push_front(PacketType packet_type, std::unique_ptr<bm::Packet>&& item)
    {
        switch (packet_type)
        {
        case PacketType::NORMAL:
            return push_front(&queue_lo, capacity_lo, &cvar_can_push_lo, std::move(item), true);
        case PacketType::RESUBMIT:
        case PacketType::RECIRCULATE:
            return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi, std::move(item), false);
        case PacketType::SENTINEL:
            return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi, std::move(item), true);
        }
        NS_FATAL_ERROR("Unreachable statement");
        return 0;
    }

    void pop_back(std::unique_ptr<bm::Packet>* pItem)
    {
        if (queue_hi.size() > 0 || queue_lo.size() > 0)
        {
            Lock lock(mutex);
            cvar_can_pop.wait(lock, [this] { return (queue_hi.size() + queue_lo.size()) > 0; });
            // give higher priority to resubmit/recirculate queue
            if (queue_hi.size() > 0)
            {
                *pItem = std::move(queue_hi.back());
                queue_hi.pop_back();
                lock.unlock();
                cvar_can_push_hi.notify_one();
            }
            else
            {
                *pItem = std::move(queue_lo.back());
                queue_lo.pop_back();
                lock.unlock();
                cvar_can_push_lo.notify_one();
            }
        }
    }

    size_t get_size()
    {
        return capacity_hi + capacity_lo;
    }

  private:
    using Mutex = std::mutex;
    using Lock = std::unique_lock<Mutex>;
    using QueueImpl = std::deque<std::unique_ptr<bm::Packet>>;

    int push_front(QueueImpl* queue,
                   size_t capacity,
                   std::condition_variable* cvar,
                   std::unique_ptr<bm::Packet>&& item,
                   bool blocking)
    {
        Lock lock(mutex);
        while (queue->size() == capacity)
        {
            if (!blocking)
                return 0;
            cvar->wait(lock);
        }
        queue->push_front(std::move(item));
        lock.unlock();
        cvar_can_pop.notify_one();
        return 1;
    }

    mutable std::mutex mutex;
    mutable std::condition_variable cvar_can_push_hi;
    mutable std::condition_variable cvar_can_push_lo;
    mutable std::condition_variable cvar_can_pop;
    size_t capacity_hi;
    size_t capacity_lo;
    QueueImpl queue_hi;
    QueueImpl queue_lo;
};

/**
 * @brief This code is taken from
 * https://github.com/p4lang/behavioral-model/blob/main/include/bm/bm_sim/queueing.h#L489
 * In ns-3 replace the real-time with ns-3 virtual simulator time.
 *
 * This class is slightly more advanced than QueueingLogicRL. The difference
 * between the 2 is that this one offers the ability to set several priority
 * queues for each logical queue. Priority queues are numbered from `0` to
 * `nb_priorities` (see NSQueueingLogicPriRL::NSQueueingLogicPriRL()). Priority `0`
 * is the highest priority queue. Each priority queue can have its own rate and
 * its own capacity. Queues will be served in order of priority, until their
 * respective maximum rate is reached. If no maximum rate is set, queues with a
 * high priority can starve lower-priority queues. For example, if the queue
 * with priority `0` always contains at least one element, the other queues
 * will never be served.
 * As for QueueingLogicRL, the write behavior (push_front()) is not blocking:
 * once a logical queue is full, subsequent incoming elements will be dropped
 * until the queue starts draining again.
 * Look at the documentation for QueueingLogic for more information about the
 * template parameters (they are the same).
 *
 * @tparam T
 * @tparam FMap
 */
template <typename T, typename FMap>
class NSQueueingLogicPriRL
{
    using MutexType = std::mutex;
    using LockType = std::unique_lock<MutexType>;

  public:
    /**
     * @brief Construct a new NSQueueingLogicPriRL object\
     *
     * See QueueingLogic::QueueingLogicRL() for an introduction. The difference
     * here is that each logical queue can receive several priority queues (as
     * determined by \p nb_priorities, which is set to `2` by default). Each of
     * these priority queues will initially be able to hold \p capacity
     * elements. The capacity of each priority queue can be changed later by
     * using set_capacity(size_t queue_id, size_t priority, size_t c).
     *
     * @param nb_workers
     * @param capacity
     * @param map_to_worker
     * @param nb_priorities
     */
    NSQueueingLogicPriRL(size_t nb_workers,
                         size_t capacity,
                         FMap map_to_worker,
                         size_t nb_priorities = 2)
        : nb_workers(nb_workers),
          capacity(capacity),
          workers_info(nb_workers),
          map_to_worker(std::move(map_to_worker)),
          nb_priorities(nb_priorities)
    {
    }

    /**
     * @brief Place the packet in the front of corresponding priority queue.
     * If priority queue \p priority of logical queue \p queue_id is full, the
     * function will return `0` immediately. Otherwise, \p item will be copied to
     * the queue and the function will return `1`. If \p queue_id or \p priority
     * are incorrect, an exception of type std::out_of_range will be thrown (same
     * if the FMap object provided to the constructor does not behave correctly).
     *
     * @param queue_id each egress port will have a queue_id
     * @param priority the priroity of the packet in one queue
     * @param item the packet or things to be placed in the queue
     * @return int
     */
    int push_front(size_t queue_id, size_t priority, const T& item)
    {
        size_t worker_id = map_to_worker(queue_id);
        LockType lock(mutex);
        auto& q_info = get_queue(queue_id);
        auto& w_info = workers_info.at(worker_id);
        auto& q_info_pri = q_info.at(priority);
        if (q_info_pri.size >= q_info_pri.capacity)
            return 0;
        q_info_pri.last_sent = get_next_tp(q_info_pri);
        q_info_pri.queue.emplace(item,
                                 queue_id,
                                 q_info_pri.last_sent,
                                 w_info.wrapping_counter++);
        q_info_pri.size++;
        q_info.size++;
        w_info.size++;
        return 1;
    }

    int push_front(size_t queue_id, const T& item)
    {
        return push_front(queue_id, 0, item);
    }

    //! Same as push_front(size_t queue_id, size_t priority, const T &item), but
    //! \p item is moved instead of copied.
    int push_front(size_t queue_id, size_t priority, T&& item)
    {
        size_t worker_id = map_to_worker(queue_id);
        LockType lock(mutex);
        auto& q_info = get_queue(queue_id);
        auto& w_info = workers_info.at(worker_id);
        auto& q_info_pri = q_info.at(priority);
        if (q_info_pri.size >= q_info_pri.capacity)
            return 0;
        q_info_pri.last_sent = get_next_tp(q_info_pri);
        q_info_pri.queue.emplace(std::move(item),
                                 queue_id,
                                 q_info_pri.last_sent,
                                 w_info.wrapping_counter++);
        q_info_pri.size++;
        q_info.size++;
        w_info.size++;
        return 1;
    }

    int push_front(size_t queue_id, T&& item)
    {
        return push_front(queue_id, 0, std::move(item));
    }

    /**
     * @brief The exit end of the priority queue is prioritized. (itself bmv2 code
     * through the lock mechanism, but ns-3 does not have a built-in locking
     * mechanism ns3 in the replacement for the polling mechanism, so there will
     * be some loss in performance)
     *
     * [from bmv2]
     * Retrieves an element for the worker thread indentified by \p worker_id and
     * moves it to \p pItem. The id of the logical queue which contained this
     * element is copied to \p queue_id and the priority value of the served
     * queue is copied to \p priority.
     * Elements are retrieved according to the priority queue they are in
     * (highest priorities, i.e. lowest priority values, are served first). Once
     * a given priority queue reaches its maximum rate, the next queue is served.
     * If no elements are available (either the queues are empty or they have
     * exceeded their rate already), the function will block.
     *
     * @ todo remove the lock mechanism, also the loops in the function
     *
     * @param worker_id
     * @param queue_id
     * @param priority
     * @param pItem
     */
    void pop_back(size_t worker_id, size_t* queue_id, size_t* priority, T* pItem)
    {
        LockType lock(mutex);
        auto& w_info = workers_info.at(worker_id);
        if (w_info.size == 0)
            return;

        Time now = Simulator::Now();
        bool found = false;
        size_t best_pri = 0;
        size_t best_port = 0;
        Time best_send = Time::Max();
        size_t best_id = static_cast<size_t>(-1);

        // Scan all per-port queues to find the highest-priority eligible packet.
        // Priority ordering: higher index = higher priority (served first).
        for (auto& kv : queues_info)
        {
            size_t port_id = kv.first;
            if (map_to_worker(port_id) != worker_id)
                continue;
            auto& q_info = kv.second;
            // Iterate from highest to lowest priority; stop at first eligible.
            for (size_t pri = nb_priorities; pri-- > 0;)
            {
                auto& q_info_pri = q_info.at(pri);
                if (q_info_pri.queue.empty())
                    continue;
                const auto& top = q_info_pri.queue.top();
                if (top.send > now)
                    continue;
                // Eligible: prefer higher pri, then earlier send, then lower id.
                if (!found || pri > best_pri ||
                    (pri == best_pri && (top.send < best_send ||
                     (top.send == best_send && top.id < best_id))))
                {
                    found = true;
                    best_pri = pri;
                    best_port = port_id;
                    best_send = top.send;
                    best_id = top.id;
                }
                break; // best eligible packet for this port is found
            }
        }

        if (!found)
            return;

        *queue_id = best_port;
        *priority = best_pri;
        auto& q_info = get_queue_or_throw(best_port);
        auto& q_info_pri = q_info.at(best_pri);
        *pItem = std::move(const_cast<QE&>(q_info_pri.queue.top()).e);
        q_info_pri.queue.pop();
        q_info_pri.size--;
        q_info.size--;
        w_info.size--;
    }

    Time get_this_pkt_delay(const size_t queue_id, const size_t priority)
    {
        auto& q_info = get_queue(queue_id);
        auto& q_info_pri = q_info.at(priority);
        // Time now = Simulator::Now ();
        return q_info_pri.pkt_delay_time;
    }

    /**
     * @brief Returns the earliest time at which any queued packet becomes
     * rate-eligible for dequeue.
     *
     * Returns Time(0) if at least one packet is already eligible (send <= now).
     * Returns Time::Max() if all queues are empty (no packets at all).
     * Returns a future Time otherwise.
     *
     * Callers should check `size(port) > 0` or compare against Time::Max()
     * to distinguish "nothing queued" from "queued but rate-limited".
     */
    Time get_next_tp_all_ports()
    {
        LockType lock(mutex);
        Time now = Simulator::Now();
        Time next = Time::Max(); // sentinel: no packets queued anywhere

        for (auto& kv : queues_info)
        {
            auto& q_info = kv.second;
            for (size_t pri = nb_priorities; pri-- > 0;)
            {
                auto& q_info_pri = q_info.at(pri);
                if (q_info_pri.queue.empty())
                    continue;
                if (q_info_pri.queue.top().send <= now)
                    return Time(0);
                next = std::min(next, q_info_pri.queue.top().send);
            }
        }
        return next;
    }

    /**
     * @brief Returns the earliest time at which any queued packet for a
     *        specific egress port becomes rate-eligible for dequeue.
     *
     * Returns Time(0) if a packet is already eligible (send <= now).
     * Returns Time::Max() if the port queue is empty.
     * Returns a future Time otherwise.
     *
     * @param port The egress port (= queue_id) to query.
     */
    Time get_next_tp_for_port(size_t port)
    {
        LockType lock(mutex);
        auto it = queues_info.find(port);
        if (it == queues_info.end())
            return Time::Max();

        auto& q_info = it->second;
        if (q_info.size == 0)
            return Time::Max();

        Time now = Simulator::Now();
        Time next = Time::Max();

        for (size_t pri = nb_priorities; pri-- > 0;)
        {
            auto& q_info_pri = q_info.at(pri);
            if (q_info_pri.queue.empty())
                continue;
            if (q_info_pri.queue.top().send <= now)
                return Time(0);
            next = std::min(next, q_info_pri.queue.top().send);
        }
        return next;
    }

    /**
     * @brief Dequeue the next rate-eligible packet for a specific egress port.
     *
     * Scans priority queues high-to-low and pops the first packet whose
     * send timestamp <= Simulator::Now(). Returns immediately (no blocking)
     * if no eligible packet exists.
     *
     * @param port     The egress port (= queue_id) to dequeue from.
     * @param priority Set to the priority of the dequeued packet.
     * @param pItem    Receives the dequeued packet; unchanged if none eligible.
     */
    void pop_back_for_port(size_t port, size_t* priority, T* pItem)
    {
        LockType lock(mutex);
        auto it = queues_info.find(port);
        if (it == queues_info.end())
            return;

        auto& q_info = it->second;
        if (q_info.size == 0)
            return;

        Time now = Simulator::Now();
        size_t worker_id = map_to_worker(port);
        auto& w_info = workers_info.at(worker_id);

        for (size_t pri = nb_priorities; pri-- > 0;)
        {
            auto& q_info_pri = q_info.at(pri);
            if (q_info_pri.queue.empty())
                continue;
            if (q_info_pri.queue.top().send > now)
                continue;
            *priority = pri;
            *pItem = std::move(const_cast<QE&>(q_info_pri.queue.top()).e);
            q_info_pri.queue.pop();
            q_info_pri.size--;
            q_info.size--;
            w_info.size--;
            return;
        }
    }

    /**
     * @brief
     * Same as
     * pop_back(size_t worker_id, size_t *queue_id, size_t *priority, T *pItem),
     * but the priority of the popped element is discarded.
     *
     * @param worker_id from bmv2 thread id, in ns-3 we only one, so ignore it
     * @param queue_id the queue_id in each egress port
     * @param pItem the packet or things to be pop out from queue
     */
    void pop_back(size_t worker_id, size_t* queue_id, T* pItem)
    {
        size_t priority;
        return pop_back(worker_id, queue_id, &priority, pItem);
    }

    /**
     * @brief  QueueingLogic::size
     * @copydoc QueueingLogic::size
     * The occupancies of all the priority queues for this logical queue are
     * added.
     * @param queue_id the queue_id of logical queue in each egress port
     * @return size_t
     */
    size_t size(size_t queue_id) const
    {
        LockType lock(mutex);
        auto it = queues_info.find(queue_id);
        if (it == queues_info.end())
            return 0;
        auto& q_info = it->second;
        return q_info.size;
    }

    /**
     * @brief Get the occupancy of priority queue \p priority for logical
     * queue with id \p queue_id.
     *
     * @param queue_id the id of logical queue in each egress port
     * @param priority the prirority of the packet in one logical queue
     * with \p queue_id
     * @return size_t
     */
    size_t size(size_t queue_id, size_t priority) const
    {
        LockType lock(mutex);
        auto it = queues_info.find(queue_id);
        if (it == queues_info.end())
            return 0;
        auto& q_info = it->second;
        auto& q_info_pri = q_info.at(priority);
        return q_info_pri.size;
    }

    /**
     * @brief Set the capacity of all the priority queues for logical
     * queue \p queue_id to \p c elements.
     *
     * @param queue_id the id of logical queue in each egress port
     * @param c number of packets in queue
     */
    void set_capacity(size_t queue_id, size_t c)
    {
        LockType lock(mutex);
        for_each_q(queue_id, SetCapacityFn(c));
    }

    /**
     * @brief Set the capacity of priority queue with \p priority for
     * logical queue \p queue_id to \p c elements.
     *
     * @param queue_id the id of logical queue in each egress port
     * @param priority the \p priority number of one logical queue
     * @param c number of packets in one priority queue
     */
    void set_capacity(size_t queue_id, size_t priority, size_t c)
    {
        LockType lock(mutex);
        for_one_q(queue_id, priority, SetCapacityFn(c));
    }

    /**
     * @brief Set the capacity of all the priority queues of all
     * logical queues to \p c elements.
     *
     * @param c number of packets in one priority queue
     */
    void set_capacity_for_all(size_t c)
    {
        LockType lock(mutex);
        for (auto& p : queues_info)
            for_each_q(p.first, SetCapacityFn(c));
        capacity = c;
    }

    //! Set the maximum rate of all the priority queues for logical queue \p
    //! queue_id to \p pps. \p pps is expressed in "number of elements per
    //! second". Until this function is called, there will be no rate limit for
    //! the queue. The same behavior (no rate limit) can be achieved by calling
    //! this method with a rate of 0.

    /**
     * @brief Set the rate of processing packets
     * Set the maximum rate of all the priority queues for logical queue \p
     * queue_id to \p pps. \p pps is expressed in "number of elements per
     * second". Until this function is called, there will be no rate limit for
     * the queue. The same behavior (no rate limit) can be achieved by calling
     * this method with a rate of 0.
     *
     * @param queue_id the id of logical queue in each egress port
     * @param pps packets per second
     */
    void set_rate(size_t queue_id, uint64_t pps)
    {
        LockType lock(mutex);
        for_each_q(queue_id, SetRateFn(pps));
    }

    /**
     * @brief Set the rate object
     * Same as set_rate(size_t queue_id, uint64_t pps) but only applies
     * to the given priority queue.
     * @param queue_id the id of logical queue in each egress port
     * @param priority the prirority of the packet in one logical queue
     * @param pps packets per second
     */
    void set_rate(size_t queue_id, size_t priority, uint64_t pps)
    {
        LockType lock(mutex);
        for_one_q(queue_id, priority, SetRateFn(pps));
    }

    /**
     * @brief Set the rate of all the priority queues of all logical
     * queues to \p pps.
     *
     * @param pps
     */
    void set_rate_for_all(uint64_t pps)
    {
        LockType lock(mutex);
        for (auto& p : queues_info)
            for_each_q(p.first, SetRateFn(pps));
        queue_rate_pps = pps;
    }

    //! Deleted copy constructor
    NSQueueingLogicPriRL(const NSQueueingLogicPriRL&) = delete;
    //! Deleted copy assignment operator
    NSQueueingLogicPriRL& operator=(const NSQueueingLogicPriRL&) = delete;

    //! Deleted move constructor
    NSQueueingLogicPriRL(NSQueueingLogicPriRL&&) = delete;
    //! Deleted move assignment operator
    NSQueueingLogicPriRL&& operator=(NSQueueingLogicPriRL&&) = delete;

  private:
    /**
     * @brief calculate the intermediate time interval for processing
     * one packet. 1 pps = 1 packet per second,  default is 1ms for
     * one packet. pps should not set to 0.
     *
     * @param pps
     * @return constexpr Time
     */
    static constexpr Time rate_to_time(uint64_t pps)
    {
        return (pps == 0) ? Seconds(0.001)
                          : Seconds(static_cast<double>(1. / static_cast<double>(pps)));
    }

    /**
     * @brief The control label of the packet, the queue it is in,
     * the timestamp, etc.
     */
    struct QE
    {
        QE(T e, size_t queue_id, const Time& send, size_t id)
            : e(std::move(e)),
              queue_id(queue_id),
              send(send),
              id(id)
        {
        }

        T e;
        size_t queue_id;
        Time send;
        size_t id;
    };

    /**
     * @brief Check if the packet meets the out-of-queue requirements
     *
     */
    struct QEComp
    {
        bool operator()(const QE& lhs, const QE& rhs) const
        {
            return (lhs.send == rhs.send) ? lhs.id > rhs.id : lhs.send > rhs.send;
        }
    };

    using MyQ = std::priority_queue<QE, std::deque<QE>, QEComp>;

    /**
     * @brief information for each prioriry queue.
     *
     */
    struct QueueInfoPri
    {
        QueueInfoPri(size_t capacity, uint64_t queue_rate_pps)
            : capacity(capacity),
              queue_rate_pps(queue_rate_pps),
              pkt_delay_time(rate_to_time(queue_rate_pps)),
              last_sent(Simulator::Now())
        {
        }

        // MyQ holds unique_ptrs which are non-copyable; disable copy.
        QueueInfoPri(const QueueInfoPri&) = delete;
        QueueInfoPri& operator=(const QueueInfoPri&) = delete;
        QueueInfoPri(QueueInfoPri&&) = default;
        QueueInfoPri& operator=(QueueInfoPri&&) = default;

        MyQ queue;    ///< Per-(port, priority) packet queue
        size_t size{0};
        size_t capacity;
        uint64_t queue_rate_pps;
        Time pkt_delay_time;
        Time last_sent;
    };

    /**
     * @brief information for each logical queue (containing multiple
     * priority queues).
     */
    struct QueueInfo : public std::vector<QueueInfoPri>
    {
        QueueInfo(size_t capacity, uint64_t queue_rate_pps, size_t nb_priorities)
        {
            // QueueInfoPri is non-copyable (holds unique_ptrs); use emplace_back.
            this->reserve(nb_priorities);
            for (size_t i = 0; i < nb_priorities; i++)
                this->emplace_back(capacity, queue_rate_pps);
        }

        size_t size{0};
    };

    /**
     * @brief Per-worker bookkeeping (packet queues are now per-port in QueueInfoPri).
     */
    struct WorkerInfo
    {
        size_t size{0};
        size_t wrapping_counter{0};
    };

    QueueInfo& get_queue(size_t queue_id)
    {
        auto it = queues_info.find(queue_id);
        if (it != queues_info.end())
            return it->second;
        auto p = queues_info.emplace(queue_id, QueueInfo(capacity, queue_rate_pps, nb_priorities));
        return p.first->second;
    }

    const QueueInfo& get_queue_or_throw(size_t queue_id) const
    {
        return queues_info.at(queue_id);
    }

    QueueInfo& get_queue_or_throw(size_t queue_id)
    {
        return queues_info.at(queue_id);
    }

    Time get_next_tp(const QueueInfoPri& q_info_pri)
    {
        // Calculate when the next step should be sent
        return (Simulator::Now() > q_info_pri.last_sent + q_info_pri.pkt_delay_time)
                   ? Simulator::Now()
                   : q_info_pri.last_sent + q_info_pri.pkt_delay_time;
    }

    template <typename Function>
    Function for_each_q(size_t queue_id, Function fn)
    {
        auto& q_info = get_queue(queue_id);
        for (auto& q_info_pri : q_info)
            fn(q_info_pri);
        return fn;
    }

    template <typename Function>
    Function for_one_q(size_t queue_id, size_t priority, Function fn)
    {
        auto& q_info = get_queue(queue_id);
        auto& q_info_pri = q_info.at(priority);
        fn(q_info_pri);
        return fn;
    }

    struct SetCapacityFn
    {
        explicit SetCapacityFn(size_t c)
            : c(c)
        {
        }

        void operator()(QueueInfoPri& info) const
        { // NOLINT(runtime/references)
            info.capacity = c;
        }

        size_t c;
    };

    struct SetRateFn
    {
        explicit SetRateFn(uint64_t pps)
            : pps(pps)
        {
            pkt_delay_time = rate_to_time(pps);
        }

        void operator()(QueueInfoPri& info) const
        { // NOLINT(runtime/references)
            info.queue_rate_pps = pps;
            info.pkt_delay_time = pkt_delay_time;
        }

        uint64_t pps;
        Time pkt_delay_time;
    };

    mutable MutexType mutex;
    size_t nb_workers;
    size_t capacity;            // default capacity
    uint64_t queue_rate_pps{0}; // default rate
    std::unordered_map<size_t, QueueInfo> queues_info{};
    std::vector<WorkerInfo> workers_info{};
    std::vector<MyQ> queues{};
    FMap map_to_worker;
    size_t nb_priorities;
};

} // namespace ns3

#endif /* P4_QUEUE_H */
