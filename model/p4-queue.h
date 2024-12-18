#ifndef P4_QUEUE_H
#define P4_QUEUE_H

#include <map>
#include <queue>
#include <condition_variable>
#include <mutex>

#include "p4-queue-item.h"
#include "ns3/object.h"
#include "ns3/random-variable-stream.h"
#include "ns3/simulator.h"

namespace ns3 {

/**
 * \brief Multi-port P4Queuebuffer with priority-based virtual queues
 */
class P4Queuebuffer : public Object
{
public:
  /**
   * \brief Constructor
   * \param nPorts Number of ports
   * \param nPriorities Number of priorities per port
   */
  P4Queuebuffer (uint32_t nPorts, uint32_t nPriorities);

  /**
   * \brief Destructor
   */
  virtual ~P4Queuebuffer ();

  /**
   * \brief Enqueue a packet into the appropriate port and priority queue
   * \param item The queue item to enqueue
   * \return True if enqueued successfully, false otherwise
   */
  bool Enqueue (Ptr<P4QueueItem> item);

  /**
   * \brief Dequeue a packet from the specified port and priority queue
   * \return The dequeued item, or nullptr if the queue is empty
   */
  Ptr<P4QueueItem> Dequeue ();

  /**
   * \brief Dequeue a packet from the specified port and priority queue
   * \param port The target port
   * \return The dequeued item, or nullptr if the queue is empty
   */
  Ptr<P4QueueItem> Dequeue (uint32_t port);

  /**
   * \brief Set the random seed for the queue
   * \param seed The random seed to set
   * \return True if the seed is set successfully, false otherwise
   */
  bool SetRandomSeed (uint32_t seed);

  /**
   * \brief Peek at the packet at the front of the specified port and priority queue
   * \param port The target port
   * \return The peeked item, or nullptr if the queue is empty
   */
  Ptr<P4QueueItem> Peek (uint32_t port);

  /**
   * \brief Peek at the packet at the front of the specified port and priority queue
   * \return The peeked item, or nullptr if the queue is empty
   */
  Ptr<P4QueueItem> Peek ();

  /**
   * \brief Check if the queue is empty for a specific port
   * \param port The port to check
   * \return True if the queue is empty, false otherwise
   */
  bool IsEmpty (uint32_t port) const;

  /**
   * \brief Get the total length of all queues for a specific port
   * \param port The port to check
   * \return The total length of all queues for the port
   */
  uint32_t GetQueueTotalLengthPerPort (uint8_t port) const;

  /**
   * \brief Get the virtual queue length for a specific port and priority
   * \param port The port to check
   * \param priority The priority to check
   * \return The virtual queue length for the port and priority
   */
  uint32_t GetVirtualQueueLengthPerPort (uint8_t port, uint8_t priority) const;

  /**
   * \brief Reset the virtual queue number, because the number of queues is changed
   * 
   * \return True if the change the port number, false otherwise
   */
  bool ReSetVirtualQueueNumber (uint32_t newSize);

  bool AddVirtualQueue (uint32_t port_num);

  bool RemoveVirtualQueue (uint32_t port_num);

private:
  uint32_t m_nPorts; //!< Number of ports
  uint32_t m_nPriorities; //!< Number of priorities per port
  Ptr<UniformRandomVariable> m_rng; //!< Random number generator

  bool is_peek_marked{false}; //!< Mark the peek packet
  uint32_t marked_port{0}; //!< Port of the marked packet

  // Map of ports to priority queues
  std::map<uint32_t, std::vector<std::queue<Ptr<P4QueueItem>>>> m_queues;
};

/**
 * \brief A two-tier priority queue for P4QueueItem. This is used for the Input
 * Queue Buffer (before Parser) in the P4SwitchCore model.
 * 
 */
class TwoTierP4Queue : public Object
{
public:
  /**
   * \brief Constructor
   */
  TwoTierP4Queue ();

  /**
   * \brief Destructor
   */
  virtual ~TwoTierP4Queue ();

  void Initialize ();

  /**
   * \brief Enqueue a packet into the appropriate queue
   * \param item The queue item to enqueue
   * \return True if enqueued successfully, false otherwise
   */
  bool Enqueue (Ptr<P4QueueItem> item);

  /**
   * \brief Dequeue a packet from the queues (high priority first)
   * \return The dequeued item, or nullptr if both queues are empty
   */
  Ptr<P4QueueItem> Dequeue ();

  /**
   * \brief Check if both queues are empty
   * \return True if both queues are empty, false otherwise
   */
  bool IsEmpty () const;

private:
  std::queue<Ptr<P4QueueItem>> m_highPriorityQueue; //!< High-priority queue
  std::queue<Ptr<P4QueueItem>> m_lowPriorityQueue; //!< Low-priority queue
};

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
  enum class PacketType {
    NORMAL,
    RESUBMIT,
    RECIRCULATE,
    SENTINEL // signal for the ingress thread to terminate
  };

  InputBuffer (size_t capacity_hi, size_t capacity_lo)
      : capacity_hi (capacity_hi), capacity_lo (capacity_lo)
  {
  }

  int
  push_front (PacketType packet_type, std::unique_ptr<bm::Packet> &&item)
  {
    switch (packet_type)
      {
      case PacketType::NORMAL:
        return push_front (&queue_lo, capacity_lo, &cvar_can_push_lo, std::move (item), true);
      case PacketType::RESUBMIT:
      case PacketType::RECIRCULATE:
        return push_front (&queue_hi, capacity_hi, &cvar_can_push_hi, std::move (item), false);
      case PacketType::SENTINEL:
        return push_front (&queue_hi, capacity_hi, &cvar_can_push_hi, std::move (item), true);
      }
    NS_FATAL_ERROR ("Unreachable statement");
    return 0;
  }

  void
  pop_back (std::unique_ptr<bm::Packet> *pItem)
  {
    if (queue_hi.size () > 0 || queue_lo.size () > 0)
      {
        Lock lock (mutex);
        cvar_can_pop.wait (lock, [this] { return (queue_hi.size () + queue_lo.size ()) > 0; });
        // give higher priority to resubmit/recirculate queue
        if (queue_hi.size () > 0)
          {
            *pItem = std::move (queue_hi.back ());
            queue_hi.pop_back ();
            lock.unlock ();
            cvar_can_push_hi.notify_one ();
          }
        else
          {
            *pItem = std::move (queue_lo.back ());
            queue_lo.pop_back ();
            lock.unlock ();
            cvar_can_push_lo.notify_one ();
          }
      }
  }
  size_t
  get_size ()
  {
    return capacity_hi + capacity_lo;
  }

private:
  using Mutex = std::mutex;
  using Lock = std::unique_lock<Mutex>;
  using QueueImpl = std::deque<std::unique_ptr<bm::Packet>>;

  int
  push_front (QueueImpl *queue, size_t capacity, std::condition_variable *cvar,
              std::unique_ptr<bm::Packet> &&item, bool blocking)
  {
    Lock lock (mutex);
    while (queue->size () == capacity)
      {
        if (!blocking)
          return 0;
        cvar->wait (lock);
      }
    queue->push_front (std::move (item));
    lock.unlock ();
    cvar_can_pop.notify_one ();
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
 * @brief A simple priority queueing logic for ns-3 p4simulator.
 * 
 * [from bmv2 author]
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
  NSQueueingLogicPriRL (size_t nb_workers, size_t capacity, FMap map_to_worker,
                        size_t nb_priorities = 2)
      : nb_workers (nb_workers),
        capacity (capacity),
        workers_info (nb_workers),
        map_to_worker (std::move (map_to_worker)),
        nb_priorities (nb_priorities)
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
  int
  push_front (size_t queue_id, size_t priority, const T &item)
  {
    size_t worker_id = map_to_worker (queue_id);
    LockType lock (mutex);
    auto &q_info = get_queue (queue_id);
    auto &w_info = workers_info.at (worker_id);
    auto &q_info_pri = q_info.at (priority);
    if (q_info_pri.size >= q_info_pri.capacity)
      return 0;
    q_info_pri.last_sent = get_next_tp (q_info_pri);
    w_info.queues[priority].emplace (item, queue_id, q_info_pri.last_sent,
                                     w_info.wrapping_counter++);
    q_info_pri.size++;
    q_info.size++;
    w_info.size++;
    w_info.q_not_empty.notify_one ();
    return 1;
  }

  /**
   * @brief  Place the packet in the queue. The state is priority queue not 
   * enabled.
   * 
   * @param queue_id each egress port will have a queue_id
   * @param item the packet or things to be placed in the queue
   * @return int 
   */
  int
  push_front (size_t queue_id, const T &item)
  {
    return push_front (queue_id, 0, item);
  }

  //! Same as push_front(size_t queue_id, size_t priority, const T &item), but
  //! \p item is moved instead of copied.
  int
  push_front (size_t queue_id, size_t priority, T &&item)
  {
    size_t worker_id = map_to_worker (queue_id);
    LockType lock (mutex);
    auto &q_info = get_queue (queue_id);
    auto &w_info = workers_info.at (worker_id);
    auto &q_info_pri = q_info.at (priority);
    if (q_info_pri.size >= q_info_pri.capacity)
      return 0;
    q_info_pri.last_sent = get_next_tp (q_info_pri);
    w_info.queues[priority].emplace (std::move (item), queue_id, q_info_pri.last_sent,
                                     w_info.wrapping_counter++);
    q_info_pri.size++;
    q_info.size++;
    w_info.size++;
    w_info.q_not_empty.notify_one ();
    return 1;
  }

  int
  push_front (size_t queue_id, T &&item)
  {
    return push_front (queue_id, 0, std::move (item));
  }

  /**
   * @brief The exit end of the priority queue is prioritized. (itself bmv2 code 
   * through the lock mechanism, but ns-3 does not have a built-in locking 
   * mechanism ns3 in the replacement for the polling mechanism, so there will
   * be some loss in performance)
   * 
   * [from bmv2 author]
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
  void
  pop_back (size_t worker_id, size_t *queue_id, size_t *priority, T *pItem)
  {
    LockType lock (mutex);
    auto &w_info = workers_info.at (worker_id);
    MyQ *queue = nullptr;
    size_t pri;
    while (true)
      {
        if (w_info.size == 0)
          {
            // w_info.q_not_empty.wait(lock); // Empty queue, wait until lock state changes (add pkts)
            // will take out the null, but leave the detection step to a later process
            return;
          }
        else
          {
            // There's a pkt in the queue.
            Time now = Simulator::Now ();
            Time next = now + Seconds (10); // set 10s as the max interval for one packet process.
            for (pri = 0; pri < nb_priorities; pri++)
              {
                auto &q = w_info.queues[pri];
                if (q.size () == 0)
                  continue;
                if (q.top ().send <= now)
                  {
                    queue = &q;
                    break;
                  }
                next = (next < q.top ().send) ? next : q.top ().send;
              }
            if (queue)
              break;
            // At this point the queue is empty again, waiting for the lock state to change (add pkts)
            // Null will be taken out, but the detection step is left to a later process
            return;
          }
      }
    *queue_id = queue->top ().queue_id;
    *priority = pri;
    // TODO(antonin): improve / document this
    // http://stackoverflow.com/questions/20149471/move-out-element-of-std-priority-queue-in-c11
    *pItem = std::move (const_cast<QE &> (queue->top ()).e);
    queue->pop ();
    auto &q_info = get_queue_or_throw (*queue_id);
    auto &q_info_pri = q_info.at (*priority);
    q_info_pri.size--;
    q_info.size--;
    w_info.size--;
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
  void
  pop_back (size_t worker_id, size_t *queue_id, T *pItem)
  {
    size_t priority;
    return pop_back (worker_id, queue_id, &priority, pItem);
  }

  /**
   * @brief  QueueingLogic::size
   * @copydoc QueueingLogic::size
   * The occupancies of all the priority queues for this logical queue are 
   * added.
   * @param queue_id the queue_id of logical queue in each egress port
   * @return size_t 
   */
  size_t
  size (size_t queue_id) const
  {
    LockType lock (mutex);
    auto it = queues_info.find (queue_id);
    if (it == queues_info.end ())
      return 0;
    auto &q_info = it->second;
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
  size_t
  size (size_t queue_id, size_t priority) const
  {
    LockType lock (mutex);
    auto it = queues_info.find (queue_id);
    if (it == queues_info.end ())
      return 0;
    auto &q_info = it->second;
    auto &q_info_pri = q_info.at (priority);
    return q_info_pri.size;
  }

  /**
   * @brief Set the capacity of all the priority queues for logical 
   * queue \p queue_id to \p c elements.
   * 
   * @param queue_id the id of logical queue in each egress port
   * @param c number of packets in queue
   */
  void
  set_capacity (size_t queue_id, size_t c)
  {
    LockType lock (mutex);
    for_each_q (queue_id, SetCapacityFn (c));
  }

  /**
   * @brief Set the capacity of priority queue with \p priority for 
   * logical queue \p queue_id to \p c elements.
   * 
   * @param queue_id the id of logical queue in each egress port
   * @param priority the \p priority number of one logical queue
   * @param c number of packets in one priority queue
   */
  void
  set_capacity (size_t queue_id, size_t priority, size_t c)
  {
    LockType lock (mutex);
    for_one_q (queue_id, priority, SetCapacityFn (c));
  }

  /**
   * @brief Set the capacity of all the priority queues of all 
   * logical queues to \p c elements.
   * 
   * @param c number of packets in one priority queue
   */
  void
  set_capacity_for_all (size_t c)
  {
    LockType lock (mutex);
    for (auto &p : queues_info)
      for_each_q (p.first, SetCapacityFn (c));
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
  void
  set_rate (size_t queue_id, uint64_t pps)
  {
    LockType lock (mutex);
    for_each_q (queue_id, SetRateFn (pps));
  }

  /**
   * @brief Set the rate object
   * Same as set_rate(size_t queue_id, uint64_t pps) but only applies 
   * to the given priority queue.
   * @param queue_id the id of logical queue in each egress port
   * @param priority the prirority of the packet in one logical queue 
   * @param pps packets per second
   */
  void
  set_rate (size_t queue_id, size_t priority, uint64_t pps)
  {
    LockType lock (mutex);
    for_one_q (queue_id, priority, SetRateFn (pps));
  }

  /**
   * @brief Set the rate of all the priority queues of all logical 
   * queues to \p pps.
   * 
   * @param pps 
   */
  void
  set_rate_for_all (uint64_t pps)
  {
    LockType lock (mutex);
    for (auto &p : queues_info)
      for_each_q (p.first, SetRateFn (pps));
    queue_rate_pps = pps;
  }

  //! Deleted copy constructor
  NSQueueingLogicPriRL (const NSQueueingLogicPriRL &) = delete;
  //! Deleted copy assignment operator
  NSQueueingLogicPriRL &operator= (const NSQueueingLogicPriRL &) = delete;

  //! Deleted move constructor
  NSQueueingLogicPriRL (NSQueueingLogicPriRL &&) = delete;
  //! Deleted move assignment operator
  NSQueueingLogicPriRL &&operator= (NSQueueingLogicPriRL &&) = delete;

private:
  /**
   * @brief calculate the intermediate time interval for processing
   * one packet. 1 pps = 1 packet per second,  default is 1ms for 
   * one packet. pps should not set to 0.
   * 
   * @param pps 
   * @return constexpr Time 
   */
  static constexpr Time
  rate_to_time (uint64_t pps)
  {

    return (pps == 0) ? Seconds (0.001)
                      : Seconds (static_cast<double> (1. / static_cast<double> (pps)));
  }

  /**
   * @brief The control label of the packet, the queue it is in, 
   * the timestamp, etc.
   */
  struct QE
  {
    QE (T e, size_t queue_id, const Time &send, size_t id)
        : e (std::move (e)), queue_id (queue_id), send (send), id (id)
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
    bool
    operator() (const QE &lhs, const QE &rhs) const
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
    QueueInfoPri (size_t capacity, uint64_t queue_rate_pps)
        : capacity (capacity),
          queue_rate_pps (queue_rate_pps),
          pkt_delay_time (rate_to_time (queue_rate_pps)),
          last_sent (Simulator::Now ())
    {
    }

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
    QueueInfo (size_t capacity, uint64_t queue_rate_pps, size_t nb_priorities)
        : std::vector<QueueInfoPri> (nb_priorities, QueueInfoPri (capacity, queue_rate_pps))
    {
    }

    size_t size{0};
  };

  /**
   * @brief threads information from bmv2 src.
   * 
   */
  struct WorkerInfo
  {
    mutable std::condition_variable q_not_empty{};
    size_t size{0};
    std::array<MyQ, 32> queues;
    size_t wrapping_counter{0};
  };

  QueueInfo &
  get_queue (size_t queue_id)
  {
    auto it = queues_info.find (queue_id);
    if (it != queues_info.end ())
      return it->second;
    auto p = queues_info.emplace (queue_id, QueueInfo (capacity, queue_rate_pps, nb_priorities));
    return p.first->second;
  }

  const QueueInfo &
  get_queue_or_throw (size_t queue_id) const
  {
    return queues_info.at (queue_id);
  }

  QueueInfo &
  get_queue_or_throw (size_t queue_id)
  {
    return queues_info.at (queue_id);
  }

  Time
  get_next_tp (const QueueInfoPri &q_info_pri)
  {
    // Calculate when the next step should be sent
    return (Simulator::Now () > q_info_pri.last_sent + q_info_pri.pkt_delay_time)
               ? Simulator::Now ()
               : q_info_pri.last_sent + q_info_pri.pkt_delay_time;
  }

  template <typename Function>
  Function
  for_each_q (size_t queue_id, Function fn)
  {
    auto &q_info = get_queue (queue_id);
    for (auto &q_info_pri : q_info)
      fn (q_info_pri);
    return fn;
  }

  template <typename Function>
  Function
  for_one_q (size_t queue_id, size_t priority, Function fn)
  {
    auto &q_info = get_queue (queue_id);
    auto &q_info_pri = q_info.at (priority);
    fn (q_info_pri);
    return fn;
  }

  struct SetCapacityFn
  {
    explicit SetCapacityFn (size_t c) : c (c)
    {
    }

    void
    operator() (QueueInfoPri &info) const
    { // NOLINT(runtime/references)
      info.capacity = c;
    }

    size_t c;
  };

  struct SetRateFn
  {
    explicit SetRateFn (uint64_t pps) : pps (pps)
    {
      pkt_delay_time = rate_to_time (pps);
    }

    void
    operator() (QueueInfoPri &info) const
    { // NOLINT(runtime/references)
      info.queue_rate_pps = pps;
      info.pkt_delay_time = pkt_delay_time;
    }

    uint64_t pps;
    Time pkt_delay_time;
  };

  mutable MutexType mutex;
  size_t nb_workers;
  size_t capacity; // default capacity
  uint64_t queue_rate_pps{0}; // default rate
  std::unordered_map<size_t, QueueInfo> queues_info{};
  std::vector<WorkerInfo> workers_info{};
  std::vector<MyQ> queues{};
  FMap map_to_worker;
  size_t nb_priorities;
};


} // namespace ns3

#endif /* P4_QUEUE_H */
