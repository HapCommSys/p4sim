// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 TU Dresden. Author: Mingyu Ma <mingyu.ma@tu-dresden.de>

/*
 * NSQueueingLogicPriRL, the egress queue of the v1model and PSA switches.
 *
 * Not tested on purpose, because the comments and the code disagree and the
 * intended timing model is still open: the spacing before set_rate() is called
 * ("no rate limit" vs. 1 ms) and whether the first element waits one interval.
 */

#include "ns3/p4-queue.h"
#include "ns3/simulator.h"
#include "ns3/test.h"

#include <vector>

using namespace ns3;

namespace
{

/// Test case that destroys the simulator in DoTeardown(), also after a failed assertion
class P4TestCase : public TestCase
{
  protected:
    using TestCase::TestCase;

    void DoTeardown() override
    {
        Simulator::Destroy();
    }
};

/// All queues are served by worker 0, as in the p4sim switches
struct SingleWorker
{
    /// \return the worker of a queue
    size_t operator()(size_t) const
    {
        return 0;
    }
};

using Queue = NSQueueingLogicPriRL<int, SingleWorker>; //!< Queue under test

/// An element taken out of the queue
struct Out
{
    Time time;       //!< When it was taken out
    size_t port;     //!< Logical queue (egress port)
    size_t priority; //!< Priority queue index
    int item;        //!< The element
};

/// Take out every due element at each multiple of \p step up to \p end
void
Poll(Queue& queue, std::vector<Out>& out, Time step, Time end)
{
    for (Time t = Seconds(0); t <= end; t += step)
    {
        Simulator::Schedule(t, [&queue, &out]() {
            for (int item = 0; item != -1;)
            {
                size_t port = 0;
                size_t priority = 0;
                item = -1;
                queue.pop_back(0, &port, &priority, &item);
                if (item != -1)
                {
                    out.push_back({Simulator::Now(), port, priority, item});
                }
            }
        });
    }
    Simulator::Run();
}

} // namespace

/**
 * \ingroup p4sim-tests
 * A full queue drops new elements; set_capacity() changes the limit; an empty
 * queue returns nothing.
 */
class P4QueueCapacityTestCase : public P4TestCase
{
  public:
    P4QueueCapacityTestCase()
        : P4TestCase("Capacity: a full queue drops, an empty queue returns nothing")
    {
    }

  private:
    void DoRun() override
    {
        Queue queue(1, 2, SingleWorker(), 1);
        NS_TEST_EXPECT_MSG_EQ(queue.push_front(0, 1), 1, "First element dropped");
        NS_TEST_EXPECT_MSG_EQ(queue.push_front(0, 2), 1, "Second element dropped");
        NS_TEST_EXPECT_MSG_EQ(queue.push_front(0, 3), 0, "A full queue accepted an element");
        NS_TEST_EXPECT_MSG_EQ(queue.size(0), 2u, "Wrong occupancy");
        queue.set_capacity(0, 3);
        NS_TEST_EXPECT_MSG_EQ(queue.push_front(0, 3), 1, "set_capacity() had no effect");

        Queue empty(1, 2, SingleWorker(), 1);
        size_t port = 42;
        int item = -7;
        empty.pop_back(0, &port, &item);
        NS_TEST_EXPECT_MSG_EQ(item, -7, "An empty queue returned an element");
    }
};

/**
 * \ingroup p4sim-tests
 * With set_rate(R), the elements of a port leave in FIFO order exactly 1/R apart,
 * and a busy port does not delay another port.
 */
class P4QueueRateTestCase : public P4TestCase
{
  public:
    P4QueueRateTestCase()
        : P4TestCase("Rate: FIFO, one interval apart, ports independent")
    {
    }

  private:
    void DoRun() override
    {
        Queue queue(1, 10, SingleWorker(), 1);
        for (size_t port : {0, 1})
        {
            queue.set_rate(port, 1000); // one element per ms
            for (int i = 0; i < 3; i++)
            {
                queue.push_front(port, static_cast<int>(10 * port) + i);
            }
        }
        NS_TEST_EXPECT_MSG_EQ(queue.get_this_pkt_delay(0, 0), MilliSeconds(1), "Wrong interval");

        std::vector<Out> out;
        Poll(queue, out, MicroSeconds(250), MilliSeconds(10));
        std::vector<Out> ports[2];
        for (const auto& o : out)
        {
            ports[o.port].push_back(o);
        }
        NS_TEST_ASSERT_MSG_EQ(ports[0].size(), 3u, "Port 0 lost elements");
        NS_TEST_ASSERT_MSG_EQ(ports[1].size(), 3u, "Port 1 lost elements");
        if (ports[0].size() != 3 || ports[1].size() != 3)
        {
            return;
        }
        for (size_t i = 0; i < 3; i++)
        {
            NS_TEST_EXPECT_MSG_EQ(ports[0][i].item, static_cast<int>(i), "Not FIFO");
            NS_TEST_EXPECT_MSG_EQ(ports[1][i].time, ports[0][i].time, "Port 1 delayed by port 0");
            if (i > 0)
            {
                NS_TEST_EXPECT_MSG_EQ(ports[0][i].time - ports[0][i - 1].time,
                                      MilliSeconds(1),
                                      "Elements not 1 ms apart");
            }
        }
    }
};

/**
 * \ingroup p4sim-tests
 * When elements of several priority queues are due, the highest index leaves
 * first. (The switches put priority p into index N-1-p, so priority 0 goes first.)
 */
class P4QueuePriorityTestCase : public P4TestCase
{
  public:
    P4QueuePriorityTestCase()
        : P4TestCase("Priority: the highest index leaves first")
    {
    }

  private:
    void DoRun() override
    {
        Queue queue(1, 10, SingleWorker(), 3);
        queue.set_rate(0, 1000);
        for (size_t priority : {0, 2, 1})
        {
            queue.push_front(0, priority, static_cast<int>(100 + priority));
        }
        std::vector<Out> out;
        Poll(queue, out, MilliSeconds(5), MilliSeconds(5)); // once, when all are due
        NS_TEST_ASSERT_MSG_EQ(out.size(), 3u, "Elements lost");
        if (out.size() != 3)
        {
            return;
        }
        for (size_t i = 0; i < 3; i++)
        {
            NS_TEST_EXPECT_MSG_EQ(out[i].priority, 2 - i, "Wrong priority order");
        }
    }
};

/**
 * \ingroup p4sim-tests
 * Egress queue tests.
 */
class P4QueueTestSuite : public TestSuite
{
  public:
    P4QueueTestSuite()
        : TestSuite("p4-queue", TestSuite::Type::UNIT)
    {
        AddTestCase(new P4QueueCapacityTestCase, TestCase::Duration::QUICK);
        AddTestCase(new P4QueueRateTestCase, TestCase::Duration::QUICK);
        AddTestCase(new P4QueuePriorityTestCase, TestCase::Duration::QUICK);
    }
};

static P4QueueTestSuite g_p4QueueTestSuite; //!< Static variable for test initialization
