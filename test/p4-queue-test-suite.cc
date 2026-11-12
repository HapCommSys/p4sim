/*
 * Copyright (c) 2025 TU Dresden
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/*
 * Unit tests of NSQueueingLogicPriRL, the egress queue of the v1model and PSA
 * switches: capacity, rate limiting, FIFO order, priorities and independent
 * per-port queues. No P4 switch or BMv2 pipeline is involved.
 *
 * Only behaviour that the queue documents unambiguously is checked. Two open
 * points of the timing model are deliberately not pinned down here: the
 * spacing used before set_rate() is called (the comments say "no rate limit",
 * the code uses 1 ms) and whether the first packet waits one interval.
 */

#include "ns3/p4-queue.h"
#include "ns3/simulator.h"
#include "ns3/test.h"

#include <vector>

using namespace ns3;

namespace
{

/// All queues are served by a single worker, as in the p4sim switches
struct SingleWorkerMapper
{
    /// \return the worker of a queue (always 0)
    size_t operator()(size_t /* queueId */) const
    {
        return 0;
    }
};

using TestQueue = NSQueueingLogicPriRL<int, SingleWorkerMapper>; //!< Queue under test

/// One element taken out of the queue
struct Popped
{
    Time time;       //!< When it was taken out
    size_t queueId;  //!< Logical queue (egress port)
    size_t priority; //!< Priority queue index
    int item;        //!< The element
};

/**
 * Poll the queue every \p step until \p end, as the switch egress timer does,
 * and record every element taken out.
 */
void
PollQueue(TestQueue& queue, std::vector<Popped>& out, Time step, Time end)
{
    for (Time t = Seconds(0); t <= end; t += step)
    {
        Simulator::Schedule(t, [&queue, &out]() {
            // Several elements can be due at the same time: take all of them.
            while (true)
            {
                size_t queueId = 0;
                size_t priority = 0;
                int item = -1;
                queue.pop_back(0, &queueId, &priority, &item);
                if (item == -1)
                {
                    break;
                }
                out.push_back({Simulator::Now(), queueId, priority, item});
            }
        });
    }
}

} // namespace

/**
 * \ingroup p4sim-tests
 * A full priority queue drops new elements, and set_capacity() changes the limit.
 */
class P4QueueCapacityTestCase : public TestCase
{
  public:
    P4QueueCapacityTestCase()
        : TestCase("A full queue drops new elements")
    {
    }

  private:
    void DoRun() override
    {
        TestQueue queue(1, 3, SingleWorkerMapper(), 1);
        for (int i = 0; i < 3; i++)
        {
            NS_TEST_ASSERT_MSG_EQ(queue.push_front(0, i), 1, "Element " << i << " was dropped");
        }
        NS_TEST_ASSERT_MSG_EQ(queue.push_front(0, 3), 0, "A full queue accepted an element");
        NS_TEST_ASSERT_MSG_EQ(queue.size(0), 3, "Wrong occupancy of the logical queue");
        NS_TEST_ASSERT_MSG_EQ(queue.size(0, 0), 3, "Wrong occupancy of the priority queue");
        NS_TEST_ASSERT_MSG_EQ(queue.size(1), 0, "An unused queue is not empty");

        queue.set_capacity(0, 4);
        NS_TEST_ASSERT_MSG_EQ(queue.push_front(0, 3), 1, "set_capacity() did not raise the limit");
        NS_TEST_ASSERT_MSG_EQ(queue.push_front(0, 4), 0, "The new limit is not enforced");
        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * Taking an element out of an empty queue returns nothing and leaves the
 * output untouched (the switch relies on this to detect an empty queue).
 */
class P4QueueEmptyTestCase : public TestCase
{
  public:
    P4QueueEmptyTestCase()
        : TestCase("pop_back() on an empty queue returns nothing")
    {
    }

  private:
    void DoRun() override
    {
        TestQueue queue(1, 3, SingleWorkerMapper(), 1);
        size_t queueId = 42;
        int item = -7;
        queue.pop_back(0, &queueId, &item);
        NS_TEST_ASSERT_MSG_EQ(item, -7, "pop_back() changed the output of an empty queue");
        NS_TEST_ASSERT_MSG_EQ(queueId, 42, "pop_back() changed the queue id of an empty queue");
        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * With set_rate(), elements leave in FIFO order, exactly 1/rate apart, and
 * never before they are due.
 */
class P4QueueRateTestCase : public TestCase
{
  public:
    P4QueueRateTestCase()
        : TestCase("Elements leave in FIFO order, 1/rate apart")
    {
    }

  private:
    void DoRun() override
    {
        TestQueue queue(1, 10, SingleWorkerMapper(), 1);
        queue.set_rate(0, 1000); // 1000 elements per second: one per ms
        NS_TEST_ASSERT_MSG_EQ(queue.get_this_pkt_delay(0, 0),
                              MilliSeconds(1),
                              "Wrong interval for 1000 elements per second");

        for (int i = 0; i < 4; i++)
        {
            NS_TEST_ASSERT_MSG_EQ(queue.push_front(0, i), 1, "Element " << i << " was dropped");
        }
        std::vector<Popped> out;
        PollQueue(queue, out, MicroSeconds(250), MilliSeconds(10));
        Simulator::Run();

        NS_TEST_ASSERT_MSG_EQ(out.size(), 4, "Not all elements left the queue");
        for (size_t i = 0; i < out.size(); i++)
        {
            NS_TEST_EXPECT_MSG_EQ(out[i].item, static_cast<int>(i), "Elements left out of order");
        }
        for (size_t i = 1; i < out.size(); i++)
        {
            NS_TEST_EXPECT_MSG_EQ(out[i].time - out[i - 1].time,
                                  MilliSeconds(1),
                                  "Elements " << i - 1 << " and " << i << " are not 1 ms apart");
        }
        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * When elements of several priority queues are due, the highest index is served
 * first. (The v1model and PSA switches put priority p into index N-1-p, so
 * priority 0 is served first.)
 */
class P4QueuePriorityTestCase : public TestCase
{
  public:
    P4QueuePriorityTestCase()
        : TestCase("The highest priority index is served first")
    {
    }

  private:
    void DoRun() override
    {
        TestQueue queue(1, 10, SingleWorkerMapper(), 3);
        queue.set_rate(0, 1000);
        NS_TEST_ASSERT_MSG_EQ(queue.push_front(0, 0, 100), 1, "Element of index 0 was dropped");
        NS_TEST_ASSERT_MSG_EQ(queue.push_front(0, 2, 102), 1, "Element of index 2 was dropped");
        NS_TEST_ASSERT_MSG_EQ(queue.push_front(0, 1, 101), 1, "Element of index 1 was dropped");

        // Poll once, after all three are due.
        std::vector<Popped> out;
        PollQueue(queue, out, MilliSeconds(5), MilliSeconds(5));
        Simulator::Run();

        NS_TEST_ASSERT_MSG_EQ(out.size(), 3, "Not all elements left the queue");
        NS_TEST_EXPECT_MSG_EQ(out[0].priority, 2, "Index 2 was not served first");
        NS_TEST_EXPECT_MSG_EQ(out[1].priority, 1, "Index 1 was not served second");
        NS_TEST_EXPECT_MSG_EQ(out[2].priority, 0, "Index 0 was not served last");
        NS_TEST_EXPECT_MSG_EQ(out[0].item, 102, "Wrong element for index 2");
        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * Each logical queue (egress port) has its own rate limit: a busy port does
 * not delay another port.
 */
class P4QueuePerPortTestCase : public TestCase
{
  public:
    P4QueuePerPortTestCase()
        : TestCase("Each egress port is rate limited independently")
    {
    }

  private:
    void DoRun() override
    {
        TestQueue queue(1, 10, SingleWorkerMapper(), 1);
        queue.set_rate(0, 1000);
        queue.set_rate(1, 1000);
        for (int i = 0; i < 3; i++)
        {
            queue.push_front(0, i);      // port 0: 0, 1, 2
            queue.push_front(1, 10 + i); // port 1: 10, 11, 12
        }
        std::vector<Popped> out;
        PollQueue(queue, out, MicroSeconds(250), MilliSeconds(10));
        Simulator::Run();

        NS_TEST_ASSERT_MSG_EQ(out.size(), 6, "Not all elements left the queues");
        std::vector<Time> port0;
        std::vector<Time> port1;
        for (const auto& p : out)
        {
            (p.queueId == 0 ? port0 : port1).push_back(p.time);
        }
        NS_TEST_ASSERT_MSG_EQ(port0.size(), 3, "Wrong number of elements from port 0");
        NS_TEST_ASSERT_MSG_EQ(port1.size(), 3, "Wrong number of elements from port 1");
        for (size_t i = 0; i < 3; i++)
        {
            NS_TEST_EXPECT_MSG_EQ(port0[i],
                                  port1[i],
                                  "Port 1 was delayed by port 0 (element " << i << ")");
        }
        Simulator::Destroy();
    }
};

/**
 * \ingroup p4sim-tests
 * Unit tests of the egress queue NSQueueingLogicPriRL.
 */
class P4QueueTestSuite : public TestSuite
{
  public:
    P4QueueTestSuite()
        : TestSuite("p4-queue", UNIT)
    {
        AddTestCase(new P4QueueCapacityTestCase, TestCase::QUICK);
        AddTestCase(new P4QueueEmptyTestCase, TestCase::QUICK);
        AddTestCase(new P4QueueRateTestCase, TestCase::QUICK);
        AddTestCase(new P4QueuePriorityTestCase, TestCase::QUICK);
        AddTestCase(new P4QueuePerPortTestCase, TestCase::QUICK);
    }
};

static P4QueueTestSuite g_p4QueueTestSuite; //!< Static variable for test initialization
