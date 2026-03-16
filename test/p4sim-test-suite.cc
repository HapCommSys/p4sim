// An essential include is test.h
#include "ns3/test.h"
#include "ns3/log.h"
#include "ns3/assert.h"

// Do not put your test classes in namespace ns3.  You may find it useful
// to use the using directive to access the ns3 namespace directly
using namespace ns3;

// Add a doxygen group for tests.
// If you have more than one test, this should be in only one of them.
/**
 * \defgroup p4sim-tests Tests for p4sim
 * \ingroup p4sim
 * \ingroup tests
 */

// This is an example TestCase.
/**
 * \ingroup p4sim-tests
 * Test case for feature 1
 */
class P4simTestCase1 : public TestCase
{
public:
  P4simTestCase1 ();
  virtual ~P4simTestCase1 ();

private:
  void DoRun () override;
};

// Add some help text to this case to describe what it is intended to test
P4simTestCase1::P4simTestCase1 () : TestCase ("P4sim test case (does nothing)")
{
}

// This destructor does nothing but we include it as a reminder that
// the test case should clean up after itself
P4simTestCase1::~P4simTestCase1 ()
{
}

//
// This method is the pure virtual method from class TestCase that every
// TestCase must implement
//
void
P4simTestCase1::DoRun ()
{
  // A wide variety of test macros are available in src/core/test.h
  NS_TEST_ASSERT_MSG_EQ (true, true, "true doesn't equal true for some reason");
  // Use this one for floating point comparisons
  NS_TEST_ASSERT_MSG_EQ_TOL (0.01, 0.01, 0.001, "Numbers are not equal within tolerance");
}

// The TestSuite class names the TestSuite, identifies what type of TestSuite,
// and enables the TestCases to be run.  Typically, only the constructor for
// this class must be defined

/**
 * \ingroup p4sim-tests
 * TestSuite for module p4sim
 */
class P4simTestSuite : public TestSuite
{
public:
  P4simTestSuite ();
};

P4simTestSuite::P4simTestSuite () : TestSuite ("p4sim", Type::UNIT)
{
  // Duration for TestCase can be QUICK, EXTENSIVE or TAKES_FOREVER
  AddTestCase (new P4simTestCase1, QUICK);
}

// Do not forget to allocate an instance of this TestSuite
/**
 * \ingroup p4sim-tests
 * Static variable for test initialization
 */
static P4simTestSuite sp4simTestSuite;
