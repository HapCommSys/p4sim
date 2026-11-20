/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "ns3/format-utils.h"
#include "ns3/p4sim-ns3-compat.h"

#include "ns3/log.h"
#include "ns3/test.h"

#include <climits>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("P4FormatUtilsTest");

/**
 * @brief TestCase for testing format-utils.h functions
 */
class FormatUtilsTestCase : public TestCase
{
public:
  FormatUtilsTestCase ();
  virtual ~FormatUtilsTestCase ();

private:
  virtual void DoRun () override;

  // Helper functions for assertions
  void TestIntToStr ();
  void TestStrToInt ();
  void TestStrToDouble ();
  void TestHexCharToInt ();
  void TestHexStrToBytes ();
  void TestIpStrToBytes ();
  void TestUint32IpToHex ();
  void TestIntToBytes ();
};

// Constructor
FormatUtilsTestCase::FormatUtilsTestCase ()
    : TestCase ("FormatUtils TestCase") // Test case description
{
}

// Destructor
FormatUtilsTestCase::~FormatUtilsTestCase ()
{
}

// Test runner
void
FormatUtilsTestCase::DoRun ()
{
  TestIntToStr ();
  TestStrToInt ();
  TestStrToDouble ();
  TestHexCharToInt ();
  TestHexStrToBytes ();
  TestIpStrToBytes ();
  TestUint32IpToHex ();
  TestIntToBytes ();
}

/**
 * @brief Test IntToStr function
 */
void
FormatUtilsTestCase::TestIntToStr ()
{
  // Test normal positive integers
  char *result = IntToStr (12345);
  NS_TEST_ASSERT_MSG_EQ (std::string (result), "12345", "IntToStr failed for positive numbers");
  delete[] result;

  // Test normal negative integers
  result = IntToStr (-6789);
  NS_TEST_ASSERT_MSG_EQ (std::string (result), "-6789", "IntToStr failed for negative numbers");
  delete[] result;

  // Test zero
  result = IntToStr (0);
  NS_TEST_ASSERT_MSG_EQ (std::string (result), "0", "IntToStr failed for zero");
  delete[] result;

  // Test maximum positive integer
  result = IntToStr (INT_MAX);
  NS_TEST_ASSERT_MSG_EQ (std::string (result), std::to_string (INT_MAX),
                         "IntToStr failed for INT_MAX");
  delete[] result;

  // Test for minimum negative integer
  result = IntToStr (INT_MIN);
  NS_TEST_ASSERT_MSG_EQ (std::string (result), std::to_string (INT_MIN),
                         "IntToStr failed for INT_MIN");
  delete[] result;

  // Test for single positive digit
  result = IntToStr (7);
  NS_TEST_ASSERT_MSG_EQ (std::string (result), "7",
                         "IntToStr failed for single digit positive number");
  delete[] result;

  // Test for single negative digit
  result = IntToStr (-3);
  NS_TEST_ASSERT_MSG_EQ (std::string (result), "-3",
                         "IntToStr failed for single digit negative number");
  delete[] result;

  // Test for negative numbers close to zero
  result = IntToStr (-1);
  NS_TEST_ASSERT_MSG_EQ (std::string (result), "-1", "IntToStr failed for negative one");
  delete[] result;

  // Test for positive numbers close to zero
  result = IntToStr (1);
  NS_TEST_ASSERT_MSG_EQ (std::string (result), "1", "IntToStr failed for positive one");
  delete[] result;
}

/**
 * @brief Test StrToInt function
 */
void
FormatUtilsTestCase::TestStrToInt ()
{
  NS_TEST_ASSERT_MSG_EQ (StrToInt ("12345"), 12345u, "StrToInt failed for decimal numbers");
  NS_TEST_ASSERT_MSG_EQ (StrToInt ("0x1a2b"), 6699u, "StrToInt failed for hexadecimal numbers");
  NS_TEST_ASSERT_MSG_EQ (StrToInt ("0b1101"), 13u, "StrToInt failed for binary numbers");

  NS_TEST_ASSERT_MSG_EQ (StrToInt ("0"), 0u, "StrToInt failed for zero");
}

/**
 * @brief Test StrToDouble function
 */
void
FormatUtilsTestCase::TestStrToDouble ()
{
  NS_TEST_ASSERT_MSG_EQ_TOL (StrToDouble ("12.34"), 12.34, 1e-6,
                             "StrToDouble failed for decimal values");
  NS_TEST_ASSERT_MSG_EQ_TOL (StrToDouble ("0.00123"), 0.00123, 1e-6,
                             "StrToDouble failed for small decimal values");
}

/**
 * @brief Test HexCharToInt function
 */
void
FormatUtilsTestCase::TestHexCharToInt ()
{
  NS_TEST_ASSERT_MSG_EQ (HexCharToInt ('a'), 10, "HexCharToInt failed for lowercase hex");
  NS_TEST_ASSERT_MSG_EQ (HexCharToInt ('F'), 15, "HexCharToInt failed for uppercase hex");
  NS_TEST_ASSERT_MSG_EQ (HexCharToInt ('0'), 0, "HexCharToInt failed for digit 0");
}

/**
 * @brief Test HexStrToBytes function
 */
void
FormatUtilsTestCase::TestHexStrToBytes ()
{
  NS_TEST_ASSERT_MSG_EQ (HexStrToBytes ("0x0a010001"), (std::string ("\x0a\x01\x00\x01", 4)),
                         "HexStrToBytes failed for valid input");

  NS_TEST_ASSERT_MSG_EQ (HexStrToBytes ("ff00"), (std::string ("\xff\x00", 2)),
                         "HexStrToBytes failed for short input");

  NS_TEST_EXPECT_MSG_EQ (HexStrToBytes ("0x123"), "",
                         "HexStrToBytes should fail for odd-length input");
  NS_TEST_EXPECT_MSG_EQ (HexStrToBytes ("zz00"), "",
                         "HexStrToBytes should fail for invalid characters");

  NS_TEST_ASSERT_MSG_EQ (HexStrToBytes (""), "", "HexStrToBytes failed for empty input");
}

/**
 * @brief Test IpStrToBytes function
 */
void
FormatUtilsTestCase::TestIpStrToBytes ()
{
  NS_TEST_ASSERT_MSG_EQ (IpStrToBytes ("10.1.0.1"), (std::string ("\x0a\x01\x00\x01", 4)),
                         "IpStrToBytes failed for valid IP address");
}

/**
 * @brief Test Uint32IpToHex function
 */
void
FormatUtilsTestCase::TestUint32IpToHex ()
{
  NS_TEST_ASSERT_MSG_EQ (Uint32IpToHex (167837697), "0x0a010001",
                         "Uint32IpToHex failed for valid input");
  NS_TEST_ASSERT_MSG_EQ (Uint32IpToHex (0), "0x00000000", "Uint32IpToHex failed for zero input");
}

/**
 * @brief Test IntToBytes function
 */
void
FormatUtilsTestCase::TestIntToBytes ()
{
  NS_TEST_ASSERT_MSG_EQ (IntToBytes ("123", 16), (std::string ("\x00\x7b", 2)), "IntToBytes failed for 16-bit width");
  NS_TEST_ASSERT_MSG_EQ (IntToBytes ("255", 8), "\xff", "IntToBytes failed for 8-bit width");
}

/**
 * @brief GetP4SimDir returns the p4sim folder of this build, whatever P4SIM_DIR
 * says. A P4SIM_DIR that names another folder is ignored, with one notice on
 * std::cerr; one that names this folder gives no notice.
 */
class P4SimDirTestCase : public TestCase
{
public:
  P4SimDirTestCase ()
      : TestCase ("GetP4SimDir: the p4sim folder of this build, whatever P4SIM_DIR says")
  {
  }

private:
  /// True if \p a and \p b exist and are the same folder
  static bool
  SameFolder (const std::string &a, const std::string &b)
  {
    std::error_code ec;
    return std::filesystem::equivalent (a, b, ec);
  }

  void
  DoRun () override
  {
    SetDataDir (NS_TEST_SOURCEDIR);
    const std::filesystem::path p4simDir =
        std::filesystem::canonical (CreateDataDirFilename (".."));
    const char *saved = std::getenv ("P4SIM_DIR");
    const std::string savedValue = (saved != nullptr) ? saved : "";

    std::ostringstream notices;
    std::streambuf *cerrBuffer = std::cerr.rdbuf (notices.rdbuf ());

    ::unsetenv ("P4SIM_DIR");
    const std::string withoutVariable = GetP4SimDir ();
    const std::string flowTable = GetP4ExamplePath () + "/simple_v1model/flowtable_0.txt";
    // This folder, spelled differently
    ::setenv ("P4SIM_DIR", (p4simDir / "test" / "..").c_str (), 1);
    const std::string thisFolder = GetP4SimDir ();
    const std::string noticesThisFolder = notices.str ();
    // Another folder, twice
    ::setenv ("P4SIM_DIR", p4simDir.parent_path ().c_str (), 1);
    const std::string otherFolder = GetP4SimDir ();
    GetP4SimDir ();

    std::cerr.rdbuf (cerrBuffer);
    if (savedValue.empty ())
      {
        ::unsetenv ("P4SIM_DIR");
      }
    else
      {
        ::setenv ("P4SIM_DIR", savedValue.c_str (), 1);
      }

    NS_TEST_EXPECT_MSG_EQ (SameFolder (withoutVariable, p4simDir), true,
                           "Without P4SIM_DIR: " << withoutVariable);
    NS_TEST_EXPECT_MSG_EQ (std::filesystem::exists (flowTable), true, "Not found: " << flowTable);
    NS_TEST_EXPECT_MSG_EQ (SameFolder (thisFolder, p4simDir), true,
                           "P4SIM_DIR names this folder: " << thisFolder);
    NS_TEST_EXPECT_MSG_EQ (noticesThisFolder, "", "A notice although P4SIM_DIR names this folder");
    NS_TEST_EXPECT_MSG_EQ (SameFolder (otherFolder, p4simDir), true,
                           "P4SIM_DIR names another folder: " << otherFolder);
    const std::string all = notices.str ();
    const std::string notice = "ignoring P4SIM_DIR";
    uint32_t count = 0;
    for (size_t pos = all.find (notice); pos != std::string::npos; pos = all.find (notice, pos + 1))
      {
        count++;
      }
    NS_TEST_EXPECT_MSG_EQ (count, 1, "Not one notice: " << all);
  }
};

/**
 * @brief TestSuite for format-utils.h
 */
class FormatUtilsTestSuite : public TestSuite
{
public:
  FormatUtilsTestSuite ();
};

FormatUtilsTestSuite::FormatUtilsTestSuite ()
    : TestSuite ("format-utils", TestSuite::Type::UNIT) // Test suite name and type
{
  AddTestCase (new FormatUtilsTestCase, P4SIM_TEST_QUICK);
  AddTestCase (new P4SimDirTestCase, P4SIM_TEST_QUICK);
}

// Register the test suite with NS-3
static FormatUtilsTestSuite formatUtilsTestSuite;

} // namespace ns3
