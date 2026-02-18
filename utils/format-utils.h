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

#ifndef FORMAT_UTILS_H
#define FORMAT_UTILS_H

#include <cstdint>
#include <string>

namespace ns3
{

/**
 * @brief Convert an integer to a string.
 *
 * @param num Integer to be converted.
 * @return A dynamically allocated C-string containing the integer representation.
 *         Caller is responsible for deleting the returned string.
 */
char* IntToStr(int num);

/**
 * @brief Convert a string to an unsigned integer.
 *
 * Supports:
 * - Hexadecimal strings prefixed with "0x" (e.g., "0x12a").
 * - Binary strings prefixed with "0b" (e.g., "0b110").
 * - Decimal strings without prefixes (e.g., "123").
 *
 * @param str Input string.
 * @return The unsigned integer value.
 * @throws std::invalid_argument if the string contains invalid characters.
 */
unsigned int StrToInt(const std::string& str);

/**
 * @brief Convert a string to a double-precision floating-point value.
 *
 * Handles standard decimal numbers (e.g., "12.34").
 *
 * @param str Input string.
 * @return The double value.
 * @throws std::invalid_argument if the string contains invalid characters.
 */
double StrToDouble(const std::string& str);

/**
 * @brief Convert a single hexadecimal character to its integer value.
 *
 * @param c Input hexadecimal character ('0'-'9', 'a'-'f', 'A'-'F').
 * @return The integer value of the hexadecimal character.
 * @throws std::invalid_argument if the character is not a valid hexadecimal digit.
 */
int HexCharToInt(char c);

/**
 * @brief Convert a hexadecimal string to a binary byte string.
 *
 * Removes the "0x" prefix if present and converts each pair of hexadecimal
 * characters into a single byte.
 *
 * Example:
 *   Input: "0x0a010001"
 *   Output: "\x0a\x01\x00\x01" (binary string with 4 bytes)
 *
 * @param str Input hexadecimal string.
 * @return A binary string.
 * @throws std::invalid_argument if the string contains invalid characters.
 */
std::string HexStrToBytes(const std::string& str);

/**
 * @brief Convert a truncated hexadecimal string to a binary byte string based on bit width.
 *
 * Removes the "0x" prefix if present and converts the hexadecimal characters into
 * bytes, truncating based on the provided bit width.
 *
 * Example:
 *   Input: "0x0a010001", bitWidth = 24
 *   Output: "\x0a\x01\x00" (binary string with 3 bytes)
 *
 * @param str Input hexadecimal string.
 * @param bitWidth Bit width to truncate to (e.g., 32, 24, 16, 8).
 * @return A truncated binary string.
 * @throws std::invalid_argument if the string contains invalid characters.
 */
std::string HexStrToBytes(const std::string& str, unsigned int bitWidth);

/**
 * @brief Convert an IPv4 address string to a binary byte string.
 *
 * Example:
 *   Input: "10.1.0.1"
 *   Output: "\x0a\x01\x00\x01" (binary string with 4 bytes)
 *
 * @param str Input IPv4 address string.
 * @return A binary string with 4 bytes.
 * @throws std::invalid_argument if the string format is invalid.
 */
std::string IpStrToBytes(const std::string& str);

/**
 * @brief Convert a truncated IPv4 address string to a binary byte string based on bit width.
 *
 * Example:
 *   Input: "10.1.0.1", bitWidth = 24
 *   Output: "\x0a\x01\x00" (binary string with 3 bytes)
 *
 * @param str Input IPv4 address string.
 * @param bitWidth Bit width to truncate to (e.g., 32, 24, 16, 8).
 * @return A truncated binary string.
 * @throws std::invalid_argument if the string format is invalid.
 */
std::string IpStrToBytes(const std::string& str, unsigned int bitWidth);

/**
 * @brief Convert an unsigned integer to a decimal string.
 *
 * Example:
 *   Input: 123
 *   Output: "123"
 *
 * @param num Input unsigned integer.
 * @return A decimal string representation of the number.
 */
std::string UintToString(unsigned int num);

/**
 * @brief Convert a 32-bit unsigned integer representing an IPv4 address to a hexadecimal string.
 *
 * Example:
 *   Input: 167772161 (equivalent to 10.1.0.1)
 *   Output: "0x0a010001"
 *
 * @param ip 32-bit unsigned integer IPv4 address.
 * @return A hexadecimal string representation of the IP address.
 */
std::string Uint32IpToHex(unsigned int ip);

/**
 * @brief Convert an integer string into a binary byte string based on bit width.
 *
 * Example:
 *   Input: "123", bitWidth = 16
 *   Output: "\x00\x7b" (binary string with 2 bytes)
 *
 * @param inputStr Input integer string.
 * @param bitWidth Bit width to format to (e.g., 16, 8).
 * @return A binary string representation.
 * @throws std::invalid_argument if the string contains invalid characters.
 */
std::string IntToBytes(const std::string& inputStr, int bitWidth);

/**
 * @brief Parse a parameter string and convert it to a binary byte string based on bit width.
 *
 * Dispatches to different conversion functions based on the bit width:
 * - 32: Calls HexStrToBytes.
 * - 48: (Reserved for MAC address conversion, not implemented).
 * - 128: (Reserved for IPv6 address conversion, not implemented).
 * - Other: Calls IntToBytes.
 *
 * @param inputStr Input parameter string.
 * @param bitWidth Bit width for conversion.
 * @return A binary string representation.
 * @throws std::invalid_argument if the string format is invalid.
 */
std::string ParseParam(std::string& inputStr, unsigned int bitWidth);

uint64_t getTickCount(); // Get current time (ms)

/**
 * @brief Get the P4Sim project root directory path.
 *
 * Reads from the environment variable P4SIM_DIR. If not set, falls back
 * to a path relative to the executable location.
 *
 * Set the environment variable in your shell:
 *   export P4SIM_DIR="/path/to/ns3/contrib/p4sim"
 *
 * @return The absolute path to the p4sim directory.
 */
std::string GetP4SimDir();

/**
 * @brief Get the path to the P4Sim examples/p4src directory.
 *
 * Convenience function that returns GetP4SimDir() + "/examples/p4src".
 * Use this as a base path and append specific example subdirectories.
 *
 * Example:
 *   GetP4ExamplePath() => "/home/user/ns3/contrib/p4sim/examples/p4src"
 *   GetP4ExamplePath() + "/source_routing" => ".../p4src/source_routing"
 *
 * @return The full absolute path to examples/p4src.
 */
std::string GetP4ExamplePath();

} // namespace ns3

#endif /* FORMAT_UTILS_H */
