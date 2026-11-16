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

#include "ns3/assert.h"
#include "ns3/attribute.h" // For MakeStringAccessor and MakeStringChecker
#include "ns3/custom-header.h"
#include "ns3/log.h"
#include "ns3/string.h" // For StringValue

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("CustomHeader");

TypeId
CustomHeader::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::CustomHeader")
                            .SetParent<Header>()
                            .SetGroupName("Custom")
                            .AddConstructor<CustomHeader>();
    return tid;
}

CustomHeader::CustomHeader()
    : m_protocol_index(0),
      m_offset_bytes(0)
{
    InitFields();
}

CustomHeader::CustomHeader(const CustomHeader& other)
    : Header(),
      m_layer(other.m_layer),
      m_op(other.m_op),
      m_protocol_index(other.m_protocol_index),
      m_fields(other.m_fields),
      m_offset_bytes(other.m_offset_bytes)
{
    NS_LOG_DEBUG("Copy constructor called");
}

CustomHeader::~CustomHeader()
{
}

void
CustomHeader::InitFields()
{
    m_fields.clear();
}

CustomHeader&
CustomHeader::operator=(const CustomHeader& other)
{
    if (this == &other)
    {
        return *this; // Self-assignment protection
    }

    // Header::operator= (other);

    // Copy other members
    m_layer = other.m_layer;
    m_op = other.m_op;
    m_protocol_index = other.m_protocol_index;
    m_fields = other.m_fields; // Use std::vector's copy constructor
    m_offset_bytes = other.m_offset_bytes;

    NS_LOG_DEBUG("Assignment operator called");
    return *this;
}

// Function to calculate the offset where the custom header should be inserted
uint32_t
CustomHeader::CalculateHeaderInsertOffset(HeaderLayer layer, HeaderLayerOperator operation)
{
    // Define the size of known headers
    const uint32_t ETH_HEADER_SIZE = 14;  // Ethernet header
    const uint32_t IPV4_HEADER_SIZE = 20; // IPv4 header (minimum size)
    const uint32_t UDP_HEADER_SIZE = 8;   // UDP header
    // const uint32_t TCP_HEADER_SIZE = 20; // TCP header (minimum size)

    // Start with offset = 0 (beginning of the packet)
    uint32_t offset = 0;

    switch (layer)
    {
    case LAYER_2:
        if (operation == ADD_BEFORE)
        {
            offset = 0; // Before Ethernet header
        }
        else if (operation == REPLACE || operation == ADD_AFTER)
        {
            offset = ETH_HEADER_SIZE; // End of Ethernet header
        }
        break;

    case LAYER_3:
        if (operation == ADD_BEFORE)
        {
            offset = ETH_HEADER_SIZE; // Before IPv4 header
        }
        else if (operation == REPLACE || operation == ADD_AFTER)
        {
            offset = ETH_HEADER_SIZE + IPV4_HEADER_SIZE; // After IPv4 header
        }
        break;

    case LAYER_4:
        if (operation == ADD_BEFORE)
        {
            offset = ETH_HEADER_SIZE + IPV4_HEADER_SIZE; // Before UDP/TCP header
        }
        else if (operation == REPLACE || operation == ADD_AFTER)
        {
            offset =
                ETH_HEADER_SIZE + IPV4_HEADER_SIZE + UDP_HEADER_SIZE; // Default to UDP header size
        }
        break;

    case LAYER_5:
        if (operation == ADD_BEFORE)
        {
            offset =
                ETH_HEADER_SIZE + IPV4_HEADER_SIZE + UDP_HEADER_SIZE; // Before Application data
        }
        else if (operation == REPLACE || operation == ADD_AFTER)
        {
            // Assume no additional layer beyond application data
            offset = ETH_HEADER_SIZE + IPV4_HEADER_SIZE + UDP_HEADER_SIZE; // End of packet
        }
        break;

    default:
        std::cerr << "Unknown layer specified!" << std::endl;
        break;
    }

    return offset;
}

void
CustomHeader::AddField(const std::string& name, uint32_t bitWidth)
{
    if (bitWidth > 64)
    {
        throw std::invalid_argument("Bit width cannot exceed 64 bits.");
    }
    Field field{name, bitWidth, 0};
    m_fields.push_back(field);
}

void
CustomHeader::SetField(const std::string& name, uint64_t value)
{
    for (auto& field : m_fields)
    {
        if (field.name == name)
        {
            if (value >= (1ULL << field.bitWidth))
            {
                throw std::out_of_range("Value exceeds the maximum allowed by field width.");
            }
            field.value = value;
            return;
        }
    }
    throw std::invalid_argument("Field not found: " + name);
}

uint64_t
CustomHeader::GetField(const std::string& name) const
{
    for (const auto& field : m_fields)
    {
        if (field.name == name)
        {
            return field.value;
        }
    }
    throw std::invalid_argument("Field not found: " + name);
}

void
CustomHeader::SetProtocolFieldNumber(uint64_t id)
{
    if (m_fields.empty())
    {
        NS_LOG_WARN("m_fields is empty! Set protocol number.");
    }

    else if (id >= m_fields.size())
    {
        NS_LOG_WARN("Invalid protocol number assignment: id = " << id << ", but m_fields size = "
                                                                << m_fields.size());
        return;
    }

    m_protocol_index = id;
}

uint64_t
CustomHeader::GetProtocolNumber()
{
    NS_LOG_INFO("Protocol number: " << m_protocol_index);

    if (m_protocol_index >= m_fields.size())
    {
        NS_LOG_ERROR("Index out of bounds: m_protocol_index = "
                     << m_protocol_index << ", but m_fields size = " << m_fields.size());
        return 0;
    }

    return m_fields[m_protocol_index].value;
}

void
CustomHeader::SetLayer(HeaderLayer layer)
{
    m_layer = layer;
}

HeaderLayer
CustomHeader::GetLayer() const
{
    return m_layer;
}

void
CustomHeader::SetOperator(HeaderLayerOperator op)
{
    m_op = op;
}

HeaderLayerOperator
CustomHeader::GetOperator() const
{
    return m_op;
}

TypeId
CustomHeader::GetInstanceTypeId(void) const
{
    return GetTypeId();
}

void
CustomHeader::Serialize(Buffer::Iterator start) const
{
    uint32_t currentBit = 0;
    uint8_t currentByte = 0;

    for (const auto& field : m_fields)
    {
        uint32_t bitsToWrite = field.bitWidth;
        uint64_t value = field.value;

        while (bitsToWrite > 0)
        {
            uint32_t freeBits = 8 - currentBit;
            uint32_t bitsToWriteNow = std::min(freeBits, bitsToWrite);

            currentByte |= ((value >> (bitsToWrite - bitsToWriteNow)) & ((1 << bitsToWriteNow) - 1))
                           << (freeBits - bitsToWriteNow);
            bitsToWrite -= bitsToWriteNow;
            currentBit += bitsToWriteNow;

            if (currentBit == 8)
            {
                start.WriteU8(currentByte);
                currentByte = 0;
                currentBit = 0;
            }
        }
    }

    if (currentBit > 0)
    {
        start.WriteU8(currentByte);
    }
}

uint32_t
CustomHeader::Deserialize(Buffer::Iterator start)
{
    uint32_t totalBits = 0;
    for (const auto& field : m_fields)
    {
        totalBits += field.bitWidth;
    }

    uint32_t bytesToRead = (totalBits + 7) / 8;

    std::vector<uint8_t> buffer(bytesToRead);

    NS_LOG_DEBUG("Deserializing " << bytesToRead << " bytes...");
    for (uint32_t i = 0; i < bytesToRead; ++i)
    {
        buffer[i] = start.ReadU8();
    }

    uint32_t currentBit = 0;
    for (auto& field : m_fields)
    {
        uint32_t bitsToRead = field.bitWidth;
        uint64_t value = 0;

        while (bitsToRead > 0)
        {
            uint32_t byteIndex = currentBit / 8;
            uint32_t bitIndex = currentBit % 8;

            uint32_t freeBits = 8 - bitIndex;
            uint32_t bitsToReadNow = std::min(freeBits, bitsToRead);

            value = (value << bitsToReadNow) | ((buffer[byteIndex] >> (freeBits - bitsToReadNow)) &
                                                ((1 << bitsToReadNow) - 1));

            bitsToRead -= bitsToReadNow;
            currentBit += bitsToReadNow;
        }

        field.value = value;
        NS_LOG_DEBUG("Field " << field.name << ": 0x" << std::hex << std::uppercase << field.value);
    }

    return bytesToRead;
}

uint32_t
CustomHeader::GetSerializedSize(void) const
{
    // Bytes required to store all fields
    uint32_t totalBits = 0;
    for (const auto& field : m_fields)
    {
        totalBits += field.bitWidth;
    }
    return (totalBits + 7) / 8;
}

void
CustomHeader::Print(std::ostream& os) const
{
    os << "CustomHeader { ";
    for (const auto& field : m_fields)
    {
        os << field.name << ": 0x" << std::hex << std::uppercase << field.value << " ";
    }
    os << "}";
}

} // namespace ns3
