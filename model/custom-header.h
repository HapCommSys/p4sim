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

#ifndef CUSTOM_HEADER_H
#define CUSTOM_HEADER_H

#include "ns3/header.h"
#include "ns3/packet.h"

#include <stdexcept>
#include <string>
#include <vector>

namespace ns3
{

enum HeaderLayer
{
    LAYER_2 = 2, // Data Link Layer
    LAYER_3 = 3, // Network Layer
    LAYER_4 = 4, // Transport Layer
    LAYER_5 = 5  // Application or custom user-defined Layer
};

enum HeaderLayerOperator
{
    ADD_BEFORE = 1, // add before the current header exsit in this layer
    REPLACE = 2,    // replace the current header exsit in this layer
    ADD_AFTER = 3   // add after the current header exsit in this layer
};

class CustomHeader : public Header
{
  public:
    struct Field
    {
        std::string name;  // Field name
        uint32_t bitWidth; // Field bit-width
        uint64_t value;    // Field value
    };

    CustomHeader();
    virtual ~CustomHeader();

    // Copy constructor
    CustomHeader(const CustomHeader& other);

    // Assignment operator
    CustomHeader& operator=(const CustomHeader& other);

    void InitFields();

    uint32_t CalculateHeaderInsertOffset(HeaderLayer layer, HeaderLayerOperator operation);

    // bool SetHeaderForPacket (Ptr<Packet> packet, HeaderLayer layer, HeaderLayerOperator
    // operation);

    // Add a field definition [Deprecated]
    void AddField(const std::string& name, uint32_t bitWidth);

    // Set a field value [Deprecated]
    void SetField(const std::string& name, uint64_t value);

    // Set protocol number
    void SetProtocolFieldNumber(uint64_t id);

    // Get protocol number
    uint64_t GetProtocolNumber();

    // Get a field value
    uint64_t GetField(const std::string& name) const;

    // Set and get header layer
    void SetLayer(HeaderLayer layer);
    HeaderLayer GetLayer() const;

    // Set and get header operator
    void SetOperator(HeaderLayerOperator op);
    HeaderLayerOperator GetOperator() const;

    // NS-3 required methods
    static TypeId GetTypeId(void);
    virtual TypeId GetInstanceTypeId(void) const override;

    uint16_t GetOffset() const
    {
        return m_offset_bytes;
    }

    virtual void Serialize(Buffer::Iterator start) const override;
    virtual uint32_t Deserialize(Buffer::Iterator start) override;
    virtual uint32_t GetSerializedSize(void) const override;
    virtual void Print(std::ostream& os) const override;

    // static void InsertCustomHeader (Ptr<Packet> packet, const CustomHeader &header);
    // static void RemoveHeaderAtOffset (Ptr<Packet> packet, CustomHeader &header);

  private:
    HeaderLayer m_layer;         // OSI Layer for this header
    HeaderLayerOperator m_op;    // Operator for this header
    uint64_t m_protocol_index;   // Protocol number
    std::vector<Field> m_fields; // Dynamic list of fields

    uint16_t m_offset_bytes; // Offset in bytes
};

} // namespace ns3

#endif // CUSTOM_HEADER_H