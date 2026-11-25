/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#ifndef P4_DIGEST_H
#define P4_DIGEST_H

#include <cstdint>
#include <iomanip>
#include <ostream>
#include <string>
#include <vector>

/**
 * \file
 * \ingroup p4sim
 * ns3::P4Digest declaration.
 */

namespace ns3
{

/**
 * \ingroup p4sim
 * \brief A field of a digest record (see P4Digest)
 */
struct P4DigestField
{
    /// The field in the PHV, "header.field", as the learn list of the BMv2 JSON names it.
    /// p4c often copies the digest data into temporaries first ("scalars.tmp"), so the
    /// order of the fields, which is that of the digest data, is what identifies them.
    std::string name;
    uint32_t bitwidth; ///< its width in bits
    std::string value; ///< its value: (bitwidth + 7) / 8 bytes, most significant first

    /**
     * \brief The value as a number
     * \return the value; of a field wider than 64 bits, its low 64 bits
     */
    uint64_t GetUint64() const
    {
        uint64_t number = 0;
        for (unsigned char byte : value)
        {
            number = (number << 8) | byte;
        }
        return number;
    }
};

/**
 * \ingroup p4sim
 * \brief The record of a digest() in a P4 program, for the control plane
 *
 * digest<T>(receiver, data) in the ingress of a v1model program chooses a learn
 * list of the program; at the end of the ingress the switch reads the fields of
 * that list from the packet, as simple_switch does. P4SwitchNetDevice passes the
 * record to its "Digest" trace source, and P4Controller to its digest callback.
 */
struct P4Digest
{
    uint32_t listId;      ///< ID of the learn list in the BMv2 JSON (the receiver is not used)
    std::string listName; ///< its name: the type T of the digest data
    std::vector<P4DigestField> fields; ///< the fields of the digest data, in their order
};

/**
 * \brief Print a digest as "name {field=0x..., ...}"
 * \param os the output stream
 * \param digest the digest
 * \return the output stream
 */
inline std::ostream&
operator<<(std::ostream& os, const P4Digest& digest)
{
    os << digest.listName << " {";
    for (size_t i = 0; i < digest.fields.size(); i++)
    {
        os << (i > 0 ? ", " : "") << digest.fields[i].name << "=0x";
        for (unsigned char byte : digest.fields[i].value)
        {
            os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        os << std::dec << std::setfill(' ');
    }
    return os << "}";
}

} // namespace ns3

#endif // P4_DIGEST_H
