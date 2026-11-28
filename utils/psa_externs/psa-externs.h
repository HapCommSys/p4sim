/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef P4SIM_PSA_EXTERNS_H
#define P4SIM_PSA_EXTERNS_H

/**
 * The externs of BMv2 1.15.8's psa_switch: Counter, Hash, InternetChecksum,
 * Meter and Random (utils/psa_externs). They register themselves when the
 * P4sim library is loaded. PNA programs use the same ones: BMv2's pna_nic has
 * identical copies under the same names.
 */
int import_counters();
int import_hash();
int import_internet_checksum();
int import_meters();
int import_random();

namespace ns3
{

/// Keeps the PSA externs in the program, also in a static build
inline void
ImportPsaExterns()
{
    import_counters();
    import_hash();
    import_internet_checksum();
    import_meters();
    import_random();
}

} // namespace ns3

#endif // P4SIM_PSA_EXTERNS_H
