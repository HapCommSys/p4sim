/*
 * Copyright (c) 2026 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * Multi-Hop Route Inspection, the "mri" exercise of p4lang/tutorials:
 * https://github.com/p4lang/tutorials/tree/master/exercises/mri
 * The P4 program is the reference solution of the exercise, unchanged, and the
 * flow tables are its runtime files (examples/p4src/mri); the network is in
 * tutorial-triangle.h.
 *
 * Host h1 sends a UDP packet to h2 every 100 ms with an MRI option in its IPv4
 * header, as the tutorial's send.py does. The egress of every switch on the way
 * adds a record: the switch ID and the depth of its queue when the packet left it
 * (deq_qdepth). From 2 to 3 s, h11 sends 1 Mbps of UDP to h22 over the same
 * 512 kbps link from s1 to s2, so the queue of that port grows. h2 reads the
 * records, and the program checks that every packet went s1 -> s2 and that the
 * queue of s1 shows the congestion, and only while it lasts.
 */

#include "example-check.h"
#include "tutorial-triangle.h"

#include "ns3/applications-module.h"
#include "ns3/core-module.h"

#include <iomanip>

using namespace ns3;
using namespace p4sim_example;

namespace
{

const uint16_t PORT = 4321;               ///< UDP port of h2 (the tutorial's)
const Time INTERVAL = MilliSeconds(100);  ///< between two packets of h1
const uint32_t N_PACKETS = 40;            ///< packets of h1, from 1 s on
const Time CONGESTION_START = Seconds(2); ///< h11 starts sending to h22
const Time CONGESTION_STOP = Seconds(3);  ///< and stops
const std::string MESSAGE = "P4 is cool"; ///< payload of h1's packets
const uint8_t MRI_OPTION = 0x5f;          ///< copy flag 0, class 2, option 31 (MRI)

/// The record of one switch: its ID and the depth of its queue
struct Hop
{
    uint32_t swid;
    uint32_t qdepth;
};

/// A packet of h1 at h2: when, and the records of its hops, the last hop first
struct Arrival
{
    Time time;
    std::vector<Hop> hops;
};

std::vector<Arrival> g_arrivals;

/// The big-endian number at \p bytes
uint32_t
Read32(const uint8_t* bytes)
{
    return uint32_t(bytes[0]) << 24 | uint32_t(bytes[1]) << 16 | uint32_t(bytes[2]) << 8 | bytes[3];
}

/// h1 sends a packet with an empty MRI option. ns-3 cannot add IPv4 options, so
/// the host builds the IPv4 and UDP headers itself and hands the packet to its
/// device: to the MAC address of s1, as all its IPv4 packets
void
Send(Ptr<NetDevice> device, Ipv4Address source, Ipv4Address destination)
{
    static uint16_t id = 0;
    // IPv4 with the option, UDP, data
    const auto ipLength = static_cast<uint16_t>(24 + 8 + MESSAGE.size());
    std::vector<uint8_t> b(ipLength, 0);
    b[0] = 0x46; // version 4, 6 words (20 bytes and the 4-byte option)
    b[2] = ipLength >> 8;
    b[3] = ipLength & 0xff;
    b[4] = id >> 8;
    b[5] = id++ & 0xff;
    b[8] = 64; // TTL
    b[9] = UdpL4Protocol::PROT_NUMBER;
    source.Serialize(&b[12]);
    destination.Serialize(&b[16]);
    b[20] = MRI_OPTION;
    b[21] = 4; // option length: type, length and count, no records yet
    b[22] = 0; // count
    b[23] = 0;
    uint32_t sum = 0; // header checksum over the 24 bytes
    for (uint32_t i = 0; i < 24; i += 2)
    {
        sum += b[i] << 8 | b[i + 1];
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    b[10] = ~sum >> 8 & 0xff;
    b[11] = ~sum & 0xff;
    const auto udpLength = static_cast<uint16_t>(8 + MESSAGE.size());
    b[24] = 1234 >> 8; // source port
    b[25] = 1234 & 0xff;
    b[26] = PORT >> 8;
    b[27] = PORT & 0xff;
    b[28] = udpLength >> 8;
    b[29] = udpLength & 0xff; // checksum 0: none
    std::copy(MESSAGE.begin(), MESSAGE.end(), b.begin() + 32);
    device->Send(Create<Packet>(b.data(), b.size()),
                 Mac48Address("08:00:00:00:01:00"),
                 Ipv4L3Protocol::PROT_NUMBER);
}

/// An IPv4 packet reached the device of h2: read the records of an MRI option
void
Receive(Ptr<NetDevice>,
        Ptr<const Packet> packet,
        uint16_t,
        const Address&,
        const Address&,
        NetDevice::PacketType)
{
    std::vector<uint8_t> b(packet->GetSize());
    packet->CopyData(b.data(), b.size());
    if (b.size() < 24 || (b[0] & 0x0f) <= 5 || b[20] != MRI_OPTION)
    {
        return; // no MRI option
    }
    Arrival arrival{Simulator::Now(), {}};
    uint32_t count = b[22] << 8 | b[23];
    for (uint32_t i = 0; i < count && 24 + 8 * (i + 1) <= b.size(); i++)
    {
        arrival.hops.push_back({Read32(&b[24 + 8 * i]), Read32(&b[28 + 8 * i])});
    }
    g_arrivals.push_back(arrival);
}

} // namespace

int
main(int argc, char* argv[])
{
    std::string dir = GetP4ExamplePath() + "/mri";
    std::string json = dir + "/mri.json";
    bool pcap = false;
    CommandLine cmd(__FILE__);
    cmd.AddValue("json", "The compiled P4 program, e.g. your own solution of the exercise", json);
    cmd.AddValue("pcap", "Write a pcap file per host (p4-mri-<node>-0.pcap)", pcap);
    cmd.Parse(argc, argv);

    Triangle t = BuildTriangle(json, dir);
    StartCongestion(t, CONGESTION_START, CONGESTION_STOP);

    // h1 -> h2: one packet with an MRI option every 100 ms. h2's UDP sink takes them
    // after the device has handed them to the handler that reads the records
    PacketSinkHelper sink("ns3::UdpSocketFactory", InetSocketAddress(t.addresses[H2], PORT));
    sink.Install(t.hosts.Get(H2));
    for (uint32_t i = 0; i < N_PACKETS; i++)
    {
        Simulator::Schedule(Seconds(1) + i * INTERVAL,
                            &Send,
                            t.devices.Get(H1),
                            t.addresses[H1],
                            t.addresses[H2]);
    }
    t.hosts.Get(H2)->RegisterProtocolHandler(MakeCallback(&Receive),
                                             Ipv4L3Protocol::PROT_NUMBER,
                                             t.devices.Get(H2));
    if (pcap)
    {
        SwitchedEthernetHelper().EnablePcap("p4-mri", t.devices, true);
    }

    Simulator::Stop(Seconds(7));
    Simulator::Run();
    Simulator::Destroy();

    // The records, every fifth packet (h11 congests s1 -> s2 from 2 to 3 s)
    std::cout << "Records of the packets from h1 at h2, the last hop first:\n"
              << "  arrival (s)   switch: queue depth\n"
              << std::fixed << std::setprecision(2);
    bool path = true;     // every packet went s1 -> s2
    uint32_t idleS1 = 0;  // packets before the congestion that found s1's queue empty
    uint32_t maxS1 = 0;   // the deepest queue of s1 that a packet saw
    uint32_t afterS1 = 0; // the last 5 packets that found s1's queue empty
    uint32_t maxS2 = 0;   // the deepest queue of s2 that a packet saw
    for (size_t i = 0; i < g_arrivals.size(); i++)
    {
        const Arrival& a = g_arrivals[i];
        bool twoHops = a.hops.size() == 2 && a.hops[0].swid == 2 && a.hops[1].swid == 1;
        path = path && twoHops;
        if (i % 5 == 0)
        {
            std::cout << "  " << std::setw(11) << a.time.GetSeconds() << "  ";
            for (const Hop& hop : a.hops)
            {
                std::cout << "  s" << hop.swid << ": " << std::setw(2) << hop.qdepth;
            }
            std::cout << "\n";
        }
        if (twoHops)
        {
            const Hop& s1 = a.hops[1];
            idleS1 += (a.time < CONGESTION_START && s1.qdepth == 0);
            afterS1 += (i + 5 >= N_PACKETS && s1.qdepth == 0);
            maxS1 = std::max(maxS1, s1.qdepth);
            maxS2 = std::max(maxS2, a.hops[0].qdepth);
        }
    }

    int failed = Check(g_arrivals.size() == N_PACKETS,
                       std::to_string(g_arrivals.size()) + " of " + std::to_string(N_PACKETS) +
                           " packets from h1 arrived");
    failed |= Check(path, "every packet recorded the path s1 -> s2");
    failed |= Check(idleS1 == 10,
                    std::to_string(idleS1) + " of the 10 packets before the "
                                             "congestion found the queue of s1 empty");
    failed |= Check(maxS1 >= 10,
                    "the queue of s1 grew to " + std::to_string(maxS1) +
                        " packets during the congestion");
    failed |= Check(afterS1 == 5,
                    std::to_string(afterS1) + " of the last 5 packets, after the "
                                              "congestion, found it empty again");
    failed |=
        Check(maxS2 == 0,
              "the queue of s2 to h2 stayed empty (" + std::to_string(maxS2) + " packets at most)");
    return failed;
}
