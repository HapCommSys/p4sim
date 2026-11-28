/*
 * Copyright (c) 2026 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * Explicit Congestion Notification, the "ecn" exercise of p4lang/tutorials:
 * https://github.com/p4lang/tutorials/tree/master/exercises/ecn
 * The P4 program is the reference solution of the exercise, unchanged, and the
 * flow tables are its runtime files (examples/p4src/ecn); the network is in
 * tutorial-triangle.h.
 *
 * Host h1 sends a short UDP packet ("P4 is cool") to h2 every 100 ms, marked as
 * ECN-capable (ECN 1). From 2 to 3 s, h11 sends 1 Mbps of UDP to h22, which is not
 * ECN-capable (ECN 0), over the same 512 kbps link from s1 to s2, so the queue of
 * that port grows. The egress of a switch sets ECN to 3 (congestion experienced) in
 * an ECN-capable packet that found 10 or more packets in its queue (enq_qdepth).
 * h2 prints the ECN value of the packets from h1, and the program checks that the
 * marks follow the congestion: none before it, some while the queue is long, none
 * once it has drained, and none on the packets of h11, which are not ECN-capable.
 * It also checks the IPv4 checksum, which the switches must update with the ECN
 * field.
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

const uint16_t PORT = 4321;                   ///< UDP port of h2 (the tutorial's)
const Time INTERVAL = MilliSeconds(100);      ///< between two packets of h1
const uint32_t N_PACKETS = 40;                ///< packets of h1, from 1 s on
const Time CONGESTION_START = Seconds(2);     ///< h11 starts sending to h22
const Time CONGESTION_STOP = Seconds(3);      ///< and stops
const std::string MESSAGE = "P4 is cool";     ///< payload of h1's packets
const uint8_t ECN_CAPABLE = 1;                ///< ECN of h1's packets (ECT(1))
const uint8_t ECN_CONGESTION_EXPERIENCED = 3; ///< ECN that the switches set

/// A packet that h2 or h22 received: when, its ECN field, and whether its IPv4
/// header checksum is right
struct Arrival
{
    Time time;
    uint8_t ecn;
    bool checksumOk;
};

std::vector<Arrival> g_fromH1;  ///< h1's packets at h2
std::vector<Arrival> g_fromH11; ///< h11's packets at h22

/// h1 sends its next packet
void
Send(Ptr<Socket> socket)
{
    socket->Send(Create<Packet>(reinterpret_cast<const uint8_t*>(MESSAGE.data()), MESSAGE.size()));
}

/// An IPv4 packet reached the device of h2 or h22: note the ECN field and the
/// checksum of the packets from \p source
void
Receive(std::vector<Arrival>* arrivals,
        Ipv4Address source,
        Ptr<NetDevice>,
        Ptr<const Packet> packet,
        uint16_t,
        const Address&,
        const Address&,
        NetDevice::PacketType)
{
    Ipv4Header ip;
    ip.EnableChecksum(); // ns-3 checks no checksums by default; the switches set it
    if (packet->PeekHeader(ip) && ip.GetSource() == source)
    {
        arrivals->push_back(
            {Simulator::Now(), static_cast<uint8_t>(ip.GetTos() & 0x3), ip.IsChecksumOk()});
    }
}

} // namespace

int
main(int argc, char* argv[])
{
    std::string dir = GetP4ExamplePath() + "/ecn";
    std::string json = dir + "/ecn.json";
    bool pcap = false;
    CommandLine cmd(__FILE__);
    cmd.AddValue("json", "The compiled P4 program, e.g. your own solution of the exercise", json);
    cmd.AddValue("pcap", "Write a pcap file per host (p4-ecn-<node>-0.pcap)", pcap);
    cmd.Parse(argc, argv);

    Triangle t = BuildTriangle(json, dir);
    StartCongestion(t, CONGESTION_START, CONGESTION_STOP);

    // h1 -> h2: one ECN-capable packet every 100 ms
    PacketSinkHelper sink("ns3::UdpSocketFactory", InetSocketAddress(t.addresses[H2], PORT));
    sink.Install(t.hosts.Get(H2));
    Ptr<Socket> socket = Socket::CreateSocket(t.hosts.Get(H1), UdpSocketFactory::GetTypeId());
    socket->Connect(InetSocketAddress(t.addresses[H2], PORT));
    socket->SetIpTos(ECN_CAPABLE); // after Connect(), which sets the TOS of the address

    for (uint32_t i = 0; i < N_PACKETS; i++)
    {
        Simulator::Schedule(Seconds(1) + i * INTERVAL, &Send, socket);
    }

    // The ECN field of every packet that arrives, read on the devices of h2 and h22
    t.hosts.Get(H2)->RegisterProtocolHandler(
        MakeBoundCallback(&Receive, &g_fromH1, t.addresses[H1]),
        ETHERTYPE_IPV4,
        t.devices.Get(H2));
    t.hosts.Get(H22)->RegisterProtocolHandler(
        MakeBoundCallback(&Receive, &g_fromH11, t.addresses[H11]),
        ETHERTYPE_IPV4,
        t.devices.Get(H22));
    if (pcap)
    {
        SwitchedEthernetHelper().EnablePcap("p4-ecn", t.devices, true);
    }

    Simulator::Stop(Seconds(7));
    Simulator::Run();
    Simulator::Destroy();

    // The packets of h1 at h2, in runs of the same ECN value
    std::cout << "ECN of the packets from h1 at h2 (h11 congests s1 -> s2 from "
              << CONGESTION_START.GetSeconds() << " to " << CONGESTION_STOP.GetSeconds() << " s):\n"
              << std::fixed << std::setprecision(2);
    for (size_t i = 0; i < g_fromH1.size();)
    {
        size_t j = i;
        while (j + 1 < g_fromH1.size() && g_fromH1[j + 1].ecn == g_fromH1[i].ecn)
        {
            j++;
        }
        std::cout << "  " << g_fromH1[i].time.GetSeconds() << " to "
                  << g_fromH1[j].time.GetSeconds() << " s: ECN " << int(g_fromH1[i].ecn) << " ("
                  << j - i + 1 << " packets)\n";
        i = j + 1;
    }

    // Packets sent before the congestion arrive before it, and the last ones
    // after the queue has drained
    auto count = [](const std::vector<Arrival>& arrivals, uint8_t ecn, Time from, Time to) {
        uint32_t n = 0;
        for (const Arrival& a : arrivals)
        {
            n += (a.ecn == ecn && a.time >= from && a.time < to);
        }
        return n;
    };
    uint32_t before = count(g_fromH1, ECN_CAPABLE, Seconds(0), CONGESTION_START);
    uint32_t marked = count(g_fromH1, ECN_CONGESTION_EXPERIENCED, Seconds(0), Seconds(10));
    uint32_t after = count(g_fromH1, ECN_CAPABLE, Seconds(4.5), Seconds(10));
    uint32_t h11Marked = count(g_fromH11, ECN_CONGESTION_EXPERIENCED, Seconds(0), Seconds(10));
    uint32_t badChecksums = 0;
    for (const auto* arrivals : {&g_fromH1, &g_fromH11})
    {
        for (const Arrival& a : *arrivals)
        {
            badChecksums += !a.checksumOk;
        }
    }

    int failed = Check(g_fromH1.size() == N_PACKETS,
                       std::to_string(g_fromH1.size()) + " of " + std::to_string(N_PACKETS) +
                           " packets from h1 arrived");
    failed |= Check(before == 10,
                    std::to_string(before) + " of the 10 packets before the "
                                             "congestion arrived with ECN 1");
    failed |= Check(marked >= 5,
                    std::to_string(marked) + " packets were marked with ECN 3 "
                                             "while the queue was long");
    failed |= Check(after == 5,
                    std::to_string(after) + " of the last 5 packets, after the "
                                            "queue had drained, arrived with ECN 1");
    failed |= Check(!g_fromH11.empty() && h11Marked == 0,
                    std::to_string(h11Marked) + " of the " + std::to_string(g_fromH11.size()) +
                        " packets of h11, which are not ECN-capable, were marked");
    failed |= Check(badChecksums == 0,
                    std::to_string(badChecksums) + " of the " +
                        std::to_string(g_fromH1.size() + g_fromH11.size()) +
                        " packets at h2 and h22 have a wrong IPv4 checksum");
    return failed;
}
