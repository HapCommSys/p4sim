/*
 * Copyright (c) 2026 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

/**
 * Hello, P4: the first example, and a test bed for own P4 programs.
 *
 *   host 0 ── port 0 ┐
 *   host 1 ── port 1 ┼── P4 switch (hello.p4)
 *   host 2 ── port 2 ┘
 *
 * Each host sends three UDP echo requests to every other host. The program prints
 * how many replies came back, and exits with 1 unless all did.
 *
 * Run an own v1model program, without writing C++ (doc/getting-started.md):
 *
 *   ./ns3 run "p4-hello --json=/path/my.json --flowTable=/path/my.txt --hosts=4"
 *
 * Host i is on port i of the switch and has the address 10.0.0.<i+1> and the MAC
 * address 00:00:00:00:00:<i+1>. The hosts know each other's MAC addresses, as in
 * the p4lang tutorials, so the P4 program does not have to handle ARP.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-switch-net-device.h"
#include "ns3/switched-ethernet-helper.h"

#include <iomanip>

using namespace ns3;

namespace
{

const uint32_t N_REQUESTS = 3; ///< echo requests per pair of hosts

/// Count a reply that an echo client received
void
CountReply(uint32_t* replies, Ptr<const Packet>)
{
    ++*replies;
}

} // namespace

int
main(int argc, char* argv[])
{
    std::string json = GetP4ExamplePath() + "/hello/hello.json";
    std::string flowTable = GetP4ExamplePath() + "/hello/flowtable.txt";
    uint32_t nHosts = 3;
    bool pcap = false;

    CommandLine cmd(__FILE__);
    cmd.AddValue("json", "The compiled P4 program", json);
    cmd.AddValue("flowTable", "The flow table; none for no flow table", flowTable);
    cmd.AddValue("hosts", "Number of hosts, 2 to 9", nHosts);
    cmd.AddValue("pcap", "Write a pcap file per host (p4-hello-<host>-0.pcap)", pcap);
    cmd.Parse(argc, argv);
    NS_ABORT_MSG_IF(nHosts < 2 || nHosts > 9, "--hosts must be 2 to 9");
    if (flowTable == "none")
    {
        flowTable.clear();
    }

    // 1. A switch with a P4 program and its flow table
    NodeContainer hosts(nHosts);
    Ptr<Node> switchNode = CreateObject<Node>();
    P4Helper p4;
    p4.SetDeviceAttribute("JsonPath", StringValue(json));
    p4.SetDeviceAttribute("FlowTablePath", StringValue(flowTable));
    Ptr<P4SwitchNetDevice> sw = DynamicCast<P4SwitchNetDevice>(p4.Install(switchNode).Get(0));

    // 2. One link per host; host i is on port i
    SwitchedEthernetHelper eth;
    eth.SetChannelAttribute("DataRate", StringValue("1Gbps"));
    eth.SetChannelAttribute("Delay", StringValue("10us"));
    NetDeviceContainer hostDevs = eth.Install(sw, hosts);

    // 3. Addresses
    std::vector<Mac48Address> mac;
    for (uint32_t i = 0; i < nHosts; i++)
    {
        mac.emplace_back(("00:00:00:00:00:0" + std::to_string(i + 1)).c_str());
        hostDevs.Get(i)->SetAddress(mac[i]);
    }
    InternetStackHelper internet;
    internet.Install(hosts);
    Ipv4AddressHelper ipv4("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ip = ipv4.Assign(hostDevs);
    for (uint32_t i = 0; i < nHosts; i++)
    {
        Ptr<ArpCache> arp =
            hosts.Get(i)->GetObject<Ipv4L3Protocol>()->GetInterface(1)->GetArpCache();
        for (uint32_t j = 0; j < nHosts; j++)
        {
            if (i != j)
            {
                ArpCache::Entry* entry = arp->Add(ip.GetAddress(j));
                entry->SetMacAddress(mac[j]);
                entry->MarkPermanent();
            }
        }
        std::cout << "host " << i << ": port " << i << ", " << ip.GetAddress(i) << ", " << mac[i]
                  << "\n";
    }

    // 4. Every host sends echo requests to every other host
    UdpEchoServerHelper server(9);
    server.Install(hosts);
    std::vector<std::vector<uint32_t>> replies(nHosts, std::vector<uint32_t>(nHosts, 0));
    for (uint32_t i = 0; i < nHosts; i++)
    {
        for (uint32_t j = 0; j < nHosts; j++)
        {
            if (i != j)
            {
                UdpEchoClientHelper client(ip.GetAddress(j), 9);
                client.SetAttribute("MaxPackets", UintegerValue(N_REQUESTS));
                client.SetAttribute("Interval", TimeValue(MilliSeconds(100)));
                ApplicationContainer app = client.Install(hosts.Get(i));
                app.Start(Seconds(1));
                app.Get(0)->TraceConnectWithoutContext(
                    "Rx",
                    MakeBoundCallback(&CountReply, &replies[i][j]));
            }
        }
    }
    if (pcap)
    {
        eth.EnablePcap("p4-hello", hostDevs, true);
    }

    Simulator::Stop(Seconds(3));
    Simulator::Run();
    Simulator::Destroy();

    // 5. The result
    uint32_t reached = 0;
    std::cout << "\nreplies   ";
    for (uint32_t j = 0; j < nHosts; j++)
    {
        std::cout << "  to " << j;
    }
    std::cout << "\n";
    for (uint32_t i = 0; i < nHosts; i++)
    {
        std::cout << "  host " << i << "  ";
        for (uint32_t j = 0; j < nHosts; j++)
        {
            std::cout << "   "
                      << (i == j
                              ? " -"
                              : std::to_string(replies[i][j]) + "/" + std::to_string(N_REQUESTS));
            reached += (i != j && replies[i][j] == N_REQUESTS);
        }
        std::cout << "\n";
    }
    uint32_t pairs = nHosts * (nHosts - 1);
    std::cout << (reached == pairs ? "[PASS] " : "[FAIL] ") << reached << " of " << pairs
              << " pairs of hosts reach each other\n";
    return reached == pairs ? 0 : 1;
}
