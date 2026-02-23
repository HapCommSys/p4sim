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
 * Authors: P4sim Contributors
 */

/**
 * Dummy Switch Example
 *
 * Demonstrates the skeleton DummySwitchNetDevice with 3 hosts and 1 switch.
 * Each host is connected via a CSMA link. An optional FifoQueueDisc traffic
 * manager is attached to port 2 (egress toward host 2).
 *
 *   Host0 ──┐
 *   Host1 ──┼── DummySwitch
 *   Host2 ──┘
 *
 * A UDP packet is sent from Host0 to Host2. The switch floods to all ports
 * except the ingress, so Host1 and Host2 both receive the packet. The TM
 * on port 2 is logged.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/dummy-switch-helper.h"
#include "ns3/fifo-queue-disc.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/traffic-control-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DummySwitchExample");

int
main(int argc, char* argv[])
{
    LogComponentEnable("DummySwitchExample", LOG_LEVEL_INFO);
    LogComponentEnable("DummySwitchNetDevice", LOG_LEVEL_INFO);
    LogComponentEnable("DummySwitchPort", LOG_LEVEL_INFO);

    bool enableTm = true;
    uint16_t pktSize = 512;

    CommandLine cmd;
    cmd.AddValue("enableTm", "Enable traffic manager on port 2", enableTm);
    cmd.AddValue("pktSize", "UDP packet size in bytes", pktSize);
    cmd.Parse(argc, argv);

    // ======================== Create nodes ========================
    NS_LOG_INFO("Creating 3 hosts and 1 switch node...");
    NodeContainer hosts;
    hosts.Create(3);

    NodeContainer switchNode;
    switchNode.Create(1);

    // ======================== Create CSMA links ========================
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));

    // One link from each host to the switch
    NetDeviceContainer switchPorts;
    std::vector<NetDeviceContainer> hostDevices(3);

    for (uint32_t i = 0; i < 3; i++)
    {
        NetDeviceContainer link = csma.Install(
            NodeContainer(hosts.Get(i), switchNode.Get(0)));
        hostDevices[i].Add(link.Get(0)); // host side
        switchPorts.Add(link.Get(1));     // switch side
    }

    // ======================== Install Internet stack ========================
    InternetStackHelper internet;
    internet.Install(hosts);

    // Assign IP addresses to host devices
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    std::vector<Ipv4InterfaceContainer> hostInterfaces(3);
    for (uint32_t i = 0; i < 3; i++)
    {
        hostInterfaces[i] = ipv4.Assign(hostDevices[i]);
    }

    // ======================== Install DummySwitch ========================
    NS_LOG_INFO("Installing DummySwitchNetDevice on switch node...");
    DummySwitchHelper dummySwitchHelper;
    Ptr<DummySwitchNetDevice> sw = dummySwitchHelper.Install(switchNode.Get(0), switchPorts);

    // ======================== Attach Traffic Manager ========================
    if (enableTm)
    {
        NS_LOG_INFO("Attaching FifoQueueDisc to port 2...");
        Ptr<FifoQueueDisc> fifo = CreateObject<FifoQueueDisc>();
        fifo->SetMaxSize(QueueSize("100p"));
        sw->SetPortTrafficManager(2, fifo);
    }

    // ======================== Print topology info ========================
    NS_LOG_INFO("Switch has " << sw->GetNPorts() << " ports:");
    for (uint32_t i = 0; i < sw->GetNPorts(); i++)
    {
        Ptr<DummySwitchPort> port = sw->GetPort(i);
        NS_LOG_INFO("  Port " << i
                    << " -> " << port->GetNetDevice()->GetInstanceTypeId().GetName()
                    << " (TM: " << (port->HasTrafficManager() ? "yes" : "no")
                    << ", Up: " << (port->IsPortUp() ? "yes" : "no") << ")");
    }

    // ======================== Setup applications ========================
    // UDP echo server on host 2
    uint16_t port = 9;
    UdpEchoServerHelper echoServer(port);
    ApplicationContainer serverApp = echoServer.Install(hosts.Get(2));
    serverApp.Start(Seconds(1.0));
    serverApp.Stop(Seconds(10.0));

    // UDP echo client on host 0
    Ipv4Address serverAddr = hostInterfaces[2].GetAddress(0);
    UdpEchoClientHelper echoClient(serverAddr, port);
    echoClient.SetAttribute("MaxPackets", UintegerValue(3));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    echoClient.SetAttribute("PacketSize", UintegerValue(pktSize));

    ApplicationContainer clientApp = echoClient.Install(hosts.Get(0));
    clientApp.Start(Seconds(2.0));
    clientApp.Stop(Seconds(10.0));

    // ======================== Enable PCAP tracing ========================
    csma.EnablePcapAll("dummy-switch-example");

    // ======================== Run simulation ========================
    NS_LOG_INFO("Running simulation...");
    Simulator::Stop(Seconds(11.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("Simulation complete.");
    return 0;
}
