#include "ns3/applications-module.h"
#include "ns3/arp-cache.h"
#include "ns3/core-module.h"
#include "ns3/csma-helper.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/net-device.h"
#include "ns3/network-module.h"
#include "ns3/node.h"
#include "ns3/p4-helper.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4L3Router");

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4L3Router", LOG_LEVEL_INFO);
    Config::SetDefault("ns3::ArpCache::DeadTimeout", TimeValue(Seconds(0)));

    // P4 parameters
    std::string p4JsonPath =
        "/home/p4/workdir/ns-3-dev-git/contrib/p4sim/examples/p4src/l3_router/l3_router.json";
    std::string flowTableDirPath =
        "/home/p4/workdir/ns-3-dev-git/contrib/p4sim/examples/p4src/l3_router/";

    std::vector<NetDeviceContainer> routerPortsNetDevices(3);

    // 1. 创建 3 个路由器 (R0, R1, R2) 和 3 个主机 (H0, H1, H2)
    NodeContainer routers;
    routers.Create(3); // R0, R1, R2

    NodeContainer hosts;
    hosts.Create(3); // H0, H1, H2

    // 2. 为不同的链接创建 PointToPoint NetDevice
    //    (1) R0 ↔ R1
    //    (2) R1 ↔ R2
    //    (3) R0 ↔ H0
    //    (4) R1 ↔ H1
    //    (5) R2 ↔ H2

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("5Mbps"));
    csma.SetChannelAttribute("Delay", StringValue("2ms"));

    // R0 ↔ R1
    NodeContainer R0R1;
    R0R1.Add(routers.Get(0));
    R0R1.Add(routers.Get(1));
    NetDeviceContainer ndcR0R1 = csma.Install(R0R1);

    // R1 ↔ R2
    NodeContainer R1R2;
    R1R2.Add(routers.Get(1));
    R1R2.Add(routers.Get(2));
    NetDeviceContainer ndcR1R2 = csma.Install(R1R2);

    // R0 ↔ H0
    NodeContainer R0H0;
    R0H0.Add(routers.Get(0));
    R0H0.Add(hosts.Get(0));
    NetDeviceContainer ndcR0H0 = csma.Install(R0H0);

    // R1 ↔ H1
    NodeContainer R1H1;
    R1H1.Add(routers.Get(1));
    R1H1.Add(hosts.Get(1));
    NetDeviceContainer ndcR1H1 = csma.Install(R1H1);

    // R2 ↔ H2
    NodeContainer R2H2;
    R2H2.Add(routers.Get(2));
    R2H2.Add(hosts.Get(2));
    NetDeviceContainer ndcR2H2 = csma.Install(R2H2);

    // 收集 R0 上的 netdevice 到 routerSwitch[0].switchDevices
    routerPortsNetDevices[0].Add(ndcR0R1.Get(0));
    routerPortsNetDevices[0].Add(ndcR0H0.Get(0));
    // ...

    // 收集 R1 上的 netdevice 到 routerSwitch[1].switchDevices
    routerPortsNetDevices[1].Add(ndcR0R1.Get(1));
    routerPortsNetDevices[1].Add(ndcR1R2.Get(0));
    routerPortsNetDevices[1].Add(ndcR1H1.Get(0));
    // ...

    // 收集 R2 上的 netdevice 到 routerSwitch[2].switchDevices
    routerPortsNetDevices[2].Add(ndcR1R2.Get(1));
    routerPortsNetDevices[2].Add(ndcR2H2.Get(0));

    // 3. 安装网络协议栈 (TCP/IP, IPv4 等) 到路由器和主机
    InternetStackHelper stack;
    stack.Install(routers);
    stack.Install(hosts);

    // 4. 分配 IP 地址（每条链路用一个独立网段）
    Ipv4AddressHelper address;

    // R0 <-> R1
    address.SetBase("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR0R1 = address.Assign(ndcR0R1);

    // R1 <-> R2
    address.SetBase("10.0.1.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR1R2 = address.Assign(ndcR1R2);

    // R0 <-> H0
    address.SetBase("10.0.2.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR0H0 = address.Assign(ndcR0H0);

    // R1 <-> H1
    address.SetBase("10.0.3.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR1H1 = address.Assign(ndcR1H1);

    // R2 <-> H2
    address.SetBase("10.0.4.0", "255.255.255.0");
    Ipv4InterfaceContainer iicR2H2 = address.Assign(ndcR2H2);

    // P4 Switch Configuration
    P4Helper p4SwitchHelper;
    p4SwitchHelper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(0));
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch", UintegerValue(0));

    for (unsigned int i = 0; i < 3; i++)
    {
        // install p4 switch in the router hosts
        std::string flowTablePath = flowTableDirPath + "flowtable_" + std::to_string(i) + ".txt";
        p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
        NS_LOG_INFO("*** P4 switch configuration: " << p4JsonPath << ", \n " << flowTablePath);

        p4SwitchHelper.Install(routers.Get(i), routerPortsNetDevices[i]);
    }

    // ---- 在这里打印节点拓扑和 IP 信息 ----
    //    7.1 打印节点和接口信息

    //     === Print Host & IP/MAC Interface Info ===
    // Host node 0 -> real NodeId: 3, 2 Ipv4 Interfaces
    //   Interface 1 IP: 10.0.2.2 Mask: 255.255.255.0 MAC: 00:00:00:00:00:06
    // Host node 1 -> real NodeId: 4, 2 Ipv4 Interfaces
    //   Interface 1 IP: 10.0.3.2 Mask: 255.255.255.0 MAC: 00:00:00:00:00:08
    // Host node 2 -> real NodeId: 5, 2 Ipv4 Interfaces
    //   Interface 1 IP: 10.0.4.2 Mask: 255.255.255.0 MAC: 00:00:00:00:00:0a

    // === Print Router & IP/MAC Interface Info ===
    // Router node 0 -> real NodeId: 0, 3 Ipv4 Interfaces
    //   Interface 1 IP: 10.0.0.1 Mask: 255.255.255.0 MAC: 00:00:00:00:00:01
    //   Interface 2 IP: 10.0.2.1 Mask: 255.255.255.0 MAC: 00:00:00:00:00:05
    // Router node 1 -> real NodeId: 1, 4 Ipv4 Interfaces
    //   Interface 1 IP: 10.0.0.2 Mask: 255.255.255.0 MAC: 00:00:00:00:00:02
    //   Interface 2 IP: 10.0.1.1 Mask: 255.255.255.0 MAC: 00:00:00:00:00:03
    //   Interface 3 IP: 10.0.3.1 Mask: 255.255.255.0 MAC: 00:00:00:00:00:07
    // Router node 2 -> real NodeId: 2, 3 Ipv4 Interfaces
    //   Interface 1 IP: 10.0.1.2 Mask: 255.255.255.0 MAC: 00:00:00:00:00:04
    //   Interface 2 IP: 10.0.4.1 Mask: 255.255.255.0 MAC: 00:00:00:00:00:09

    // Print out the IP and MAC of each interface on each host node
    NS_LOG_INFO("=== Print Host & IP/MAC Interface Info ===");
    for (uint32_t i = 0; i < hosts.GetN(); i++)
    {
        Ptr<Node> node = hosts.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();

        NS_LOG_INFO("Host node " << i << " -> real NodeId: " << node->GetId() << ", "
                                 << ipv4->GetNInterfaces() << " Ipv4 Interfaces");

        // Iterate over each interface
        for (uint32_t ifIndex = 0; ifIndex < ipv4->GetNInterfaces(); ifIndex++)
        {
            // Each interface may have multiple IP addresses
            for (uint32_t adIndex = 0; adIndex < ipv4->GetNAddresses(ifIndex); adIndex++)
            {
                Ipv4InterfaceAddress iaddr = ipv4->GetAddress(ifIndex, adIndex);
                Ipv4Address ipAddr = iaddr.GetLocal();

                // Skip loopback interface
                if (ipAddr == Ipv4Address::GetLoopback())
                    continue;

                // Retrieve the NetDevice that corresponds to 'ifIndex'
                Ptr<NetDevice> dev = ipv4->GetNetDevice(ifIndex);
                // Convert the generic Address to a Mac48Address (if it's that kind)
                Address genericMac = dev->GetAddress();
                Mac48Address mac = Mac48Address::ConvertFrom(genericMac);

                NS_LOG_INFO("  Interface " << ifIndex << " IP: " << ipAddr
                                           << " Mask: " << iaddr.GetMask() << " MAC: " << mac);
            }
        }
    }
    // Print out the IP and MAC of each interface on each host node
    NS_LOG_INFO("=== Print Router & IP/MAC Interface Info ===");
    for (uint32_t i = 0; i < routers.GetN(); i++)
    {
        Ptr<Node> node = routers.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();

        NS_LOG_INFO("Router node " << i << " -> real NodeId: " << node->GetId() << ", "
                                   << ipv4->GetNInterfaces() << " Ipv4 Interfaces");

        // Iterate over each interface
        for (uint32_t ifIndex = 0; ifIndex < ipv4->GetNInterfaces(); ifIndex++)
        {
            // Each interface may have multiple IP addresses
            for (uint32_t adIndex = 0; adIndex < ipv4->GetNAddresses(ifIndex); adIndex++)
            {
                Ipv4InterfaceAddress iaddr = ipv4->GetAddress(ifIndex, adIndex);
                Ipv4Address ipAddr = iaddr.GetLocal();

                // Skip loopback interface
                if (ipAddr == Ipv4Address::GetLoopback())
                    continue;

                // Retrieve the NetDevice that corresponds to 'ifIndex'
                Ptr<NetDevice> dev = ipv4->GetNetDevice(ifIndex);
                // Convert the generic Address to a Mac48Address (if it's that kind)
                Address genericMac = dev->GetAddress();
                Mac48Address mac = Mac48Address::ConvertFrom(genericMac);

                NS_LOG_INFO("  Interface " << ifIndex << " IP: " << ipAddr
                                           << " Mask: " << iaddr.GetMask() << " MAC: " << mac);
            }
        }
    }

    // Ipv4StaticRoutingHelper staticRouting;
    // Ptr<Ipv4> ipv4H0 = hosts.Get(0)->GetObject<Ipv4>();
    // Ptr<Ipv4StaticRouting> host0sr = staticRouting.GetStaticRouting(ipv4H0);

    // // "Any traffic not in 10.0.2.x goes to 10.0.2.1"
    // host0sr->AddNetworkRouteTo(Ipv4Address("10.0.0.0"),
    //                            Ipv4Mask("255.255.0.0"),
    //                            Ipv4Address("10.0.2.1"),
    //                            1 // The interface index that has 10.0.2.2
    // );

    uint16_t echoPort = 9;
    UdpEchoServerHelper echoServer(echoPort);
    ApplicationContainer serverApps = echoServer.Install(hosts.Get(2)); // H2
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(10.0));

    // 在 H0 上安装一个 UDP Echo Client，目标 IP 为 H2 的地址
    UdpEchoClientHelper echoClient(iicR2H2.GetAddress(1), echoPort);
    echoClient.SetAttribute("MaxPackets", UintegerValue(5));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    echoClient.SetAttribute("PacketSize", UintegerValue(1024));

    ApplicationContainer clientApps = echoClient.Install(hosts.Get(0)); // H0
    clientApps.Start(Seconds(2.0));
    clientApps.Stop(Seconds(9.0));

    csma.EnablePcapAll("p4-l3-router");

    NS_LOG_INFO("Running simulation...");
    Simulator::Stop(Seconds(11.0));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}