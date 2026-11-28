/*
 * Copyright (c) 2025 TU Dresden
 * SPDX-License-Identifier: Apache-2.0
 * Based on P4Simulator (https://github.com/kphf1995cm/P4Simulator), Apache-2.0.
 */

#include "build-flowtable-helper.h"

#include "ns3/log.h"

#include <fstream>
#include <sstream>
#include <time.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("BuildFlowtableHelper");

BuildFlowtableHelper::BuildFlowtableHelper(std::string buildType, unsigned int podNum)
{
    NS_LOG_FUNCTION(this);
    m_buildType = buildType;
    m_podNum = podNum;
}

BuildFlowtableHelper::~BuildFlowtableHelper()
{
    NS_LOG_FUNCTION(this);
}

void
BuildFlowtableHelper::BuildFattreeFlowTable()
{
    unsigned int coreSwitchNum = (m_podNum / 2) * (m_podNum / 2);
    unsigned int hostNum = coreSwitchNum * m_podNum;
    unsigned int switchNum = 5 * coreSwitchNum;
    unsigned int halfPodNum = m_podNum / 2;
    unsigned int aggrStartIndex = coreSwitchNum;
    unsigned int edgeStartIndex = 3 * coreSwitchNum;
    // unsigned int tmlStartIndex = 5 * coreSwitchNum;
    unsigned int curAggrSwitchIndex;
    unsigned int curEdgeSwitchIndex;

    std::vector<std::vector<unsigned int>> switchReachHostIndexMap(switchNum);

    // add edge switch flowtable
    for (unsigned int i = 0; i < m_podNum; i++) // number pod
    {
        for (unsigned int j = 0; j < halfPodNum; j++)
        {
            curEdgeSwitchIndex = edgeStartIndex + i * halfPodNum + j;
            std::unordered_set<unsigned int> curEdgeSwitchLinkHostIndex;
            std::vector<unsigned int> otherPortIndex; // link Switch Port
            // add flowtable entry for these packet which send to linked host
            for (size_t p = 0; p < m_switchNodes[curEdgeSwitchIndex].portNode.size(); p++)
            {
                if (m_switchNodes[curEdgeSwitchIndex].portNode[p].flag == 0) // represent host
                {
                    // attain host ipAddr
                    unsigned int tmpHostIndex =
                        m_switchNodes[curEdgeSwitchIndex].portNode[p].nodeIndex;
                    curEdgeSwitchLinkHostIndex.insert(tmpHostIndex);
                    switchReachHostIndexMap[curEdgeSwitchIndex].push_back(tmpHostIndex);
                    std::string dstIp = m_hostNodes[tmpHostIndex].ipAddr;
                    m_switchNodes[curEdgeSwitchIndex].flowTableEntries.push_back(
                        FlowTableEntry_t("", dstIp, p));
                }
                else
                    otherPortIndex.push_back(p);
            }
            // add flowtable entry for other packet
            for (unsigned int p = 0; p < hostNum; p++)
            {
                if (curEdgeSwitchLinkHostIndex.count(p) == 0)
                {
                    std::string dstIp = m_hostNodes[p].ipAddr;
                    // random select a out port
                    unsigned int transferPort = otherPortIndex[rand() % otherPortIndex.size()];
                    m_switchNodes[curEdgeSwitchIndex].flowTableEntries.push_back(
                        FlowTableEntry_t("", dstIp, transferPort));
                }
            }
        }
    }

    // add aggrate switch flowtable
    for (unsigned int i = 0; i < m_podNum; i++) // number pod
    {
        for (unsigned int j = 0; j < halfPodNum; j++)
        {
            curAggrSwitchIndex = aggrStartIndex + i * halfPodNum + j;
            std::unordered_set<unsigned int> curAggrSwitchLinkHostIndex;
            std::vector<unsigned int> otherPortIndex;
            // add flowtable entry for these packet which send to linked terminal
            for (size_t p = 0; p < m_switchNodes[curAggrSwitchIndex].portNode.size(); p++)
            {
                if (m_switchNodes[curAggrSwitchIndex].portNode[p].nodeIndex >
                    curAggrSwitchIndex) // mean link edge switch
                {
                    unsigned int linkSIndex =
                        m_switchNodes[curAggrSwitchIndex].portNode[p].nodeIndex;
                    for (size_t q = 0; q < switchReachHostIndexMap[linkSIndex].size(); q++)
                    {
                        unsigned int linkTIndex = switchReachHostIndexMap[linkSIndex][q];
                        std::string dstIp = m_hostNodes[linkTIndex].ipAddr;
                        curAggrSwitchLinkHostIndex.insert(linkTIndex);
                        switchReachHostIndexMap[curAggrSwitchIndex].push_back(linkTIndex);
                        m_switchNodes[curAggrSwitchIndex].flowTableEntries.push_back(
                            FlowTableEntry_t("", dstIp, p));
                    }
                }
                else
                    otherPortIndex.push_back(p);
            }

            // add flowtable entry for other packet
            for (unsigned int p = 0; p < hostNum; p++)
            {
                if (curAggrSwitchLinkHostIndex.count(p) == 0)
                {
                    std::string dstIp = m_hostNodes[p].ipAddr;
                    // random select a out port
                    unsigned int transferPort = otherPortIndex[rand() % otherPortIndex.size()];
                    m_switchNodes[curAggrSwitchIndex].flowTableEntries.push_back(
                        FlowTableEntry_t("", dstIp, transferPort));
                }
            }
        }
    }

    // add core switch flowtable
    for (unsigned int i = 0; i < coreSwitchNum; i++)
    {
        for (size_t p = 0; p < m_switchNodes[i].portNode.size(); p++)
        {
            if (m_switchNodes[i].portNode[p].flag == 1) // represent switch
            {
                unsigned int linkSIndex = m_switchNodes[i].portNode[p].nodeIndex;
                for (size_t q = 0; q < switchReachHostIndexMap[linkSIndex].size(); q++)
                {
                    unsigned int linkTIndex = switchReachHostIndexMap[linkSIndex][q];
                    std::string dstIp = m_hostNodes[linkTIndex].ipAddr;
                    m_switchNodes[i].flowTableEntries.push_back(FlowTableEntry_t("", dstIp, p));
                }
            }
        }
    }
}

/*void BuildFlowtableHelper::BuildSilkroadFlowTable()
    {
    unsigned int coreSwitchNum = (m_podNum / 2)*(m_podNum / 2);
    unsigned int terminalNum = coreSwitchNum*m_podNum;
    unsigned int switchNum = 5 * coreSwitchNum;
    unsigned int halfPodNum = m_podNum / 2;
    unsigned int aggrStartIndex = coreSwitchNum;
    unsigned int edgeStartIndex = 3 * coreSwitchNum;
    //unsigned int tmlStartIndex = 5 * coreSwitchNum;
    unsigned int curAggrSwitchIndex;
    unsigned int curEdgeSwitchIndex;

    std::vector<std::vector<unsigned int>> switchReachTerminalIndexMap(switchNum);
    std::vector<std::vector<unsigned int>> switchReachOutTerminalIndexMap(switchNum);

    // add edge switch flowtable
    for (unsigned int i = 0; i < m_podNum; i++)// number pod
    {
    for (unsigned int j = 0; j < halfPodNum; j++)
    {
    curEdgeSwitchIndex = edgeStartIndex + i*halfPodNum + j;
    std::unordered_set<unsigned int> curEdgeSwitchLinkTerminalIndex;
    std::vector<unsigned int> otherPortIndex;
    //add flowtable entry for these packet which send to linked terminal
    for (size_t p = 0; p < m_switchNodes[curEdgeSwitchIndex].portNode.size(); p++)
    {
    if (m_switchNodes[curEdgeSwitchIndex].portNode[p].flag == 0)//represent terminal
    {
    //attain terminal ipAddr
    curEdgeSwitchLinkTerminalIndex.insert(m_switchNodes[curEdgeSwitchIndex].portNode[p].nodeIndex);
    switchReachTerminalIndexMap[curEdgeSwitchIndex].push_back(m_switchNodes[curEdgeSwitchIndex].portNode[p].nodeIndex);
    std::string dstIp =
   m_terminalNodes[m_switchNodes[curEdgeSwitchIndex].portNode[p].nodeIndex].ipAddr;
    m_switchNodes[curEdgeSwitchIndex].flowTableEntries.push_back(FlowTableEntry("", dstIp,
   uintToPortStr(p)));
    }
    else
    otherPortIndex.push_back(p);
    }
    //add flowtable entry for other packet
    for (unsigned int p = 0; p < terminalNum; p++)
    {
    if (curEdgeSwitchLinkTerminalIndex.count(p) == 0)
    {
    std::string dstIp = m_terminalNodes[p].ipAddr;
    //random select a out port
    unsigned int transfer_port = otherPortIndex[rand() % otherPortIndex.size()];
    m_switchNodes[curEdgeSwitchIndex].flowTableEntries.push_back(FlowTableEntry("", dstIp,
   uintToPortStr(transfer_port)));
    }
    }
    }
    }

    // add aggrate switch flowtable
    for (unsigned int i = 0; i < m_podNum; i++)// number pod
    {
    for (unsigned int j = 0; j < halfPodNum; j++)
    {
    curAggrSwitchIndex = aggrStartIndex + i*halfPodNum + j;
    std::unordered_set<unsigned int> curAggrSwitchLinkTerminalIndex;
    std::vector<unsigned int> otherPortIndex;
    //add flowtable entry for these packet which send to linked terminal
    for (size_t p = 0; p < m_switchNodes[curAggrSwitchIndex].portNode.size(); p++)
    {
    if (m_switchNodes[curAggrSwitchIndex].portNode[p].nodeIndex > curAggrSwitchIndex)//mean link
   edge switch
    {
    unsigned int linkSIndex = m_switchNodes[curAggrSwitchIndex].portNode[p].nodeIndex;
    for (size_t q = 0; q < switchReachTerminalIndexMap[linkSIndex].size(); q++)
    {
    unsigned int linkTIndex = switchReachTerminalIndexMap[linkSIndex][q];
    std::string dstIp = m_terminalNodes[linkTIndex].ipAddr;
    curAggrSwitchLinkTerminalIndex.insert(linkTIndex);
    switchReachTerminalIndexMap[curAggrSwitchIndex].push_back(linkTIndex);
    m_switchNodes[curAggrSwitchIndex].flowTableEntries.push_back(FlowTableEntry("", dstIp,
   uintToPortStr(p)));

    }
    }
    else
    otherPortIndex.push_back(p);
    }

    //add flowtable entry for other packet
    for (unsigned int p = 0; p < terminalNum; p++)
    {
    if (curAggrSwitchLinkTerminalIndex.count(p) == 0)
    {
    std::string dstIp = m_terminalNodes[p].ipAddr;
    //random select a out port
    unsigned int transfer_port = otherPortIndex[rand() % otherPortIndex.size()];
    m_switchNodes[curAggrSwitchIndex].flowTableEntries.push_back(FlowTableEntry("", dstIp,
   uintToPortStr(transfer_port)));
    }
    }
    }
    }

    //add core switch flowtable
    for (unsigned int i = 0; i < coreSwitchNum; i++)
    {
    for (size_t p = 0; p < m_switchNodes[i].portNode.size(); p++)
    {
    if (m_switchNodes[i].portNode[p].flag == 1)//represent switch
    {
    unsigned int linkSIndex = m_switchNodes[i].portNode[p].nodeIndex;
    for (size_t q = 0; q < switchReachTerminalIndexMap[linkSIndex].size(); q++)
    {
    unsigned int linkTIndex = switchReachTerminalIndexMap[linkSIndex][q];
    std::string dstIp = m_terminalNodes[linkTIndex].ipAddr;
    m_switchNodes[i].flowTableEntries.push_back(FlowTableEntry("", dstIp, uintToPortStr(p)));
    }
    }
    else //represent out terminal
    {
    unsigned int linkTIndex = m_switchNodes[i].portNode[p].nodeIndex;
    std::string dstIp = m_terminalNodes[linkTIndex].ipAddr;
    m_switchNodes[i].flowTableEntries.push_back(FlowTableEntry("", dstIp, uintToPortStr(p)));
    switchReachOutTerminalIndexMap[i].push_back(linkTIndex);//core switch reach out terminal index
    }
    }
    }

    // add aggrate switch flowtable to out terminal
    for (unsigned int i = 0; i < m_podNum; i++)// number pod
    {
    for (unsigned int j = 0; j < halfPodNum; j++)
    {
    curAggrSwitchIndex = aggrStartIndex + i*halfPodNum + j;
    for (size_t p = 0; p < m_switchNodes[curAggrSwitchIndex].portNode.size(); p++)
    {
    if (m_switchNodes[curAggrSwitchIndex].portNode[p].nodeIndex < curAggrSwitchIndex)//mean link
   core switch
    {
    unsigned int linkCIndex = m_switchNodes[curAggrSwitchIndex].portNode[p].nodeIndex;
    for (size_t q = 0; q < switchReachOutTerminalIndexMap[linkCIndex].size(); q++)
    {
    unsigned int linkTIndex = switchReachOutTerminalIndexMap[linkCIndex][q];
    std::string dstIp = m_terminalNodes[linkTIndex].ipAddr;
    switchReachOutTerminalIndexMap[curAggrSwitchIndex].push_back(linkTIndex);
    m_switchNodes[curAggrSwitchIndex].flowTableEntries.push_back(FlowTableEntry("", dstIp,
   uintToPortStr(p)));
    }
    }
    }
    }
    }

    // add edge switch flowtable to out terminal
    for (unsigned int i = 0; i < m_podNum; i++)// number pod
    {
    for (unsigned int j = 0; j < halfPodNum; j++)
    {
    curEdgeSwitchIndex = edgeStartIndex + i*halfPodNum + j;
    for (size_t p = 0; p < m_switchNodes[curEdgeSwitchIndex].portNode.size(); p++)
    {
    if (m_switchNodes[curEdgeSwitchIndex].portNode[p].flag == 1)//mean link aggr switch
    {
    unsigned int linkAIndex = m_switchNodes[curEdgeSwitchIndex].portNode[p].nodeIndex;
    for (size_t q = 0; q < switchReachOutTerminalIndexMap[linkAIndex].size(); q++)
    {
    unsigned int linkTIndex = switchReachOutTerminalIndexMap[linkAIndex][q];
    std::string dstIp = m_terminalNodes[linkTIndex].ipAddr;
    switchReachOutTerminalIndexMap[curEdgeSwitchIndex].push_back(linkTIndex);
    m_switchNodes[curEdgeSwitchIndex].flowTableEntries.push_back(FlowTableEntry("", dstIp,
   uintToPortStr(p)));
    }
    }
    }
    }
    }
    }*/

void
BuildFlowtableHelper::SetSwitchesFlowtableEntries()
{
    if (m_buildType == "default")
    {
        std::vector<std::vector<unsigned int>> hostLink(
            m_hostNodes.size(),
            std::vector<unsigned int>(m_hostNodes.size()));
        unsigned int linkCounter = 0;
        unsigned int linkSum = m_hostNodes.size() * (m_hostNodes.size() - 1);
        for (size_t i = 0; i < m_hostNodes.size() && linkCounter < linkSum; i++)
            DfsFromHostIndex(i, hostLink, linkCounter);
    }
    else
    {
        if (m_buildType == "fattree")
        {
            BuildFattreeFlowTable();
        }
        else
        {
            if (m_buildType == "silkroad")
            {
                BuildSilkroadFlowTable();
            }
        }
    }
}

void
BuildFlowtableHelper::DfsFromHostIndex(unsigned int hostIndex,
                                       std::vector<std::vector<unsigned int>>& hostLink,
                                       unsigned int& linkCounter)
{
    std::stack<SaveNode_t> passSwitch;
    std::set<unsigned int> recordPassSwitch;
    Dfs(hostIndex,
        m_hostNodes[hostIndex].linkSwitchIndex,
        m_hostNodes[hostIndex].portIndex,
        passSwitch,
        recordPassSwitch,
        hostLink,
        linkCounter);
}

void
BuildFlowtableHelper::Dfs(unsigned int hostIndex,
                          unsigned int switchIndex,
                          unsigned int switchInPort,
                          std::stack<SaveNode_t>& passSwitch,
                          std::set<unsigned int>& recordPassSwitch,
                          std::vector<std::vector<unsigned int>>& hostLink,
                          unsigned int& linkCounter)
{
    unsigned int curPassSwitchNum = passSwitch.size();
    for (size_t t = 0; t < m_switchNodes[switchIndex].portNode.size(); t++) // traver port number
    {
        if (t == switchInPort)
            continue;
        if (m_switchNodes[switchIndex].portNode[t].flag == 0) // represent host
        {
            unsigned int dstHostIndex = m_switchNodes[switchIndex].portNode[t].nodeIndex;
            if (hostLink[hostIndex][dstHostIndex] == 0)
            {
                hostLink[hostIndex][dstHostIndex] = 1;
                hostLink[dstHostIndex][hostIndex] = 1;
                linkCounter += 2;
                std::stack<SaveNode_t> s = passSwitch;
                // add passed switch entry
                while (s.size() > curPassSwitchNum)
                    s.pop();
                while (s.empty() == false)
                {
                    AddFlowtableEntry2(hostIndex,
                                       s.top().inPortIndex,
                                       s.top().switchIndex,
                                       s.top().outPortIndex,
                                       dstHostIndex);
                    s.pop();
                }
                // add cur switch entry
                AddFlowtableEntry2(hostIndex, switchInPort, switchIndex, t, dstHostIndex);
            }
        }
        else // represent switch
        {
            unsigned nextSwitchIndex = m_switchNodes[switchIndex].portNode[t].nodeIndex;
            unsigned nextSwitchPort = m_switchNodes[switchIndex].portNode[t].nodePort;
            if (recordPassSwitch.count(nextSwitchIndex) == 0)
            { // make sure stay in init switch num
                while (passSwitch.size() > curPassSwitchNum)
                    passSwitch.pop();
                passSwitch.push(SaveNode_t(switchIndex, switchInPort, t));
                recordPassSwitch.insert(switchIndex);
                Dfs(hostIndex,
                    nextSwitchIndex,
                    nextSwitchPort,
                    passSwitch,
                    recordPassSwitch,
                    hostLink,
                    linkCounter);
            }
        }
    }
}

std::string
BuildFlowtableHelper::UintToStr(unsigned int num)
{
    if (num != 0)
    {
        std::string res;
        while (num)
        {
            res.insert(res.begin(), num % 10 + '0');
            num /= 10;
        }
        return res;
    }
    else
        return std::string("0");
}

std::string
BuildFlowtableHelper::UintToPortStr(unsigned int num)
{
    if (num != 0)
    {
        std::string res("0x0000");
        unsigned int k = 5;
        int tmp;
        while (num)
        {
            tmp = num % 16;
            if (tmp < 10)
                res[k] = tmp + '0';
            else
                res[k] = tmp - 10 + 'a';
            k--;
            num /= 16;
        }
        return res;
    }
    else
    {
        return std::string("0x0000");
    }
}

void
BuildFlowtableHelper::Write(std::string fileDir)
{
    std::ofstream fp;

    std::ostringstream lineBuffer;

    std::unordered_set<std::string> handledDstIpSet;

    for (size_t i = 0; i < m_switchNodes.size(); i++)
    {
        std::string fileName = "flowtable_" + UintToStr(i);
        fp.open(fileDir + "/" + fileName);
        // set default action
        std::string defaultAction[] = {"table_set_default ipv4_nhop drop",
                                       "table_set_default arp_nhop drop",
                                       "table_set_default forward_table drop"};
        for (int k = 0; k < 3; k++)
        {
            lineBuffer.clear();
            lineBuffer.str("");
            lineBuffer << defaultAction[k] << std::endl;
            fp << lineBuffer.str();
        }

        // add flowtable entry
        // dst port decided by dstIp, so can combile flowtable entries
        // the best solution is to change FlowTableEntry struct
        handledDstIpSet.clear();

        for (size_t j = 0; j < m_switchNodes[i].flowTableEntries.size(); j++)
        {
            if (handledDstIpSet.count(m_switchNodes[i].flowTableEntries[j].dstIp) == 0)
            {
                handledDstIpSet.insert(m_switchNodes[i].flowTableEntries[j].dstIp);
                lineBuffer.clear();
                lineBuffer.str("");
                lineBuffer << "table_add ipv4_nhop set_ipv4_nhop "
                           << m_switchNodes[i].flowTableEntries[j].dstIp << " => "
                           << m_switchNodes[i].flowTableEntries[j].dstIp << std::endl;
                fp << lineBuffer.str();

                lineBuffer.clear();
                lineBuffer.str("");
                lineBuffer << "table_add arp_nhop set_arp_nhop "
                           << m_switchNodes[i].flowTableEntries[j].dstIp << " => "
                           << m_switchNodes[i].flowTableEntries[j].dstIp << std::endl;
                fp << lineBuffer.str();

                lineBuffer.clear();
                lineBuffer.str("");
                lineBuffer << "table_add forward_table set_port "
                           << m_switchNodes[i].flowTableEntries[j].dstIp << " => "
                           << m_switchNodes[i].flowTableEntries[j].outPort << std::endl;
                fp << lineBuffer.str();
            }
        }
        fp.close();
    }
}

} // namespace ns3

/*
table_add ipv4_nhop set_ipv4_nhop dstIp => dstIp
table_add arp_nhop set_arp_nhop dstIp => dstIp
table_add forward_table set_port dstIp => port
*/
