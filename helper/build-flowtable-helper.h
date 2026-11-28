/*
 * Copyright (c) 2025 TU Dresden
 * SPDX-License-Identifier: Apache-2.0
 * Based on P4Simulator (https://github.com/kphf1995cm/P4Simulator), Apache-2.0.
 */

#ifndef BUILD_FLOWTABLE_HELPER_H
#define BUILD_FLOWTABLE_HELPER_H

#include <vector>
#include <string>
#include <iostream>
#include <stack>
#include <set>
namespace ns3 {

struct HostNode_t
{
  std::string ipAddr;
  unsigned int linkSwitchIndex;
  unsigned int portIndex;

public:
  HostNode_t (const std::string &ip, unsigned int lsi, unsigned int pi)
  {
    ipAddr = ip;
    linkSwitchIndex = lsi;
    portIndex = pi;
  }
};

struct NodeFlagIndex_t
{
  int flag; //0 represent host; 1 represent switch;
  unsigned int nodeIndex;
  unsigned int nodePort;

public:
  NodeFlagIndex_t (int f, unsigned int ni, unsigned int np)
  {
    flag = f;
    nodeIndex = ni;
    nodePort = np;
  }
};

struct FlowTableEntry_t
{
  std::string srcIp;
  std::string dstIp;
  unsigned int outPort;

public:
  FlowTableEntry_t (std::string src, std::string dst, unsigned int port)
  {
    srcIp = src;
    dstIp = dst;
    outPort = port;
  }
};

struct SwitchNode_t
{
  std::vector<FlowTableEntry_t> flowTableEntries;
  std::vector<NodeFlagIndex_t> portNode;

public:
  SwitchNode_t (const std::vector<std::string> &pn) //(s0_0,h0)
  {
    int flag;
    unsigned int nodeIndex;
    unsigned int nodePort;
    for (size_t i = 0; i < pn.size (); i++)
      {
        if (pn[i][0] == 's') //switch
          {
            flag = 1;
            unsigned int pos = pn[i].find ("_");
            nodeIndex = StrToUint (pn[i].substr (1, pos - 1));
            nodePort = StrToUint (pn[i].substr (pos + 1));
            portNode.push_back (NodeFlagIndex_t (flag, nodeIndex, nodePort));
          }
        else //host
          {
            flag = 0;
            nodeIndex = StrToUint (pn[i].substr (1));
            nodePort = 0;
            portNode.push_back (NodeFlagIndex_t (flag, nodeIndex, nodePort));
          }
      }
  }

private:
  unsigned int
  StrToUint (std::string str)
  {
    unsigned int res = 0;
    for (size_t i = 0; i < str.size (); i++)
      {
        res = res * 10 + str[i] - '0';
      }
    return res;
  }
};

struct SaveNode_t
{
  unsigned int switchIndex;
  unsigned int inPortIndex;
  unsigned int outPortIndex;

public:
  SaveNode_t (unsigned int si, unsigned int ipi, unsigned int opi)
  {
    switchIndex = si;
    inPortIndex = ipi;
    outPortIndex = opi;
  }
};

class BuildFlowtableHelper
{
public:
  BuildFlowtableHelper (std::string buildType = "default", unsigned int podNum = 2);
  ~BuildFlowtableHelper ();

  virtual void Write (std::string fileDir);

  void
  Build (const std::vector<unsigned int> &linkSwitchIndex,
         const std::vector<unsigned int> &linkSwitchPort, const std::vector<std::string> &hostIpv4,
         const std::vector<std::vector<std::string>> &switchPortInfo)
  {
    for (size_t i = 0; i < linkSwitchIndex.size (); i++)
      {
        m_hostNodes.push_back (HostNode_t (hostIpv4[i], linkSwitchIndex[i], linkSwitchPort[i]));
      }
    for (size_t i = 0; i < switchPortInfo.size (); i++)
      {
        m_switchNodes.push_back (SwitchNode_t (switchPortInfo[i]));
      }

    SetSwitchesFlowtableEntries ();
  }

  void
  Show ()
  {
    for (size_t i = 0; i < m_switchNodes.size (); i++)
      {
        std::cout << "s" << i << ":" << std::endl;
        for (size_t j = 0; j < m_switchNodes[i].flowTableEntries.size (); j++)
          std::cout << m_switchNodes[i].flowTableEntries[j].srcIp << " "
                    << m_switchNodes[i].flowTableEntries[j].dstIp << " "
                    << m_switchNodes[i].flowTableEntries[j].outPort << std::endl;
      }
  }
  void
  ShowHostSwitchNode ()
  {
    for (size_t i = 0; i < m_hostNodes.size (); i++)
      {
        std::cout << "h" << i << ": " << m_hostNodes[i].ipAddr << " "
                  << m_hostNodes[i].linkSwitchIndex << " " << m_hostNodes[i].portIndex << std::endl;
      }
    for (size_t i = 0; i < m_switchNodes.size (); i++)
      {
        std::cout << "s" << i << ":";
        for (size_t j = 0; j < m_switchNodes[i].portNode.size (); j++)
          {
            std::cout << m_switchNodes[i].portNode[j].flag << " "
                      << m_switchNodes[i].portNode[j].nodeIndex << " "
                      << m_switchNodes[i].portNode[j].nodePort << std::endl;
          }
      }
  }

private:
  unsigned int m_podNum;
  std::string m_buildType;

  void SetSwitchesFlowtableEntries ();

  void DfsFromHostIndex (unsigned int hostIndex, std::vector<std::vector<unsigned int>> &hostLink,
                         unsigned int &linkCounter);

  std::vector<HostNode_t> m_hostNodes;
  std::vector<SwitchNode_t> m_switchNodes;

  BuildFlowtableHelper (const BuildFlowtableHelper &);

  BuildFlowtableHelper operator= (const BuildFlowtableHelper &);

  std::string UintToStr (unsigned int num);

  std::string UintToPortStr (unsigned int num);

  void Dfs (unsigned int hostIndex, unsigned int switchIndex, unsigned int switchInPort,
            std::stack<SaveNode_t> &passSwitch, std::set<unsigned int> &recordPassSwitch,
            std::vector<std::vector<unsigned int>> &hostLink, unsigned int &linkCounter);

  void
  AddFlowtableEntry (unsigned int switchIndex, unsigned int srcIp, unsigned int dstIp,
                     unsigned int outPort)
  {
    m_switchNodes[switchIndex].flowTableEntries.push_back (
        FlowTableEntry_t (m_hostNodes[srcIp].ipAddr, m_hostNodes[dstIp].ipAddr, outPort));
  }

  void
  AddFlowtableEntry2 (unsigned int srcIp, unsigned int inPort, unsigned int switchIndex,
                      unsigned int outPort, unsigned int dstIp)
  {
    m_switchNodes[switchIndex].flowTableEntries.push_back (
        FlowTableEntry_t (m_hostNodes[dstIp].ipAddr, m_hostNodes[srcIp].ipAddr, inPort));
    m_switchNodes[switchIndex].flowTableEntries.push_back (
        FlowTableEntry_t (m_hostNodes[srcIp].ipAddr, m_hostNodes[dstIp].ipAddr, outPort));
  }

  void BuildFattreeFlowTable ();

  void
  BuildSilkroadFlowTable ()
  {
  }
  void
  ShowSwitchReachHostIndex (const std::vector<std::vector<unsigned int>> &switchMap)
  {
    for (size_t i = 0; i < switchMap.size (); i++)
      {
        std::cout << "switch " << i << ":" << std::endl;
        for (size_t j = 0; j < switchMap[i].size (); j++)
          {
            std::cout << switchMap[i][j] << " ";
          }
        std::cout << std::endl;
      }
  }
};

} // namespace ns3

#endif
