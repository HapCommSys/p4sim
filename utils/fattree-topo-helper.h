/*
 * SPDX-License-Identifier: Apache-2.0
 * Based on P4Simulator (https://github.com/kphf1995cm/P4Simulator), Apache-2.0.
 *
 * Authors: <https://github.com/kphf1995cm/>
 */

/*
target network topo file
5 2 6 // (switchNum hostNum linkNum)
1 s 3 s 1000Mbps 0.01ms // (index type index type dataRate delay)
1 s 0 s 1000Mbps 0.01ms
2 s 4 s 1000Mbps 0.01ms
2 s 0 s 1000Mbps 0.01ms
3 s 5 h 1000Mbps 0.01ms
4 s 6 h 1000Mbps 0.01ms
0 BASIC
1 BASIC
2 BASIC
3 BASIC
4 BASIC
*/

#ifndef FATTREE_TOPO_HELPER_H
#define FATTREE_TOPO_HELPER_H

#include <string>
#include <vector>

namespace ns3
{
/**
 *
 * \brief build fattree topo
 */
struct LinkNodeTypeIndex_t
{
    char type;
    unsigned int index;

  public:
    LinkNodeTypeIndex_t(char t, unsigned int i)
    {
        type = t;
        index = i;
    }
};

class FattreeTopoHelper
{
  public:
    /*
     * Construct a FattreeTopoHelper
     */
    FattreeTopoHelper(unsigned int podNum, std::string topoFileName = "topo.txt");
    ~FattreeTopoHelper();

    unsigned int GetSwitchNum();
    unsigned int GetPodNum();
    unsigned int GetTerminalNum();
    void SetLinkDataRate(std::string dataRate = "");
    std::string GetLinkDataRate();
    void SetLinkDelay(std::string delay = "");
    std::string GetLinkDelay();
    unsigned int GetLinkNum();
    void SetTopoFileName(const std::string& topoFileName);
    void Write();
    void Show();

  private:
    void Build(unsigned int podNum);
    FattreeTopoHelper(const FattreeTopoHelper&);
    FattreeTopoHelper& operator=(const FattreeTopoHelper&);

    unsigned int m_switchNum;
    // unsigned int m_treeLevelNum;
    unsigned int m_terminalNum;
    unsigned int m_podNum;
    unsigned int m_coreSwitchNum;
    std::vector<std::vector<LinkNodeTypeIndex_t>> m_switchLinkNodeTypeIndex;
    std::string m_topoFileName;
    std::string m_linkDataRate; // eg: 1000Mbps
    std::string m_linkDelay;    // eg: 0.01ms
    unsigned int m_linkNum;
    std::string UintToStr(unsigned int temp);
};
} // namespace ns3

#endif /* FATTREE_TOPO_HELPER_H */
