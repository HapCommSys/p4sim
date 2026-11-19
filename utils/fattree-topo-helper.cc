/*
 * SPDX-License-Identifier: Apache-2.0
 * Based on P4Simulator (https://github.com/kphf1995cm/P4Simulator), Apache-2.0.
 *
 * Authors: <https://github.com/kphf1995cm/>
 */

#include "ns3/fattree-topo-helper.h"
#include "ns3/log.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <math.h>
#include <sstream>
#include <time.h>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("FattreeTopoHelper");

FattreeTopoHelper::FattreeTopoHelper(unsigned int podNum, std::string topoFileName)
{
    NS_LOG_FUNCTION_NOARGS();
    Build(podNum);
    m_topoFileName = topoFileName;
}

FattreeTopoHelper::~FattreeTopoHelper()
{
}

void
FattreeTopoHelper::SetTopoFileName(const std::string& topoFileName)
{
    m_topoFileName = topoFileName;
}

unsigned int
FattreeTopoHelper::GetSwitchNum()
{
    return m_switchNum;
}

unsigned int
FattreeTopoHelper::GetPodNum()
{
    return m_podNum;
}

unsigned int
FattreeTopoHelper::GetTerminalNum()
{
    return m_terminalNum;
}

void
FattreeTopoHelper::SetLinkDataRate(std::string dataRate)
{
    m_linkDataRate = dataRate;
}

std::string
FattreeTopoHelper::GetLinkDataRate()
{
    return m_linkDataRate;
}

void
FattreeTopoHelper::SetLinkDelay(std::string delay)
{
    m_linkDelay = delay;
}

std::string
FattreeTopoHelper::GetLinkDelay()
{
    return m_linkDelay;
}

unsigned int
FattreeTopoHelper::GetLinkNum()
{
    return m_linkNum;
}

std::string
FattreeTopoHelper::UintToStr(unsigned int temp)
{
    if (temp == 0)
        return std::string("0");
    std::string res;
    while (temp)
    {
        res.insert(res.begin(), temp % 10 + '0');
        temp /= 10;
    }
    return res;
}

void
FattreeTopoHelper::Build(unsigned int podNum)
{
    srand((unsigned int)time(NULL));
    m_podNum = podNum;
    m_coreSwitchNum = (podNum / 2) * (podNum / 2);
    // maybe overflow
    m_switchNum = 5 * m_coreSwitchNum;
    m_terminalNum = m_coreSwitchNum * podNum;
    m_switchLinkNodeTypeIndex.resize(m_switchNum);
    m_linkNum = 0;
    unsigned int tmlIndex = m_switchNum;
    unsigned int aggrSwitchIndex = m_coreSwitchNum;
    unsigned int edgeSwitchIndex = 3 * m_coreSwitchNum;
    // from core switch start number
    unsigned int halfPodNum = podNum / 2;
    unsigned int curAggrSwitchIndex;
    unsigned int curEdgeSwitchIndex;
    for (unsigned int i = 0; i < podNum; i++) // number pod
    {
        for (unsigned int j = 0; j < halfPodNum; j++) // number switch in pod
        {
            curAggrSwitchIndex = aggrSwitchIndex + i * halfPodNum + j;
            curEdgeSwitchIndex = edgeSwitchIndex + i * halfPodNum + j;
            for (unsigned int p = 0; p < halfPodNum; p++)
            {
                // m_switchLinkNodeTypeIndex[curAggrSwitchIndex].push_back("s"+UintToStr(j*halfPodNum
                // + p));//link core switch
                m_switchLinkNodeTypeIndex[curAggrSwitchIndex].push_back(
                    LinkNodeTypeIndex_t('s',
                                        edgeSwitchIndex + i * halfPodNum + p)); // link edge switch
                m_switchLinkNodeTypeIndex[curEdgeSwitchIndex].push_back(LinkNodeTypeIndex_t(
                    'h',
                    tmlIndex + i * m_coreSwitchNum + j * halfPodNum + p)); // link terminal
                m_linkNum += 2;
            }
        }
    }
    for (unsigned int i = 0; i < m_coreSwitchNum;
         i++) // traverse core switch (every core switch need link every pod)
    {
        unsigned int k = rand() % halfPodNum;
        for (unsigned int j = 0; j < podNum; j++) // traverse pod
        {
            if (k == halfPodNum - 1)
                k = 0;
            else
                k++;
            curAggrSwitchIndex = aggrSwitchIndex + j * halfPodNum + k;
            m_switchLinkNodeTypeIndex[curAggrSwitchIndex].push_back(LinkNodeTypeIndex_t('s', i));
            m_linkNum++;
        }
    }
}

void
FattreeTopoHelper::Write()
{
    std::ofstream file;
    file.open(m_topoFileName);

    char fromType = 's';
    char toType = 's';
    std::string linkDataRate = m_linkDataRate.empty() ? "1000Mbps" : m_linkDataRate;
    std::string linkDelay = m_linkDelay.empty() ? "0.01ms" : m_linkDelay;

    std::ostringstream lineBuffer;
    std::string line;
    lineBuffer << m_switchNum << " " << m_terminalNum << " " << m_linkNum << std::endl;
    file << lineBuffer.str();

    // write link info
    for (unsigned int i = 0; i < m_switchNum; i++)
    {
        for (std::vector<LinkNodeTypeIndex_t>::iterator iter = m_switchLinkNodeTypeIndex[i].begin();
             iter != m_switchLinkNodeTypeIndex[i].end();
             iter++)
        {
            // from,fromType,*iter,*iter,toType,*iter,linkAttr
            lineBuffer.clear();
            lineBuffer.str("");
            if (iter->type == 's')
            {
                toType = 's';
                lineBuffer << i << " " << fromType << " " << iter->index << " " << toType << " "
                           << linkDataRate << " " << linkDelay << std::endl;
            }
            else
            {
                toType = 'h';
                lineBuffer << i << " " << fromType << " " << iter->index << " " << toType << " "
                           << linkDataRate << " " << linkDelay << std::endl;
            }
            file << lineBuffer.str();
        }
    }

    // write switch network function info
    for (unsigned int i = 0; i < m_switchNum; i++)
    {
        lineBuffer.clear();
        lineBuffer.str("");
        lineBuffer << i << " " << "BASIC" << std::endl;
        file << lineBuffer.str();
    }

    file.close();
}

void
FattreeTopoHelper::Show()
{
    for (unsigned int i = 0; i < m_switchNum; i++)
    {
        std::cout << i << ": ";
        for (std::vector<LinkNodeTypeIndex_t>::iterator iter = m_switchLinkNodeTypeIndex[i].begin();
             iter != m_switchLinkNodeTypeIndex[i].end();
             ++iter)
        {
            std::cout << iter->type << " " << iter->index << std::endl;
        }
        std::cout << std::endl;
    }
}
} // namespace ns3
