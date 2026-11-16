/*
 * Copyright (c) 2010 Universita' di Firenze, Italy
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
 * Author: Tommaso Pecorella <tommaso.pecorella@unifi.it>
 * Modified: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#include "ns3/log.h"
#include "ns3/p4-topology-reader.h"

#include <fstream>
#include <sstream>
#include <vector>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("P4TopologyReader");

NS_OBJECT_ENSURE_REGISTERED(P4TopologyReader);

TypeId
P4TopologyReader::GetTypeId(void)
{
    static TypeId tid =
        TypeId("ns3::P4TopologyReader").SetParent<Object>().SetGroupName("P4TopologyReader");
    return tid;
}

P4TopologyReader::P4TopologyReader()
{
    NS_LOG_FUNCTION(this);
}

P4TopologyReader::~P4TopologyReader()
{
    NS_LOG_FUNCTION(this);
}

void
P4TopologyReader::SetFileName(const std::string& fileName)
{
    m_fileName = fileName;
}

std::string
P4TopologyReader::GetFileName() const
{
    return m_fileName;
}

/* Manipulating the address block */

P4TopologyReader::ConstLinksIterator_t
P4TopologyReader::LinksBegin(void) const
{
    return m_linksList.begin();
}

P4TopologyReader::ConstLinksIterator_t
P4TopologyReader::LinksEnd(void) const
{
    return m_linksList.end();
}

int
P4TopologyReader::LinksSize(void) const
{
    return m_linksList.size();
}

bool
P4TopologyReader::LinksEmpty(void) const
{
    return m_linksList.empty();
}

void
P4TopologyReader::AddLink(Link link)
{
    m_linksList.push_back(link);
    return;
}

P4TopologyReader::Link::Link(Ptr<Node> fromPtr,
                             unsigned int fromIndex,
                             char fromType,
                             Ptr<Node> toPtr,
                             unsigned int toIndex,
                             char toType)
{
    m_fromPtr = fromPtr;
    m_fromType = fromType;
    m_fromIndex = fromIndex;
    m_toPtr = toPtr;
    m_toType = toType;
    m_toIndex = toIndex;
}

P4TopologyReader::Link::Link()
{
}

Ptr<Node>
P4TopologyReader::Link::GetFromNode(void) const
{
    return m_fromPtr;
}

Ptr<Node>
P4TopologyReader::Link::GetToNode(void) const
{
    return m_toPtr;
}

char
P4TopologyReader::Link::GetFromType(void) const
{
    return m_fromType;
}

char
P4TopologyReader::Link::GetToType(void) const
{
    return m_toType;
}

unsigned int
P4TopologyReader::Link::GetFromIndex(void) const
{
    return m_fromIndex;
}

unsigned int
P4TopologyReader::Link::GetToIndex(void) const
{
    return m_toIndex;
}

std::string
P4TopologyReader::Link::GetAttribute(const std::string& name) const
{
    NS_ASSERT_MSG(m_linkAttr.find(name) != m_linkAttr.end(),
                  "Requested topology link attribute not found");
    return m_linkAttr.find(name)->second;
}

bool
P4TopologyReader::Link::GetAttributeFailSafe(const std::string& name, std::string& value) const
{
    if (m_linkAttr.find(name) == m_linkAttr.end())
    {
        return false;
    }
    value = m_linkAttr.find(name)->second;
    return true;
}

void
P4TopologyReader::Link::SetAttribute(const std::string& name, const std::string& value)
{
    m_linkAttr[name] = value;
}

P4TopologyReader::Link::ConstAttributesIterator_t
P4TopologyReader::Link::AttributesBegin(void) const
{
    return m_linkAttr.begin();
}

P4TopologyReader::Link::ConstAttributesIterator_t
P4TopologyReader::Link::AttributesEnd(void) const
{
    return m_linkAttr.end();
}

bool
P4TopologyReader::Read()
{
    std::ifstream fileStream(GetFileName().c_str());

    if (!fileStream.is_open())
    {
        NS_LOG_WARN("Topology file cannot be opened. Check the filename and permissions.");
        PrintHelp();
        return false;
    }

    // Variables to store topology data
    std::vector<Ptr<Node>> nodes;
    unsigned int fromIndex, toIndex;
    char fromType, toType;
    std::string dataRate, delay;

    int createdNodeNum = 0;
    int nodeNum = 0, switchNum = 0, hostNum = 0, linkNum = 0;

    std::string line;
    std::istringstream lineStream;

    // Read the first line: total number of switches, hosts, and links
    if (!getline(fileStream, line))
    {
        NS_LOG_ERROR("Topology file is empty or invalid format.");
        PrintHelp();
        return false;
    }

    lineStream.str(line);
    if (!(lineStream >> switchNum >> hostNum >> linkNum))
    {
        NS_LOG_ERROR("Invalid format in the first line of the topology file.");
        PrintHelp();
        return false;
    }

    NS_LOG_INFO("P4 topology with " << switchNum << " switches, " << hostNum << " hosts, and "
                                    << linkNum << " links.");

    // Initialize nodes
    nodeNum = switchNum + hostNum;
    nodes.resize(nodeNum, nullptr);

    // Read link information
    for (int i = 0; i < linkNum && !fileStream.eof(); ++i)
    {
        if (!getline(fileStream, line))
        {
            NS_LOG_WARN("Unexpected end of file while reading links.");
            break;
        }

        lineStream.clear();
        lineStream.str(line);

        if (!(lineStream >> fromIndex >> fromType >> toIndex >> toType >> dataRate >> delay))
        {
            NS_LOG_ERROR("Invalid link format at line " << i + 2 << ": " << line);
            continue;
        }

        NS_LOG_INFO("Link " << i << ": from " << fromType << fromIndex << " to " << toType
                            << toIndex << " with DataRate " << dataRate << " and Delay " << delay);

        // Create nodes if they do not exist
        CreateNodeIfNeeded(nodes, fromIndex, createdNodeNum);
        CreateNodeIfNeeded(nodes, toIndex, createdNodeNum);

        // Add port count
        uint32_t fromPort = m_portCounter[fromIndex]++;
        uint32_t toPort = m_portCounter[toIndex]++;

        // Add the link
        AddLinkBetweenNodes(nodes, fromIndex, fromType, toIndex, toType, dataRate, delay);

        // Save the link information
        LinkInfo link_info;
        link_info.fromIndex = fromIndex;
        link_info.fromType = fromType;
        link_info.toIndex = toIndex;
        link_info.toType = toType;
        link_info.dataRate = dataRate;
        link_info.delay = delay;
        link_info.fromPort = fromPort;
        link_info.toPort = toPort;
        m_links.push_back(link_info);
    }

    // Read switch network function information
    if (!ReadSwitchNetworkFunctions(fileStream, switchNum))
    {
        NS_LOG_ERROR("Failed to read switch network functions.");
        PrintHelp();
        return false;
    }

    // Populate m_switches and m_hosts containers
    AddNodesToContainers(nodes, switchNum, hostNum);

    fileStream.close();
    NS_LOG_INFO("P4 topology successfully read with " << createdNodeNum << " nodes created.");
    return true;
}

void
P4TopologyReader::PrintTopology() const
{
    NS_LOG_INFO("==== P4 Topology Overview ====");
    for (const auto& link : m_links)
    {
        std::string fromNode = (link.fromType == 's') ? "Switch" : "Host";
        std::string toNode = (link.toType == 's') ? "Switch" : "Host";

        std::cout << fromNode << " " << link.fromIndex << " Port " << link.fromPort << " Link to "
                  << toNode << " " << link.toIndex << " Port " << link.toPort
                  << " | DataRate: " << link.dataRate << ", Delay: " << link.delay << std::endl;
    }
    NS_LOG_INFO("==== End of Topology Overview ====");
}

// Helper: Add a link between two nodes
void
P4TopologyReader::AddLinkBetweenNodes(const std::vector<Ptr<Node>>& nodes,
                                      int fromIndex,
                                      char fromType,
                                      int toIndex,
                                      char toType,
                                      const std::string& dataRate,
                                      const std::string& delay)
{
    Link link(nodes[fromIndex], fromIndex, fromType, nodes[toIndex], toIndex, toType);
    link.SetAttribute("DataRate", dataRate);
    link.SetAttribute("Delay", delay);
    AddLink(link);

    NS_LOG_INFO("Added link between Node " << fromType << fromIndex << " and Node " << toType
                                           << toIndex);
}

// Helper: Create a node if it doesn't already exist
void
P4TopologyReader::CreateNodeIfNeeded(std::vector<Ptr<Node>>& nodes, int index, int& createdNodeNum)
{
    if (nodes[index] == nullptr)
    {
        nodes[index] = CreateObject<Node>();
        NS_LOG_INFO("Created Node " << index);
        ++createdNodeNum;
    }
}

// Helper: Read switch network function information
bool
P4TopologyReader::ReadSwitchNetworkFunctions(std::ifstream& fileStream, int switchNum)
{
    m_switchNetFunc.resize(switchNum);
    std::string line;
    std::istringstream lineStream;

    for (int i = 0; i < switchNum && !fileStream.eof(); ++i)
    {
        if (!getline(fileStream, line))
        {
            NS_LOG_WARN("Unexpected end of file while reading switch network functions.");
            return false;
        }

        lineStream.clear();
        lineStream.str(line);

        int switchIndex;
        std::string networkFunction;

        if (!(lineStream >> switchIndex >> networkFunction))
        {
            NS_LOG_ERROR("Invalid format in switch network function line: " << line);
            return false;
        }

        m_switchNetFunc[switchIndex] = networkFunction;
        NS_LOG_INFO("Switch " << switchIndex << " assigned function " << networkFunction);
    }
    return true;
}

// Helper: Add nodes to m_switches and m_hosts containers
void
P4TopologyReader::AddNodesToContainers(const std::vector<Ptr<Node>>& nodes,
                                       int switchNum,
                                       int hostNum)
{
    for (int i = 0; i < switchNum; ++i)
    {
        m_switches.Add(nodes[i]);
    }
    for (int i = 0; i < hostNum; ++i)
    {
        m_hosts.Add(nodes[switchNum + i]);
    }

    NS_LOG_INFO("Switches and hosts added to their respective containers.");
}

void
P4TopologyReader::PrintHelp() const
{
    /*
  =====================================================
  P4TopologyReader Help
  =====================================================
  The topology file must follow the specified format:
  1. First line specifies the number of switches, hosts, and links.
     Format: <switch_count> <host_count> <link_count>
     Example: 2 6 7 (2 switches, 6 hosts, 7 links)

  2. Following lines define each link:
     Format: <from_index> <from_type> <to_index> <to_type> <data_rate> <delay>
     - <from_index>, <to_index>: Node indices.
     - <from_type>, <to_type>: Node types ('s' for switch, 'h' for host).
     - <data_rate>: Link bandwidth (e.g., 1000Mbps).
     - <delay>: Link delay (e.g., 0.1ms).
     Example:
     2 h 0 s 1000Mbps 0.1ms
     3 h 0 s 1000Mbps 0.1ms

  3. Switch network functions (optional):
     Format: <switch_index> <network_function>
     - <switch_index>: Index of the switch.
     - <network_function>: The function assigned to the switch.
     Example:
     0 SIMPLE_ROUTER
     1 SIMPLE_ROUTER

  Full Example Topology File:
  =====================================================
  2 6 7
  2 h 0 s 1000Mbps 0.1ms
  3 h 0 s 1000Mbps 0.1ms
  4 h 0 s 1000Mbps 0.1ms
  0 s 1 s 50Mbps 0.1ms
  1 s 5 h 1000Mbps 0.1ms
  1 s 6 h 1000Mbps 0.1ms
  1 s 7 h 1000Mbps 0.1ms
  0 SIMPLE_ROUTER
  1 SIMPLE_ROUTER
  =====================================================

  Common Issues:
  1. Ensure the first line correctly specifies the number of switches, hosts, and links.
  2. Verify each link line follows the correct format and values are valid.
  3. Ensure all switches and hosts mentioned in the link definitions are accounted for.
  4. Make sure the file is not missing switch network functions if they are required.
  =====================================================
  */

    std::cout << "=====================================================\n";
    std::cout << "P4TopologyReader Help\n";
    std::cout << "=====================================================\n";
    std::cout << "The topology file must follow the specified format:\n";
    std::cout << "1. First line specifies the number of switches, hosts, and links.\n";
    std::cout << "   Format: <switch_count> <host_count> <link_count>\n";
    std::cout << "   Example: 2 6 7 (2 switches, 6 hosts, 7 links)\n\n";

    std::cout << "2. Following lines define each link:\n";
    std::cout << "   Format: <from_index> <from_type> <to_index> <to_type> <data_rate> <delay>\n";
    std::cout << "   - <from_index>, <to_index>: Node indices.\n";
    std::cout << "   - <from_type>, <to_type>: Node types ('s' for switch, 'h' for host).\n";
    std::cout << "   - <data_rate>: Link bandwidth (e.g., 1000Mbps).\n";
    std::cout << "   - <delay>: Link delay (e.g., 0.1ms).\n";
    std::cout << "   Example:\n";
    std::cout << "   2 h 0 s 1000Mbps 0.1ms\n";
    std::cout << "   3 h 0 s 1000Mbps 0.1ms\n\n";

    std::cout << "3. Switch network functions (optional):\n";
    std::cout << "   Format: <switch_index> <network_function>\n";
    std::cout << "   - <switch_index>: Index of the switch.\n";
    std::cout << "   - <network_function>: The function assigned to the switch.\n";
    std::cout << "   Example:\n";
    std::cout << "   0 SIMPLE_ROUTER\n";
    std::cout << "   1 SIMPLE_ROUTER\n\n";

    std::cout << "Full Example Topology File:\n";
    std::cout << "=====================================================\n";
    std::cout << "2 6 7\n";
    std::cout << "2 h 0 s 1000Mbps 0.1ms\n";
    std::cout << "3 h 0 s 1000Mbps 0.1ms\n";
    std::cout << "4 h 0 s 1000Mbps 0.1ms\n";
    std::cout << "0 s 1 s 50Mbps 0.1ms\n";
    std::cout << "1 s 5 h 1000Mbps 0.1ms\n";
    std::cout << "1 s 6 h 1000Mbps 0.1ms\n";
    std::cout << "1 s 7 h 1000Mbps 0.1ms\n";
    std::cout << "0 SIMPLE_ROUTER\n";
    std::cout << "1 SIMPLE_ROUTER\n";
    std::cout << "=====================================================\n";
    std::cout << "\n";

    std::cout << "Common Issues:\n";
    std::cout << "1. Ensure the first line correctly specifies the number of switches, hosts, and "
                 "links.\n";
    std::cout << "2. Verify each link line follows the correct format and values are valid.\n";
    std::cout << "3. Ensure all switches and hosts mentioned in the link definitions are accounted "
                 "for.\n";
    std::cout
        << "4. Make sure the file is not missing switch network functions if they are required.\n";
    std::cout << "=====================================================\n";
}

} /* namespace ns3 */
