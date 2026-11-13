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

#ifndef P4_TOPOLOGY_READER_H
#define P4_TOPOLOGY_READER_H

#include "ns3/node-container.h"
#include "ns3/object.h"

#include <list>
#include <map>
#include <string>
#include <vector>

namespace ns3
{

/**
 * \ingroup topology
 *
 * \brief Interface for input file readers management.
 *
 * This interface perform the shared tasks among all possible input file readers.
 * Each different file format is handled by its own topology reader.
 */
class P4TopologyReader : public Object
{
  public:
    /**
     * \brief Get the type ID.
     * \return The object TypeId.
     */
    static TypeId GetTypeId(void);

    /**
     * \brief Inner class holding the details about a link between two nodes.
     *
     * The link is not described in terms of technology. Rather it is only stating
     * an association between two nodes. The nodes are characterized also with names
     * reflecting how the nodes are called in the original topology file.
     */
    class Link
    {
      public:
        /**
         * \brief Constant iterator to scan the map of link attributes.
         */
        typedef std::map<std::string, std::string>::const_iterator ConstAttributesIterator_t;
        Link(Ptr<Node> fromPtr,
             unsigned int fromIndex,
             char fromType,
             Ptr<Node> toPtr,
             unsigned int toIndex,
             char toType);

        /**
         * \brief Returns a Ptr<Node> to the "from" node of the link.
         * \return A Ptr<Node> to the "from" node of the link.
         */
        Ptr<Node> GetFromNode(void) const;

        /**
         * \brief Returns a Ptr<Node> to the "to" node of the link.
         * \return A Ptr<Node> to the "to" node of the link.
         */
        Ptr<Node> GetToNode(void) const;

        char GetFromType(void) const;
        char GetToType(void) const;

        unsigned int GetFromIndex(void) const;
        unsigned int GetToIndex(void) const;

        /**
         * \brief Returns the value of a link attribute. The attribute must exist.
         * \param [in] name the name of the attribute.
         * \return The value of the attribute.
         */
        std::string GetAttribute(const std::string& name) const;
        /**
         * \brief Returns the value of a link attribute.
         * \param [in] name The name of the attribute.
         * \param [out] value The value of the attribute.
         *
         * \return True if the attribute was defined, false otherwise.
         */
        bool GetAttributeFailSafe(const std::string& name, std::string& value) const;
        /**
         * \brief Sets an arbitrary link attribute.
         * \param [in] name The name of the attribute.
         * \param [in] value The value of the attribute.
         */
        void SetAttribute(const std::string& name, const std::string& value);
        /**
         * \brief Returns an iterator to the begin of the attributes.
         * \return A const iterator to the first attribute of a link.
         */
        ConstAttributesIterator_t AttributesBegin(void) const;
        /**
         * \brief Returns an iterator to the end of the attributes.
         * \return A const iterator to the last attribute of a link.
         */
        ConstAttributesIterator_t AttributesEnd(void) const;

      private:
        Link();
        Ptr<Node> m_fromPtr; //!< The node the links originates from.
        Ptr<Node> m_toPtr;   //!< The node the links is directed to.

        char m_fromType;          //!< s or h
        unsigned int m_fromIndex; //!< direct siwtch index
        char m_toType;
        unsigned int m_toIndex;

        std::map<std::string, std::string>
            m_linkAttr; //!< Container of the link attributes (if any).
    };

    /**
     * \brief Constant iterator to the list of the links.
     */
    typedef std::list<Link>::const_iterator ConstLinksIterator_t;

    P4TopologyReader();
    virtual ~P4TopologyReader();

    NodeContainer GetHostNodeContainer(void) const
    {
        return m_hosts;
    }

    NodeContainer GetSwitchNodeContainer(void) const
    {
        return m_switches;
    }

    std::vector<std::string> GetSwitchNetFunc(void) const
    {
        return m_switchNetFunc;
    }

    /**
     * \brief Main topology reading function.
     * \return True if the reading was successful, false otherwise.
     */
    bool Read();

    /**
     * \brief Create a node if it doesn't already exist
     * \param [in] nodes The vector of nodes.
     * \param [in] index The index of the node to be created.
     * \param [in] createdNodeNum The number of nodes created so far.
     * \return True if the node was created, false otherwise.
     */
    void CreateNodeIfNeeded(std::vector<Ptr<Node>>& nodes, int index, int& createdNodeNum);

    /**
     * \brief Add a link between two nodes
     * \param [in] nodes The vector of nodes.
     * \param [in] fromIndex The index of the "from" node.
     * \param [in] fromType The type of the "from" node.
     * \param [in] toIndex The index of the "to" node.
     * \param [in] toType The type of the "to" node.
     * \param [in] dataRate The data rate of the link.
     * \param [in] delay The delay of the link.
     */
    void AddLinkBetweenNodes(const std::vector<Ptr<Node>>& nodes,
                             int fromIndex,
                             char fromType,
                             int toIndex,
                             char toType,
                             const std::string& dataRate,
                             const std::string& delay);

    /**
     * \brief Read switch network function information
     * \param [in] fileStream The input file stream.
     * \param [in] switchNum The number of switches.
     * \return True if the reading was successful, false otherwise.
     */
    bool ReadSwitchNetworkFunctions(std::ifstream& fileStream, int switchNum);

    /**
     * \brief Add nodes to m_switches and m_hosts containers
     * \param [in] nodes The vector of nodes.
     * \param [in] switchNum The number of switches.
     * \param [in] hostNum The number of hosts.
     * \return True if the containers were populated, false otherwise.
     *
     */
    void AddNodesToContainers(const std::vector<Ptr<Node>>& nodes, int switchNum, int hostNum);

    /**
     * \brief Print the help message.
     */
    void PrintHelp() const;

    /**
     * \brief Sets the input file name.
     * \param [in] fileName The input file name.
     */
    void SetFileName(const std::string& fileName);

    /**
     * \brief Returns the input file name.
     * \return The input file name.
     */
    std::string GetFileName(void) const;

    /**
     * \brief Returns an iterator to the the first link in this block.
     * \return A const iterator to the first link in this block.
     */
    ConstLinksIterator_t LinksBegin(void) const;

    /**
     * \brief Returns an iterator to the the last link in this block.
     * \return A const iterator to the last link in this block.
     */
    ConstLinksIterator_t LinksEnd(void) const;

    /**
     * \brief Returns the number of links in this block.
     * \return The number of links in this block.
     */
    int LinksSize(void) const;

    /**
     * \brief Checks if the block contains any links.
     * \return True if there are no links in this block, false otherwise.
     */
    bool LinksEmpty(void) const;

    /**
     * \brief Adds a link to the topology.
     * \param link [in] The link to be added.
     */
    void AddLink(Link link);

    void PrintTopology() const;

    NodeContainer GetHosts(void) const
    {
        return m_hosts;
    }

    NodeContainer GetSwitches(void) const
    {
        return m_switches;
    }

  private:
    /**
     * \brief Copy constructor
     *
     * Defined and unimplemented to avoid misuse.
     */
    P4TopologyReader(const P4TopologyReader&);
    /**
     * \brief Copy constructor
     *
     * Defined and unimplemented to avoid misuse.
     * \returns
     */
    P4TopologyReader& operator=(const P4TopologyReader&);

    /**
     * The name of the input file.
     */
    std::string m_fileName;

    /**
     * The container of the links between the nodes.
     */
    std::list<Link> m_linksList;

    struct LinkInfo // Save topology information
    {
        unsigned int fromIndex;
        char fromType;
        unsigned int toIndex;
        char toType;
        std::string dataRate;
        std::string delay;
        uint32_t fromPort;
        uint32_t toPort;
    };

    std::vector<LinkInfo> m_links;                  //!< Save all link information
    std::map<unsigned int, uint32_t> m_portCounter; //!< Port counter for each node

  protected:
    NodeContainer m_hosts;

    NodeContainer m_switches;

    std::vector<std::string> m_switchNetFunc;
    // end class TopologyReader
};

// end namespace ns3
}; // namespace ns3

#endif /* P4_TOPOLOGY_READER_H */
