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
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#ifndef P4_SWITCH_CORE_H
#define P4_SWITCH_CORE_H

#include "ns3/p4-switch-net-device.h"

#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/simple_pre_lag.h>
#include <bm/bm_sim/switch.h>
#include <map>
#include <vector>

#define SSWITCH_DROP_PORT 511

namespace ns3
{

class P4SwitchNetDevice;

class P4SwitchCore : public bm::Switch
{
  public:
    /**
     * @brief Construct a new P4SwitchCore object
     * @param netDevice the P4 switch net device
     * @param enableSwap enable swap
     * @param enableTracing enable tracing
     * @param thriftCommand thrift command string
     * @param dropPort the drop port (default: SSWITCH_DROP_PORT)
     */
    P4SwitchCore(P4SwitchNetDevice* netDevice,
                 bool enableSwap,
                 bool enableTracing,
                 uint32_t dropPort = SSWITCH_DROP_PORT);

    ~P4SwitchCore();

    /**
     * @brief Initialize the switch with the P4 program
     * @param jsonPath the path to the JSON file
     * @return void
     */
    void InitializeSwitchFromP4Json(const std::string& jsonPath);

    /**
     * @brief Set the BMv2 log level used by InitializeSwitchFromP4Json()
     * @param level one of "trace" (default), "debug", "info", "notice", "warn",
     *        "error", "critical", "alert", "emerg" or "off". With "off", no
     *        pipeline log file is written.
     * @note The BMv2 logger is shared by all switches of a process, so the level
     *       of the switch initialized last applies to all of them.
     */
    void SetBmLogLevel(const std::string& level);

    /**
     * @brief Choose the Thrift port, before InitializeSwitchFromP4Json() is called
     * @param port the port to use, or 0 (default) for the first free port starting
     *        at $P4SIM_THRIFT_PORT_BASE (9090 if unset)
     *
     * A port is free if no other p4sim process has reserved it (lock file
     * /tmp/p4sim-thrift-<port>.lock, held until the process exits) and no other
     * program listens on it. The port also names the BMv2 IPC sockets and the
     * pipeline log file, so those do not collide either.
     */
    void SetThriftPort(uint16_t port);

    /**
     * @brief Get the Thrift port of this switch
     * @return the port, or 0 before InitializeSwitchFromP4Json() is called
     */
    int GetThriftPort() const;

    /**
     * @brief Load the flow table to the switch
     * @param flowTablePath the path to the flow table file
     * @return int the status code
     */
    int LoadFlowTableToSwitch(const std::string& flowTablePath);

    /**
     * @brief Initialize the switch from command line options
     * @param argc the number of command line arguments
     * @param argv the command line arguments
     * @return int the status code
     */
    int InitFromCommandLineOptions(int argc, char* argv[]);

    /**
     * @brief Execute the CLI commands from a file
     * @param commandsFile the path to the CLI commands file
     * @return int the status code
     */
    int ExecuteCliCommands(const std::string& commandsFile);

    /**
     * @brief Receive a packet from the network
     * @param packetIn the incoming packet
     * @param inPort the switch port where the packet is received
     * @param protocol the protocol of the packet
     * @param destination the destination address of the packet
     * @return int the status code
     */
    virtual int ReceivePacket(Ptr<Packet> packetIn,
                              int inPort,
                              uint16_t protocol,
                              const Address& destination) = 0;

    /**
     * @brief Convert a bm packet to ns-3 packet
     *
     * @param bmPacket the bm packet
     * @return Ptr<Packet> the ns-3 packetclear
     */
    Ptr<Packet> ConvertToNs3Packet(std::unique_ptr<bm::Packet>&& bmPacket);

    /**
     * @brief Convert a ns-3 packet to bm packet
     *
     * @param nsPacket the ns-3 packet
     * @param inPort the port where the packet is received
     * @return std::unique_ptr<bm::Packet> the bm packet
     */
    std::unique_ptr<bm::Packet> ConvertToBmPacket(Ptr<Packet> nsPacket, int inPort);

    /**
     * @brief Returns the elapsed time since the switch started.
     *
     * This function calculates the difference between the current simulation time
     * (in nanoseconds) and the recorded start timestamp of the switch. Notice the
     * p4 only support 48-bit timestamp, so the timestamp will be truncated to 48-bit.
     *
     * @return The elapsed time in nanoseconds as a 64-bit unsigned integer.
     */
    uint64_t GetTimeStamp();

    // === override ===
    /**
     * @brief [Deprecated] Receive a packet from the network, using ReceivePacket instead.
     * @param port_num the port number
     * @param buffer the buffer
     * @param len the length of the buffer
     */
    int receive_(uint32_t port_num, const char* buffer, int len) override;

    /**
     * @brief Call this function after initialization of the switch to start the switch
     */
    void start_and_return_() override;

    /**
     *  @brief Notify the switch of a configuration swap
     */
    void swap_notify_() override;

    /**
     * @brief Reset the target-specific state of the switch
     */
    void reset_target_state_() override;

    /**
     * @brief Configuration for a mirroring session
     * @details The configuration includes the egress port and the multicast group ID. The egress
     * port is the port where the cloned packet is sent to. The multicast group ID is the ID of the
     * multicast group where the cloned packet is sent to.
     */
    struct MirroringSessionConfig
    {
        uint32_t egress_port;
        bool egress_port_valid;
        unsigned int mgid;
        bool mgid_valid;
    };

    /**
     * @brief Add a mirroring session to the switch
     * @param mirrorId the ID of the mirroring session, 0 to 32767
     * @param config the configuration of the mirroring session
     * @return bool true if the mirroring session is added successfully, false otherwise
     */
    bool AddMirroringSession(int mirrorId, const MirroringSessionConfig& config);

    /**
     * @brief Delete a mirroring session from the switch
     * @param mirrorId the ID of the mirroring session
     * @return bool true if the mirroring session is deleted successfully, false otherwise
     */
    bool DeleteMirroringSession(int mirrorId);

    /**
     * @brief Get the configuration of a mirroring session
     * @param mirrorId the ID of the mirroring session, 0 to 32767
     * @param config the configuration of the mirroring session
     * @return bool true if the mirroring session is found, false otherwise
     */
    bool GetMirroringSession(int mirrorId, MirroringSessionConfig* config) const;

    // Disabling copy and move operations
    P4SwitchCore(const P4SwitchCore&) = delete;
    P4SwitchCore& operator=(const P4SwitchCore&) = delete;
    P4SwitchCore(P4SwitchCore&&) = delete;
    P4SwitchCore&& operator=(P4SwitchCore&&) = delete;

  protected:
    /**
     * @brief Check the queueing metadata
     */
    void CheckQueueingMetadata();

    /**
     * @brief Add the Thrift services of the target to the Thrift server of this
     * switch, such as "simple_switch" for the commands that simple_switch_CLI adds
     * to the runtime CLI. ExecuteCliCommands() calls it after starting the server.
     * The default adds none.
     */
    virtual void AddThriftServices();

    /**
     * @brief Ingress processing pipeline
     */
    virtual void HandleIngressPipeline() = 0;

    /**
     * @brief Enqueue a packet to the switch queue buffer
     * @param egress_port the egress port
     * @param packet the packet to enqueue
     */
    virtual void Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet) = 0;

    /**
     * @brief Egress processing pipeline
     * @param workerId the worker ID
     * @return bool true if the packet is processed successfully, false otherwise
     */
    virtual bool HandleEgressPipeline(size_t workerId) = 0;

    /**
     * @brief Retrieves the index of the given destination address.
     *
     * This function checks if the specified destination address already exists
     * in the internal address map. If it exists, the corresponding index is returned.
     * If not, a new index is assigned by adding the address to the destination list,
     * updating the map, and then returning the newly assigned index.
     *
     * @param destination The destination address to look up.
     * @return The index of the destination address in the internal list.
     *
     * @note This function updates the internal address map and destination list
     *       if the address is not found, ensuring a unique index for each address.
     */
    int GetAddressIndex(const Address& destination);

    int m_p4SwitchId;                          //!< ID of the switch
    P4SwitchNetDevice* m_switchNetDevice;      //!< Pointer to the switch net device
    bool m_enableTracing;                      //!< Enable tracing
    bool m_enableQueueingMetadata{false};      //!< Enable queueing metadata
    uint32_t m_dropPort;                       //!< Port to drop packets
    std::string m_thriftCommand;               //!< Thrift command
    std::shared_ptr<bm::McSimplePreLAG> m_pre; //!< Multicast pre-LAG

    std::vector<Address> m_destinationList; //!< List of addresses (O(log n) search)
    std::map<Address, int> m_addressMap;    //!< Map for fast lookup
  private:
    class MirroringSessions;            //!< Mirroring sessions for clone .etc
    int m_thriftPort{0};                //!< Thrift port of the switch (allocated at init)
    uint16_t m_requestedThriftPort{0};  //!< Requested Thrift port, 0 = automatic
    std::string m_bmLogLevel{"trace"};  //!< BMv2 log level
    size_t m_nbQueuesPerPort;           //!< Number of queues per port (default 8)
    uint64_t m_packetId{0};             //!< Packet ID
    uint64_t m_startTimestamp;          //!< Start time of the switch
    bm::TargetParserBasic* m_argParser; //!< Structure of parsers
    std::unique_ptr<MirroringSessions> m_mirroringSessions; //!< Mirroring sessions
};

} // namespace ns3

#endif // !P4_CORE_V1MODEL_H