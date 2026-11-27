/*
 * Copyright (c) 2025 TU Dresden
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 */

#ifndef P4_SWITCH_CORE_H
#define P4_SWITCH_CORE_H

#include "ns3/event-id.h"
#include "ns3/nstime.h"
#include "ns3/p4-switch-net-device.h"

#include <atomic>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/simple_pre_lag.h>
#include <bm/bm_sim/switch.h>
#include <deque>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#define SSWITCH_DROP_PORT 511

namespace apache
{
namespace thrift
{
class TProcessor;
} // namespace thrift
} // namespace apache

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
     * @param thriftCommand thrift command string
     * @param dropPort the drop port (default: SSWITCH_DROP_PORT)
     */
    P4SwitchCore(P4SwitchNetDevice* netDevice,
                 bool enableSwap,
                 uint32_t dropPort = SSWITCH_DROP_PORT);

    ~P4SwitchCore();

    /**
     * @brief Initialize the switch with the P4 program
     *
     * It also seeds RandomEngine() from ns-3's seed and run.
     *
     * @param jsonPath the path to the JSON file
     * @return void
     */
    void InitializeSwitchFromP4Json(const std::string& jsonPath);

    /**
     * @brief Look for a primitive that the P4 program calls and this architecture lacks
     *
     * BMv2 finds a primitive by its name alone: a PNA program that calls
     * recirculate() meets the recirculate of v1model, and BMv2 reports a wrong
     * number of parameters. InitializeSwitchFromP4Json() ends the simulation
     * with this message instead, before BMv2 reads the program.
     *
     * @param jsonPath the path to the JSON file
     * @return a message that names the first such call, its source line and
     *         what to use instead; empty if there is none
     */
    std::string CheckPrimitives(const std::string& jsonPath) const;

    /**
     * @brief The random number engine of the P4 programs
     *
     * random() of v1model draws from it. Each switch seeds it from ns-3's seed
     * and run number (RngSeedManager, or --RngSeed and --RngRun) when it loads
     * its program, so a simulation gives the same random numbers every time it
     * runs with the same seed and run. All switches of a process share it; the
     * P4 programs run in the simulation thread.
     *
     * @return the engine
     */
    static std::mt19937_64& RandomEngine();

    /**
     * @brief Set the BMv2 log level used by InitializeSwitchFromP4Json()
     * @param level one of "trace", "debug", "info", "notice", "warn", "error",
     *        "critical", "alert", "emerg" or "off" (default). With "off", no
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
     * @brief Stop the Thrift services of this switch; call it before the switch
     *        is destroyed (P4SwitchNetDevice::DoDispose() does)
     *
     * BMv2 cannot stop the Thrift server of a switch: it runs until the process
     * ends. Its services run each call only while the switch has not stopped
     * them, and a call that runs when they are stopped finishes first. Afterwards
     * the server answers every call with an error ("... destroyed"), so a runtime
     * CLI that connects late does not reach the freed switch.
     */
    void StopThriftServices();

    /**
     * @brief Set the time a packet spends in the P4 pipeline (the PipelineDelay
     *        attribute of P4SwitchNetDevice)
     * @param delay the delay, not negative; 0 (the default) means none
     *
     * Every packet that the switch puts into its egress queues gets there this
     * much later: packets that leave the ingress, ingress and egress clones, and
     * multicast copies. The pipeline takes the next packet at once, so the delay
     * adds latency but does not lower the throughput. A recirculated packet
     * passes the pipeline again and is delayed again.
     */
    void SetPipelineDelay(Time delay);

    /**
     * @brief Get the time a packet spends in the P4 pipeline
     * @return the delay set by SetPipelineDelay()
     */
    Time GetPipelineDelay() const;

    /**
     * @brief Set the size of each port's transfer buffer (the TransferBufferSize
     *        attribute of P4SwitchNetDevice)
     * @param frames how many frames a port holds after the egress pipeline,
     *        besides the one it is sending; 0 (the default) means none
     *
     * The transfer buffer stands for the hardware port queue after the egress.
     * A port takes its next packet from the egress queues when it is idle or its
     * transfer buffer has room; the packet passes the egress pipeline at once and
     * waits in the transfer buffer, in order, until the port has sent the frames
     * before it. So the backlog of a congested port stays in the egress queues,
     * where the priorities are applied, and a frame in the transfer buffer is not
     * overtaken any more. The transfer buffer never drops. With 0, a port takes
     * its next packet only when it is idle. v1model (without the VOQ traffic
     * manager) and PSA; PNA and the pipeline core have no egress queues and do
     * not use it.
     */
    void SetTransferBufferSize(uint32_t frames);

    /**
     * @brief Get the size of each port's transfer buffer
     * @return the size set by SetTransferBufferSize()
     */
    uint32_t GetTransferBufferSize() const;

    /**
     * @brief Get the number of frames in a port's transfer buffer
     * @param port the port
     * @return the frames that passed the egress pipeline and wait for the port
     */
    uint32_t GetTransferBufferLength(uint32_t port) const;

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
     *
     * Empty lines and lines that start with '#' are skipped. A command that the
     * CLI reports as an error is printed with its line number, and the rest of
     * the file runs. A file that cannot be read ends the simulation. It can be
     * called again later in the simulation: the first call starts the Thrift
     * server of the switch, and the later calls use it.
     *
     * @param commandsFile the path to the CLI commands file, empty for none
     * @return 0 if every command ran without an error, 1 otherwise
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
     * @brief Load a new P4 program for a later swap_configs() (BMv2 runtime API;
     *        also behind the runtime CLI and P4Controller::LoadNewConfig())
     * @param newConfig the BMv2 JSON of the program
     * @return SUCCESS, or the BMv2 error (CONFIG_SWAP_DISABLED without EnableSwap)
     */
    bm::RuntimeInterface::ErrorCode load_new_config(const std::string& newConfig) override;

    /**
     * @brief Swap to the program loaded by load_new_config() (BMv2 runtime API;
     *        also behind the runtime CLI and P4Controller::SwapConfigs())
     *
     * BMv2 swaps only when the switch holds no packet, and its swap_configs()
     * waits for that, which in a simulation would wait forever. So the switch
     * swaps at once if it holds no packet, and otherwise when its last packet
     * has left. Until then the packets in the switch go on with the old program,
     * and the frames that arrive wait; after the swap they enter the pipeline in
     * their order, with the new program. simple_switch also takes no new packet
     * during a swap. A swap asked for by the runtime CLI, from the Thrift server's
     * thread, takes place in the simulation, at the next packet event of the switch.
     *
     * @return SUCCESS if the swap is done or waits, otherwise the BMv2 error
     *         (CONFIG_SWAP_DISABLED, NO_ONGOING_SWAP)
     */
    bm::RuntimeInterface::ErrorCode swap_configs() override;

    /**
     * @brief Whether a swap waits for the switch to empty (see swap_configs())
     * @return true while it waits
     */
    bool IsSwapPending() const;

    /**
     * @brief Keep a frame that arrives while a swap waits (see swap_configs())
     * @param frame the frame
     * @param inPort the port where it arrived
     * @param protocol its protocol
     * @param destination its destination address
     * @return true if the frame was kept: it enters the pipeline after the swap
     */
    bool HoldDuringSwap(Ptr<Packet> frame,
                        int inPort,
                        uint16_t protocol,
                        const Address& destination);

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
     * to the runtime CLI, with AddThriftService(). ExecuteCliCommands() calls it
     * after starting the server. The default adds none.
     */
    virtual void AddThriftServices();

    /**
     * @brief Add a Thrift service to the Thrift server of this switch, guarded:
     * it runs a call only until StopThriftServices()
     * @param name the name of the service, as the runtime CLI asks for it
     * @param processor the Thrift processor of the service
     */
    void AddThriftService(const std::string& name,
                          std::shared_ptr<apache::thrift::TProcessor> processor);

    /**
     * @brief The primitives that this architecture lacks, for CheckPrimitives()
     * @return for each primitive (as the P4 JSON names it), what the message
     *         suggests instead. The default is none.
     */
    virtual std::map<std::string, std::string> GetMissingPrimitives() const;

    /**
     * @brief Ingress processing pipeline
     */
    virtual void HandleIngressPipeline() = 0;

    /**
     * @brief Set the packet rate of the ingress pipeline (SwitchRate)
     * @param pps packets per second; 0 = no limit
     */
    void SetPipelineRate(uint64_t pps);

    /**
     * @brief Let the ingress pipeline take the packets in the input buffer as
     * the pipeline rate allows: at once if the rate is 0 or the pipeline is
     * idle, otherwise when the pipeline is free again. Call it after each push
     * into the input buffer.
     */
    void StartIngress();

    /**
     * @brief Get the number of packets in the input buffer
     * @return the number of packets; a core that calls StartIngress() must override this
     */
    virtual size_t GetNInputPackets() const
    {
        return 0;
    }

    /**
     * @brief Put a packet into the egress queues once the pipeline delay is over
     *        (see SetPipelineDelay()); without a delay, at once. Every packet that
     *        goes to the egress queues passes here.
     * @param egress_port the egress port
     * @param packet the packet to enqueue
     */
    void Enqueue(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet);

    /**
     * @brief Put a packet into the egress queues of the target, now
     * @param egress_port the egress port
     * @param packet the packet to enqueue
     */
    virtual void EnqueueNow(uint32_t egress_port, std::unique_ptr<bm::Packet>&& packet) = 0;

    /**
     * @brief Egress processing pipeline
     * @param workerId the worker ID
     * @return bool true if the packet is processed successfully, false otherwise
     */
    virtual bool HandleEgressPipeline(size_t workerId) = 0;

    /**
     * @brief If a swap waits (see swap_configs()), check after the current event
     *        whether the switch still holds a packet, and swap if not. Call it
     *        where a packet may leave the switch: sent, dropped or done.
     */
    void CheckPendingSwap();

    /**
     * @brief Pass on the digest of \p packet: digest() in the ingress chose the
     *        learn list \p listId. Call it at the end of the ingress, where
     *        simple_switch calls learn(). As there, the fields are read now, from
     *        the PHV of the packet. BMv2's learn engine gets the packet (for its
     *        notification socket), and the device the record (see
     *        P4SwitchNetDevice::NotifyDigest()); every call gives one record.
     * @param listId the learn list
     * @param packet the packet
     */
    void Learn(int listId, const bm::Packet& packet);

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

    /**
     * @brief The destination address with an index that GetAddressIndex() gave
     * @param index the index, as the packet registers keep it
     * @return the address; another index aborts in a build with asserts (a
     *         packet copy whose registers were not set, for example)
     */
    const Address& GetDestination(int index) const;

    /// A frame that passed the egress pipeline and waits for its port
    struct TransferFrame
    {
        Ptr<Packet> packet; //!< the frame
        uint16_t protocol;  //!< its protocol
        int addressIndex;   //!< index of its destination address in m_destinationList
    };

    /**
     * @brief Whether a port can take its next packet from the egress queues
     *        (see SetTransferBufferSize())
     * @param port the port
     * @param transmitterFree whether the port could send a frame now
     * @return true if the port is idle with an empty transfer buffer, or its
     *         transfer buffer has room
     */
    bool PortCanTakePacket(uint32_t port, bool transmitterFree) const;

    /// The transfer buffer of each port, oldest frame first (see SetTransferBufferSize())
    std::unordered_map<uint32_t, std::deque<TransferFrame>> m_transferBuffers;

    int m_p4SwitchId;                          //!< ID of the switch
    P4SwitchNetDevice* m_switchNetDevice;      //!< Pointer to the switch net device
    bool m_enableQueueingMetadata{false};      //!< Enable queueing metadata
    uint32_t m_dropPort;                       //!< Port to drop packets
    std::string m_thriftCommand;               //!< Thrift command
    std::shared_ptr<bm::McSimplePreLAG> m_pre; //!< Multicast pre-LAG

    std::vector<Address> m_destinationList; //!< List of addresses (O(log n) search)
    std::map<Address, int> m_addressMap;    //!< Map for fast lookup
  private:
    /**
     * @brief Print the commands that the runtime CLI reported as errors, with
     * the file and the line, and the command at which it stopped
     * @param file the path to the CLI commands file
     * @param commands the line number and text of each command given to the CLI
     * @param output what the CLI printed
     * @return whether an error was printed
     */
    bool ReportCliErrors(const std::string& file,
                         const std::vector<std::pair<uint32_t, std::string>>& commands,
                         const std::string& output) const;

    class MirroringSessions;            //!< Mirroring sessions for clone .etc
    int m_thriftPort{0};                //!< Thrift port of the switch (allocated at init)
    bool m_thriftServerStarted{false};  //!< ExecuteCliCommands() started the Thrift server
    uint16_t m_requestedThriftPort{0};  //!< Requested Thrift port, 0 = automatic
    std::string m_bmLogLevel{"off"};    //!< BMv2 log level
    size_t m_nbQueuesPerPort;           //!< Number of queues per port (default 8)
    uint64_t m_packetId{0};             //!< Packet ID
    uint64_t m_startTimestamp;          //!< Start time of the switch
    bm::TargetParserBasic* m_argParser; //!< Structure of parsers
    std::unique_ptr<MirroringSessions> m_mirroringSessions; //!< Mirroring sessions

    /**
     * @brief Register the Thrift services of this switch, guarded (see
     * StopThriftServices()): BMv2's "standard" and "simple_pre"/"simple_pre_lag",
     * which the server added unguarded, and those of the target
     * (AddThriftServices()). ExecuteCliCommands() calls it once the server listens.
     */
    void GuardThriftServices();

    uint64_t m_thriftId{0}; //!< ID of this switch's Thrift services; 0 = none

    /**
     * @brief Run the ingress pipeline on the next packet of the input buffer,
     * and schedule the one after it one service time (1/SwitchRate) later.
     */
    void ServeIngress();

    Time m_ingressServiceTime; //!< 1/SwitchRate, the pipeline's time per packet; 0 = no limit
    Time m_ingressFreeAt;      //!< when the pipeline can take the next packet
    EventId m_ingressEvent;    //!< the pending ServeIngress()

    /**
     * @brief Put the packets whose pipeline delay is over into the egress queues,
     * and schedule this again for the next one.
     */
    void ReleaseFromPipeline();

    /// A packet in the pipeline: it waits for the end of its pipeline delay
    struct PipelinePacket
    {
        Time leaves;                        //!< when it reaches the egress queues
        uint32_t egressPort;                //!< its egress port
        std::unique_ptr<bm::Packet> packet; //!< the packet
    };

    uint32_t m_transferBufferSize{0};             //!< see SetTransferBufferSize(); 0 = none
    Time m_pipelineDelay;                         //!< see SetPipelineDelay(); 0 = none
    std::deque<PipelinePacket> m_pipelinePackets; //!< the packets in the pipeline, oldest first
    EventId m_pipelineEvent;                      //!< the pending ReleaseFromPipeline()

    /// Whether the switch holds a packet, as BMv2 counts them for a swap, or a frame
    /// in a transfer buffer
    bool HoldsPackets();

    /// Do the waiting swap if the switch holds no packet, then let in the held frames
    void TrySwap();

    /// A frame that arrived while a swap waited
    struct HeldFrame
    {
        Ptr<Packet> frame;   //!< the frame
        int inPort;          //!< the port where it arrived
        uint16_t protocol;   //!< its protocol
        Address destination; //!< its destination address
    };

    std::atomic<bool> m_newConfigLoaded{false}; //!< load_new_config() succeeded, no swap since
    std::atomic<bool> m_swapPending{false};     //!< swap_configs() waits for the switch to empty
    std::thread::id m_simulationThread;         //!< the thread that runs the simulation
    std::deque<HeldFrame> m_heldFrames;         //!< frames that arrived while a swap waited
    EventId m_swapEvent;                        //!< the pending TrySwap()

    /// A learn list of the P4 program ("learn_lists" in the BMv2 JSON)
    struct LearnList
    {
        std::string name;                ///< its name
        std::vector<std::string> fields; ///< its fields, "header.field", in their order
    };

    /// Read the learn lists of the P4 program, unless they are read since the last swap
    void ReadLearnLists();

    std::map<int, LearnList> m_learnLists; //!< the learn lists of the P4 program, by ID
    bool m_learnListsRead{false};          //!< m_learnLists holds those of the current program
};

} // namespace ns3

#endif // !P4_CORE_V1MODEL_H