P4Sim: P4-Driven Network Simulation
------------------------------------

.. include:: replace.txt
.. highlight:: cpp

.. heading hierarchy:
   ------------- Chapter
   ************* Section (#.#)
   ============= Subsection (#.#.#)
   ############# Paragraph (no number)

P4sim is a P4-driven network simulator that integrates
`P4 <https://p4.org/>`_, the programmable data plane language, with
|ns3|.  It embeds the `BMv2 behavioral model
<https://github.com/p4lang/behavioral-model>`_ so that user-written P4
programs execute inside |ns3| simulations, producing bit-accurate
forwarding behaviour.

Model Description
*****************

The source code lives in ``contrib/p4sim``.

Design
======

A ``P4SwitchNetDevice`` is an |ns3| ``NetDevice`` that forwards frames with a P4
program.  Each switch loads a P4 program compiled for BMv2 (JSON) and, at
start-up, runs a flow-table file with the runtime CLI of its architecture
(``simple_switch_CLI``, ``psa_switch_CLI``, or ``bm_CLI`` for PNA) on its own
Thrift port.  BMv2 is
linked as a library: the parser, the match-action tables, the externs and the
deparser are those of BMv2, while |ns3| provides the ports, the queues and the
time.

The attribute ``P4SwitchArch`` selects the architecture:

.. list-table::
   :header-rows: 1

   * - Value
     - Architecture
     - BMv2 target
     - Core class
   * - 0
     - V1model
     - ``simple_switch``
     - ``P4CoreV1model``
   * - 1
     - PSA
     - ``psa_switch``
     - ``P4CorePsa``
   * - 2
     - PNA
     - ``pna_nic``
     - ``P4PnaNic``
   * - 3
     - Pipeline
     - none
     - ``P4CorePipeline``

**Ports.**  A switch has two kinds of port, which can be mixed.  The port
number is the order in which the ports are added.

* *Switched-Ethernet ports*: ``P4SwitchNetDevice::Attach()`` with a
  ``SwitchedEthernetChannel``, a full-duplex link between the switch and one
  device, usually a ``SwitchedEthernetHostDevice``.  ``SwitchedEthernetHelper``
  creates the channels and the host devices.
* *Bridge ports*: an ordinary |ns3| device of the switch's node, such as a CSMA
  device or the P4 point-to-point device (``CustomP2PNetDevice``, created by
  ``P4PointToPointHelper``), added with ``P4SwitchNetDevice::AddBridgePort()`` or
  ``P4Helper::Install(node, devices)``.  Switches are connected to each other
  this way, and the topology reader builds its networks with them.

**Packet path and timing.**

1. A frame received on a port enters the input buffer of the pipeline
   (``InputBufferSizeLow`` packets; on v1model, resubmitted and recirculated
   packets use a second buffer, ``InputBufferSizeHigh``, which is served first).
   A full input buffer drops the frame (trace ``MacRxDrop``).
2. The pipeline takes the packets at ``SwitchRate`` packets per second (0, the
   default, means no limit) and delays each of them by ``PipelineDelay`` (0 by
   default).
3. The packets then wait in output queues of ``QueueBufferSize`` packets: one
   per port and priority (v1model, PSA) or one per port (PNA).  On v1model,
   ``EnableVoqFabric`` replaces the output queues with a traffic manager of
   virtual output queues and a fabric scheduler (``P4TrafficManager``).
4. A port takes its next packet when its device reports that the previous frame
   has been sent, so a congested port sends back to back at its line rate.  With
   ``TransferBufferSize`` (v1model and PSA; 0 by default), it also takes packets
   while its transfer buffer, the port queue after the egress, has room: they
   pass the egress pipeline then and wait there in order, and are not overtaken
   any more; v1model's ``deq_timedelta`` does not contain this wait.  A pending
   program swap waits for these frames too.  The links
   serialise every frame at their data rate, and every device stores a frame
   completely before it forwards it.

**Control plane.**  Besides the flow-table file, the tables of a switch can be
changed during the simulation with ``P4Controller`` (flow entries, action
profiles, counters, meters, registers, mirroring sessions), on every
architecture.  It calls the BMv2 runtime API of the switch through
``P4RuntimeApi``, which a simulation can also use directly.  The records of
``digest()`` (v1model and the pipeline core) reach the trace source ``Digest``
of the switch and the digest callback of ``P4Controller``, so that a controller
in the simulation can learn from them; the example ``p4-l2-learning`` does.  The runtime CLIs of
BMv2 connect to the Thrift port of a switch (attribute ``ThriftPort``; by
default the first free port from ``$P4SIM_THRIFT_PORT_BASE``, 9090).

The main classes are:

* **Model** -- ``P4SwitchNetDevice``; ``P4SwitchCore`` and the cores
  ``P4CoreV1model``, ``P4CorePsa``, ``P4PnaNic`` and ``P4CorePipeline``;
  ``SwitchedEthernetChannel`` and ``SwitchedEthernetHostDevice``;
  ``CustomP2PNetDevice``, ``P4P2PChannel`` and ``P4BridgeChannel``;
  ``LinkFraming``; ``CustomHeader``; ``P4Controller`` and ``P4RuntimeApi``;
  ``P4TopologyReader``.
* **Helpers** -- ``P4Helper``, ``SwitchedEthernetHelper``,
  ``P4PointToPointHelper``, ``P4TopologyReaderHelper``,
  ``BuildNetworkFromTopology()`` (``p4-net-builder.h``), ``BuildFlowtableHelper``.
* **Utilities** -- ``format-utils`` (paths of the P4 files, conversions),
  the input buffer and output queues (``p4-queue.h``), ``P4TrafficManager``,
  ``FattreeTopoHelper``.

``doc/switch.md`` describes the switched-Ethernet devices and their timing, and
``doc/traffic-manager.md`` the traffic manager.

Scope and Limitations
=====================

* P4sim runs P4 programs as BMv2 does.  Its timing model is that of the links
  and queues above; it does not model the stages of a hardware pipeline, and it
  does not forward cut-through.
* P4sim builds with ns-3.39 to ns-3.49 and is tested with ns-3.39 and ns-3.49,
  BMv2 1.15.8, on Ubuntu 24.04 and 26.04.  From ns-3.41 on, |ns3| builds as
  C++20 or C++23, and the spdlog that BMv2 bundles does not compile as C++20;
  P4sim then uses a copy of these headers with the fix
  (``patches/bmv2-spdlog-cxx20.patch``).
* The P4 program sees every frame, ARP included, and must forward it; the
  example programs do.
* PNA has no Thrift service of its own: its ``FlowTablePath`` runs in BMv2's
  generic ``bm_CLI``, which has the table commands but not the time commands of
  ``pna_nic_CLI``.
* PSA and PNA programs give no digest records, as BMv2's ``psa_switch`` and
  ``pna_nic`` give none.
* The pipeline core (``P4SwitchArch`` 3) has no output queue: a congested port
  can lose frames.  It has no packet replication engine either: multicast
  (``mcast_grp``), clones, resubmit and recirculation have no effect, and the
  frame goes to ``egress_spec`` only.
* The Thrift server of a switch runs in its own thread.  Use the runtime CLIs
  before and after the simulation, and ``P4Controller`` during it.  BMv2 cannot
  stop the server, so the Thrift port of a destroyed switch stays open; it
  answers every call with an error.

``doc/TODO.md`` in the module lists the open items.

References
==========

* Mingyu Ma and Giang T. Nguyen. **"P4sim: Programming Protocol-independent
  Packet Processors in ns-3."** In Proc. of the 2025 International Conference
  on ns-3 (ICNS3), 2025.
  `[ACM DL] <https://dl.acm.org/doi/10.1145/3747204.3747210>`__
  `[arXiv] <https://arxiv.org/abs/2503.17554>`__
* Jiasong Bai, Jun Bi, Peng Kuang, Chengze Fan, Yu Zhou, and Cheng
  Zhang. **"NS4: Enabling programmable data plane simulation."**
  In Proc. of the Symposium on SDN Research, pp. 1--7, 2018.
  `[ACM DL] <https://dl.acm.org/doi/abs/10.1145/3185467.3185470>`__
* Chengze Fan, Jun Bi, Yu Zhou, Cheng Zhang, and Haisu Yu.
  **"NS4: A P4-driven network simulator."**
  In Proc. of the SIGCOMM Posters and Demos, pp. 105--107, 2017.
  `[ACM DL] <https://dl.acm.org/doi/10.1145/3123878.3132002>`__

Usage
*****

Prerequisites
=============

The quickest way is ``install.sh`` in ``contrib/p4sim``: on Ubuntu 24.04 or
26.04, it installs the packages, p4c and BMv2 1.15.8, then builds and tests
|ns3| with P4sim::

  git clone --depth 1 -b ns-3.39 https://github.com/nsnam/ns-3-dev-git.git ns3.39
  git clone https://github.com/HapCommSys/p4sim.git ns3.39/contrib/p4sim
  ns3.39/contrib/p4sim/install.sh

Otherwise:

1. Install BMv2, p4c and their dependencies, for example with the install
   script of `p4lang/tutorials <https://github.com/p4lang/tutorials>`_
   (Ubuntu 24.04).
2. Run ``sudo ./set_pkg_config_env.sh`` inside ``contrib/p4sim/`` to
   register the ``bm`` pkg-config package.
3. No environment variable is needed: P4sim reads the P4 files from the
   p4sim folder of the build.

``doc/installation.md`` has the full guide, and ``doc/docker.md`` describes
the Docker image.

Building
========

After cloning P4sim into ``contrib/``, configure and build |ns3| as
usual::

  ./ns3 configure --enable-tests --enable-examples
  ./ns3 build

P4sim requires the external library ``libbmall`` (from BMv2) and
``libgmp``.  These are located automatically via ``pkg-config``.

Helpers
=======

A switch with two hosts on switched-Ethernet ports::

  P4Helper p4;
  p4.SetDeviceAttribute("JsonPath", StringValue(GetP4ExamplePath() + "/simple_v1model/simple_v1model.json"));
  p4.SetDeviceAttribute("FlowTablePath", StringValue(GetP4ExamplePath() + "/simple_v1model/flowtable_0.txt"));
  NetDeviceContainer swDevs = p4.Install(switchNode);
  Ptr<P4SwitchNetDevice> sw = DynamicCast<P4SwitchNetDevice>(swDevs.Get(0));

  SwitchedEthernetHelper eth;
  eth.SetChannelAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
  NetDeviceContainer hostDevs = eth.Install(sw, hosts);

``P4Helper``
  Installs a ``P4SwitchNetDevice`` on a node: without ports
  (``Install(node)``), or with the given devices of the node as bridge ports
  (``Install(node, devices)``).

``SwitchedEthernetHelper``
  Connects hosts to a switch: one ``SwitchedEthernetChannel`` and one
  ``SwitchedEthernetHostDevice`` per host.  Like ``CsmaHelper``, it enables flow
  control on the host devices, so the queue disc of a host holds its backlog.

``P4PointToPointHelper``
  Creates point-to-point links of ``CustomP2PNetDevice`` devices, for bridge
  ports and custom headers.

``P4TopologyReaderHelper`` and ``BuildNetworkFromTopology()``
  Read a topology file (``topo.txt``) and build its switches, hosts and links.

``BuildFlowtableHelper`` and ``FattreeTopoHelper``
  Build a k-ary fat tree and its flow tables.

Attributes
==========

Attributes of ``ns3::P4SwitchNetDevice``:

.. list-table::
   :header-rows: 1

   * - Attribute
     - Default
     - Description
   * - ``JsonPath``
     - empty
     - Path to the compiled P4 program (JSON)
   * - ``FlowTablePath``
     - empty
     - Path to the flow-table file, run with the runtime CLI at start-up
   * - ``P4SwitchArch``
     - 0
     - Architecture: 0 V1model, 1 PSA, 2 PNA, 3 Pipeline
   * - ``SwitchRate``
     - 0
     - Packets per second that the pipeline takes; 0 means no limit
   * - ``PipelineDelay``
     - 0 s
     - Latency of every packet in the pipeline
   * - ``InputBufferSizeLow``
     - 128
     - Input buffer for the packets received on the ports, in packets
   * - ``InputBufferSizeHigh``
     - 128
     - V1model: input buffer for resubmitted and recirculated packets
   * - ``QueueBufferSize``
     - 128
     - Each output queue, in packets: per port and priority (v1model, PSA), or per port (PNA)
   * - ``TransferBufferSize``
     - 0
     - Frames a port holds after the egress pipeline, besides the one it sends (v1model and PSA, not with ``EnableVoqFabric``)
   * - ``EnableVoqFabric``
     - false
     - V1model: use the VOQ + fabric traffic manager instead of the output queues
   * - ``BmLogLevel``
     - off
     - Level of the BMv2 pipeline log in ``/tmp/bmv2-<thrift port>-pipeline.log``; ``off`` writes none, ``trace`` logs every packet and is slower
   * - ``ThriftPort``
     - 0
     - Thrift port of the runtime CLI; 0 picks the first free port
   * - ``EnableSwap``
     - false
     - Swapping the P4 program at run time; the swap waits until the switch holds no packet
   * - ``Mtu``
     - 1500
     - Maximum transmission unit
   * - ``EnableTracing``
     - false
     - Deprecated, no effect; use the trace sources (see Output)
   * - ``ChannelType``
     - 0
     - Deprecated, no effect; kept for older scripts

The data rate and delay of a switched-Ethernet port are attributes of
``ns3::SwitchedEthernetChannel`` (``DataRate``, default 10 Gbps; ``Delay``).
``Framing`` adds the Ethernet preamble, FCS, padding and interframe gap, on the
channel and on ``CustomP2PNetDevice`` (``doc/switch.md``).

Output
======

* **Pcap and ASCII traces** -- with the pcap and ASCII helpers of
  ``P4Helper``, ``SwitchedEthernetHelper``, ``CsmaHelper`` or
  ``P4PointToPointHelper``.
* **Trace sources** of ``P4SwitchNetDevice`` -- ``MacTx``, ``MacTxDrop``,
  ``MacRx``, ``MacRxDrop`` (full input buffer), ``Sniffer``,
  ``PromiscSniffer``, ``SwitchEvent`` and ``Digest`` (the records of
  ``digest()``).
* **Logging** -- each component has its own ``NS_LOG`` component
  (e.g. ``P4SwitchNetDevice``, ``P4CoreV1model``, ``P4Controller``), and BMv2
  writes its pipeline log as set by ``BmLogLevel``.

Portable Paths
==============

All example scripts resolve P4 artefact paths (JSON, flow tables,
topology files) through two helper functions declared in
``ns3/format-utils.h``::

  std::string GetP4SimDir();      // the p4sim folder of the build
  std::string GetP4ExamplePath(); // GetP4SimDir() + "/examples/p4src"

Typical usage in a simulation script::

  #include "ns3/format-utils.h"

  std::string p4SrcDir         = GetP4ExamplePath() + "/p4_basic";
  std::string p4JsonPath       = p4SrcDir + "/p4_basic.json";
  std::string flowTableDirPath = p4SrcDir + "/";
  std::string topoInput        = p4SrcDir + "/topo.txt";

Examples
========

Run any built-in example with::

  ./ns3 run p4-v1model-ipv4-forwarding

``doc/examples.md`` lists all examples.  A selection:

.. list-table::
   :header-rows: 1

   * - Example
     - Description
   * - ``p4-v1model-ipv4-forwarding``
     - Two hosts and a switch with IPv4 forwarding, on switched-Ethernet ports
   * - ``p4-v1model-ipv4-forwarding-bridge``
     - The same over point-to-point or CSMA bridge ports
   * - ``p4-psa-ipv4-forwarding``, ``p4-pna-ipv4-forwarding``
     - The same with PSA and PNA
   * - ``p4-basic-example``
     - Four hosts and four switches (p4lang tutorial ``basic``)
   * - ``p4-basic-controller``
     - Flow entries changed by ``P4Controller`` during the simulation
   * - ``p4-l2-learning``
     - L2 learning: ``P4Controller`` fills the tables from the digests of the switch
   * - ``p4-basic-tunnel``
     - A tunnel with a custom header
   * - ``p4-firewall``
     - A stateful TCP firewall (p4lang tutorial ``firewall``)
   * - ``p4-spine-leaf-topo``
     - Spine-leaf network with ECMP load balancing
   * - ``p4-topo-fattree``
     - Generated k-ary fat tree with its flow tables
   * - ``p4-priority-queues``
     - Strict-priority queues, with the classification in the P4 program
   * - ``p4-latency``
     - What makes up the one-way delay through a P4 switch
   * - ``p4-voq-fabric-throughput``
     - Throughput of the VOQ + fabric traffic manager

Each example reads its P4 program, flow tables and topology from a folder of
``examples/p4src/``.

Troubleshooting
===============

* If ``./ns3 configure`` reports that ``bm`` is not found, re-run
  ``sudo ./set_pkg_config_env.sh`` and verify with
  ``pkg-config --modversion bm``.
* If a simulation ends with "failed to load P4 JSON" or "cannot open the flow
  table", check that the file is in ``contrib/p4sim/examples/p4src/`` of the
  ns-3 tree that you built.
* P4sim prints each command of a flow table that the runtime CLI rejects, with
  the file and the line, and goes on.
* BMv2 writes no pipeline log by default. To see how a P4 program handles
  each packet, set ``BmLogLevel`` to ``trace`` (for example with
  ``--ns3::P4SwitchNetDevice::BmLogLevel=trace``); the log slows long
  simulations down.

Validation
**********

The module has 20 test suites with 147 test cases, from unit tests of
single classes to packet tests that send frames through a switch and check the
frames that leave it (``p4-packet``, with test files in the format of p4c's
STF).  Among them:

* ``p4-packet`` -- forwarding on every architecture; drops, priorities,
  resubmit, recirculation, clones, multicast and LAG.
* ``p4-egress``, ``p4-switch-rate``, ``p4-pipeline-delay``,
  ``p4-transfer-buffer``, ``link-framing`` -- the timing of ports, pipeline and
  links.
* ``p4-traffic-manager`` -- the VOQ + fabric traffic manager.
* ``p4-controller`` -- ``P4Controller`` and the runtime CLIs.
* ``p4-digest`` -- the records of ``digest()``, and L2 learning with
  ``P4Controller``.
* ``p4-config-swap`` -- swapping the P4 program at run time.

``test/Readme.md`` describes every suite and how to run them, for example::

  ./test.py -s p4-packet

``test/examples-to-run.py`` lets ``./test.py`` run every example as a smoke
test.  End-to-end results of the paper are in the companion artifact
repository: `p4sim-artifact-icns3
<https://github.com/HapCommSys/p4sim-artifact-icns3>`_.
