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

P4sim introduces a ``P4SwitchNetDevice`` that replaces the standard |ns3|
bridge device.  Each switch instance loads a compiled P4 JSON program and a
flow-table configuration at start-up.  Internally the packet is handed to
the BMv2 back-end (linked as a shared library) which executes the P4
pipeline and returns the forwarding decision to |ns3|.

The main components are:

* **Model** -- ``P4SwitchNetDevice``, ``P4SwitchCore``,
  architecture-specific cores (``P4CoreV1model``, ``P4CorePsa``,
  ``P4NicPna``), ``P4Controller``, ``P4TopologyReader``, and channel
  classes (``P4BridgeChannel``, ``P4P2pChannel``).
* **Helpers** -- ``P4Helper``, ``P4PointToPointHelper``,
  ``P4TopologyReaderHelper``, ``BuildFlowtableHelper``,
  ``FattreeTopoHelper``.
* **Utilities** -- ``format-utils`` (path helpers, hex/byte converters),
  ``switch-api`` (BMv2 runtime API wrappers), ``P4Queue``.

Supported P4 architectures:

========== ==========================================
Value      Architecture
========== ==========================================
0          V1model (``simple_switch``)
1          PSA (``psa_switch``)
2          PNA (``pna_nic``)
========== ==========================================

Scope and Limitations
=====================

* P4sim targets **functional simulation** -- it faithfully reproduces P4
  forwarding logic but does not model ASIC-level timing.
* Only the **software switch back-end** (BMv2) is used; hardware targets
  are out of scope.
* BMv2 is built with **C++17**, therefore |ns3| must also be compiled
  with C++17 (ns-3.39 or earlier).
* When using a CSMA channel the P4 program must handle ARP explicitly.
* Tracing support is basic (throughput-level); per-table hit/miss
  counters are not yet exported.

References
==========

* Mingyu Ma, Eugen Dedu, and Lin Han. **"P4sim: Programming
  Protocol-independent Packet Processors in ns-3."** arXiv preprint
  arXiv:2503.17554, 2025.
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

1. Install BMv2 and its dependencies via the
   `p4lang/tutorials <https://github.com/p4lang/tutorials>`_ install
   script (Ubuntu 24.04 recommended).
2. Run ``sudo ./set_pkg_config_env.sh`` inside ``contrib/p4sim/`` to
   register the ``bm`` pkg-config package.
3. Set the environment variable so that examples can find P4 artefacts::

     export P4SIM_DIR="$HOME/workdir/ns3.39/contrib/p4sim"

See ``doc/vm-env.md`` for the full step-by-step guide.

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

``P4Helper``
  Installs a ``P4SwitchNetDevice`` on a node, attaching one or more
  underlying ``NetDevice`` objects as switch ports.

``P4PointToPointHelper``
  Creates point-to-point links that use the P4-aware channel and
  ``CustomP2pNetDevice``.

``P4TopologyReaderHelper``
  Reads a simple text-based topology file (``topo.txt``) that lists
  switch--switch and switch--host links together with data-rate and delay.

``BuildFlowtableHelper``
  Programmatically generates flow-table entries for fat-tree topologies.

Attributes
==========

Key attributes on ``ns3::P4SwitchNetDevice``:

==================== ========================================================
Attribute            Description
==================== ========================================================
``JsonPath``         Path to the compiled P4 JSON file
``FlowTablePath``   Path to the flow-table configuration file
``P4SwitchArch``     Architecture selector (0 = V1model, 1 = PSA, 2 = PNA)
``ChannelType``      Channel type (0 = CSMA, 1 = point-to-point)
``SwitchRate``       Processing rate in packets per second
``QueueBufferSize``  Total queue buffer size (packets)
``EnableTracing``    Enable basic throughput tracing
==================== ========================================================

Output
======

* **Pcap traces** -- enabled via the standard |ns3| CSMA or P2P pcap
  helpers.
* **Logging** -- each component has its own ``NS_LOG`` component
  (e.g. ``P4SwitchCore``, ``P4CoreV1model``, ``P4Controller``).
* **Throughput** -- basic throughput measurement is available when
  ``EnableTracing`` is set to ``true``.

Portable Paths
==============

All example scripts resolve P4 artefact paths (JSON, flow tables,
topology files) through two helper functions declared in
``ns3/format-utils.h``::

  std::string GetP4SimDir();      // $P4SIM_DIR or fallback
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

Selected examples:

====================================  ==========================================
Script                                Description
====================================  ==========================================
``p4-v1model-ipv4-forwarding``        2-host 1-switch IPv4 forwarding (V1model)
``p4-psa-ipv4-forwarding``            Same topology, PSA architecture
``p4-basic-example``                  4-host 4-switch mesh (V1model)
``p4-basic-tunnel``                   3-host tunnel with custom header
``p4-firewall``                       Stateful firewall
``p4-l3-router``                      3-router line topology, L3 forwarding
``p4-link-monitoring``                In-band link utilisation probes
``p4-spine-leaf-topo``                Spine-leaf with ECMP load balancing
``p4-topo-fattree``                   Auto-generated fat-tree topology
``p4-queue-test``                     QoS-aware queuing
``p4-source-routing``                 Source routing with custom headers
``p4-basic-controller``               Runtime controller flow-table updates
``p4-controller-action-profile``      Controller with action profiles
====================================  ==========================================

Each example has a matching ``p4src/<name>/`` directory containing the P4
source, compiled JSON, flow tables, and ``topo.txt``.

Troubleshooting
===============

* If ``./ns3 configure`` reports that ``bm`` is not found, re-run
  ``sudo ./set_pkg_config_env.sh`` and verify with
  ``pkg-config --modversion bm``.
* If a simulation fails with "file not found" for JSON or flow-table
  paths, make sure ``P4SIM_DIR`` is exported in your environment.
* BMv2's bundled spdlog is intentionally excluded; |ns3| uses its own
  logging framework.

Validation
**********

The test suite (``test/``) includes:

* ``p4-controller-test-suite`` -- verifies runtime flow-table operations.
* ``format-utils-test-suite`` -- unit tests for hex/byte conversion
  utilities.
* ``p4-topology-reader-test-suite`` -- topology file parsing.
* ``p4-p2p-channel-test-suite`` -- point-to-point channel behaviour.

Run all P4sim tests with::

  ./test.py -s p4sim

End-to-end validation results are available in the companion artifact
repository: `p4sim-artifact-icns3
<https://github.com/HapCommSys/p4sim-artifact-icns3>`_.
