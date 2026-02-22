# ──────────────────────────────────────────────────────────────────────
# P4Sim examples — CMake build definitions
# ──────────────────────────────────────────────────────────────────────
# Common library sets used by most examples.  Collecting them in
# variables keeps the per-target blocks short and easy to maintain.
# ──────────────────────────────────────────────────────────────────────

# Base libraries required by virtually every P4 example
set(P4SIM_BASE_LIBS
  ${libp4sim}
  ${libinternet}
  ${libapplications}
  ${libnetwork}
)

# Base + CSMA (the most common combination)
set(P4SIM_CSMA_LIBS ${P4SIM_BASE_LIBS} ${libcsma})

# ========================= V1model Architecture =======================

# 2 hosts, 1 switch — IPv4 forwarding
build_lib_example(
  NAME p4-v1model-ipv4-forwarding
  SOURCE_FILES p4-v1model-ipv4-forwarding.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS}
)

# 3 hosts, 3 routers (line topology) — L3 forwarding
build_lib_example(
  NAME p4-l3-router
  SOURCE_FILES p4-l3-router.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS}
)

# 4 hosts, 4 switches — IPv4 forwarding
build_lib_example(
  NAME p4-basic-example
  SOURCE_FILES p4-basic-example.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS}
)

# 3 hosts, 3 switches — tunnel with custom header
build_lib_example(
  NAME p4-basic-tunnel
  SOURCE_FILES p4-basic-tunnel.cc
  LIBRARIES_TO_LINK ${P4SIM_BASE_LIBS}
)

# 4 hosts, 4 switches — stateful firewall
build_lib_example(
  NAME p4-firewall
  SOURCE_FILES p4-firewall.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS}
)

# 4 hosts, 4 switches — in-band link monitoring
build_lib_example(
  NAME p4-link-monitoring
  SOURCE_FILES p4-link-monitoring.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS}
)

# Spine-leaf topology — ECMP load balancing
build_lib_example(
  NAME p4-spine-leaf-topo
  SOURCE_FILES p4-spine-leaf-topo.cc
  LIBRARIES_TO_LINK ${P4SIM_BASE_LIBS}
)

# Fat-tree topology — auto-generated with P4 switches
build_lib_example(
  NAME p4-topo-fattree
  SOURCE_FILES p4-topo-fattree.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS}
)

# Source routing with custom headers
build_lib_example(
  NAME p4-source-routing
  SOURCE_FILES p4-source-routing.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS}
)

# Runtime controller — flow-table updates
build_lib_example(
  NAME p4-basic-controller
  SOURCE_FILES p4-basic-controller.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS}
)

# Controller with action profiles
build_lib_example(
  NAME p4-controller-action-profile
  SOURCE_FILES p4-controller-action-profile.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS}
)

# QoS-aware queuing test
build_lib_example(
  NAME p4-queue-test
  SOURCE_FILES p4-queue-test.cc
  LIBRARIES_TO_LINK ${P4SIM_BASE_LIBS}
)

# IPv4 forwarding with NetAnim visualisation
build_lib_example(
  NAME p4-ipv4-animation
  SOURCE_FILES p4-ipv4-animation.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS} ${libnetanim} ${libmobility}
)

# ========================= PSA Architecture ===========================

# 2 hosts, 1 switch — IPv4 forwarding (PSA)
build_lib_example(
  NAME p4-psa-ipv4-forwarding
  SOURCE_FILES p4-psa-ipv4-forwarding.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS}
)

# ========================= PNA Architecture ===========================

# 2 hosts, 1 internhosts (node with PNA arch) — IPv4 forwarding (PNA)
build_lib_example(
  NAME p4-pna-ipv4-forwarding
  SOURCE_FILES p4-pna-ipv4-forwarding.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS}
)

# ========================= Non-P4 Helpers =============================

# P2P channel with custom header (no P4 program)
build_lib_example(
  NAME p4-p2p-custom-header-test
  SOURCE_FILES p4-p2p-custom-header-test.cc
  LIBRARIES_TO_LINK ${P4SIM_BASE_LIBS}
)

# ns-3 simulation of a k-ary Fat-Tree data-center network topology (no P4 program)
build_lib_example(
  NAME topo-fattree
  SOURCE_FILES topo-fattree.cc
  LIBRARIES_TO_LINK ${P4SIM_CSMA_LIBS} ${libnix-vector-routing}
)

# ========================= Unit / Dev Tests ===========================

# Custom header parsing test
build_lib_example(
  NAME p4-custom-header-test
  SOURCE_FILES p4-custom-header-test.cc
  LIBRARIES_TO_LINK ${libp4sim}
)