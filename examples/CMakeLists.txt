
# [ ================= V1model Arch ================= ]

# simple 2 hosts 1 switch topology [ipv4 forwarding]
build_lib_example(
  NAME p4-v1model-ipv4-forwarding
  SOURCE_FILES p4-v1model-ipv4-forwarding.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
)

# simple 3 hosts 3 router line topology [ipv4 L3 forwarding]
build_lib_example(
  NAME p4-l3-router
  SOURCE_FILES p4-l3-router.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
)

# 4 hosts 4 switches topology [ipv4 forwarding]
build_lib_example(
  NAME p4-basic-example
  SOURCE_FILES p4-basic-example.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
)

# 3 hosts 3 switches topology [tunnel]
build_lib_example(
  NAME p4-basic-tunnel
  SOURCE_FILES p4-basic-tunnel.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
)

# 4 hosts 4 switches topology [Firewall]
build_lib_example(
  NAME p4-firewall
  SOURCE_FILES p4-firewall.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
)

# 4 hosts 4 switches topology [Link Monitoring]
build_lib_example(
  NAME p4-link-monitoring
  SOURCE_FILES p4-link-monitoring.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
)

# 4 hosts 4 switches topology [Link Monitoring]
build_lib_example(
  NAME p4-spine-leaf-topo
  SOURCE_FILES p4-spine-leaf-topo.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
    ${libflow-monitor}
)

# fattree test
build_lib_example(
  NAME p4-topo-fattree
  SOURCE_FILES p4-topo-fattree.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
)

# [ ================= PSA Arch ================= ]

# simple 2 hosts 1 switch topology [ipv4 forwarding]
build_lib_example(
  NAME p4-psa-ipv4-forwarding
  SOURCE_FILES p4-psa-ipv4-forwarding.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
)

# [ ================= NO P4 ================= ]

# simple 2 hosts sending with custom header [p2p]
build_lib_example(
  NAME p4-p2p-custom-header-test
  SOURCE_FILES p4-p2p-custom-header-test.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
)

# fattree test
build_lib_example(
  NAME topo-fattree
  SOURCE_FILES topo-fattree.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libnix-vector-routing}
    ${libcsma}
)

# [ ================= Test ================= ]

# custom header test
build_lib_example(
  NAME p4-custom-header-test
  SOURCE_FILES p4-custom-header-test.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
)

# network test
build_lib_example(
  NAME net-test
  SOURCE_FILES net-test.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
)

# network test
build_lib_example(
  NAME routing-test
  SOURCE_FILES routing-test.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
)

# network test
build_lib_example(
  NAME p4-traffic-gene
  SOURCE_FILES p4-traffic-gene.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libpoint-to-point}
)

# network test
build_lib_example(
  NAME p4-queue-test
  SOURCE_FILES p4-queue-test.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
)

# p4-controller test
build_lib_example(
  NAME p4-basic-controller
  SOURCE_FILES p4-basic-controller.cc
    LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
)

#p4 - controller test
build_lib_example(
    NAME p4-controller-action-profile
    SOURCE_FILES p4-controller-action-profile.cc 
    LIBRARIES_TO_LINK 
    ${libp4sim} 
    ${libinternet} 
    ${libapplications} 
    ${libnetwork} 
    ${libcsma}
)

#p4-source-routing 
build_lib_example( Add commentMore actions
  NAME p4-source-routing
  SOURCE_FILES p4-source-routing.cc
  LIBRARIES_TO_LINK
    ${libp4sim}
    ${libinternet}
    ${libapplications}
    ${libnetwork}
    ${libcsma}
)