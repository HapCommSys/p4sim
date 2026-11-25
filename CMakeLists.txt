# P4sim builds with ns-3.39 to ns-3.49. ns-3 sets the C++ standard (C++17 up to
# ns-3.40, C++20 from ns-3.41, C++23 from ns-3.46), and P4SIM_NS3_MINOR (39 for
# ns-3.39, 99 for a development tree) selects the ns-3 API in
# utils/p4sim-ns3-compat.h.
if(NS3_VER MATCHES "^3\\.([0-9]+)")
  set(P4SIM_NS3_MINOR ${CMAKE_MATCH_1})
else()
  set(P4SIM_NS3_MINOR 99)
endif()
add_compile_definitions(P4SIM_NS3_MINOR=${P4SIM_NS3_MINOR})
message(STATUS "P4sim: ns-${NS3_VER}, C++${CMAKE_CXX_STANDARD}")

# The core headers of ns-3.39 and ns-3.40 name constructors Singleton<T>(...),
# which GCC 14 and newer report in every file that includes them
# (-Wtemplate-id-cdtor). ns-3.41 fixed the headers, so only this one warning is
# off, and only for these two releases.
if(P4SIM_NS3_MINOR LESS 41)
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag(-Wtemplate-id-cdtor P4SIM_HAS_WTEMPLATE_ID_CDTOR)
  if(P4SIM_HAS_WTEMPLATE_ID_CDTOR)
    add_compile_options(-Wno-template-id-cdtor)
  endif()
endif()

# Check if stdint.h is supported
check_include_file_cxx(stdint.h HAVE_STDINT_H)
if(HAVE_STDINT_H)
    add_definitions(-DHAVE_STDINT_H)
endif()

# Include CMake script to use pkg-config
include(FindPkgConfig)

# List of third-party libraries to search
set(third_party_libraries
    "bm"
    "gmp"
    "jsoncpp"
    "libpcap"
    "nanomsg"
    "libxxhash"
    "thrift"
)

# Initialize variables to collect sources and libraries
set(third_party_sources)
set(third_party_libs)

# Iterate over each library to configure it
if(PKG_CONFIG_FOUND)
  foreach(lib ${third_party_libraries})
    pkg_check_modules(${lib} ${lib})

    # Check if the library is found
    if(${lib}_FOUND)
      # Include third-party include directories
      include_directories(${${lib}_INCLUDE_DIRS})

      # Use exported CFLAGS required by the third-party library
      add_compile_options(${${lib}_CFLAGS})

      # Add the library to the third-party libs
      list(APPEND third_party_libs ${${lib}_LIBRARIES})
    else()
      message(WARNING "Library ${lib} not found. Make sure it is installed and available.")
    endif()
  endforeach()
endif()

# BMv2's bundled spdlog names two constructors registry_t<Mutex>(...) in
# bm/spdlog/details/registry.h, which C++20 forbids and g++ rejects. From C++20
# on, P4sim compiles with a copy of BMv2's spdlog headers in which these two
# lines are fixed (patches/bmv2-spdlog-cxx20.patch); the installed BMv2 is not
# changed. BMv2 includes them as <bm/spdlog/...>, so the copy comes first.
set(p4sim_bm_overlay)
if(CMAKE_CXX_STANDARD GREATER_EQUAL 20)
  if(bm_INCLUDEDIR)
    set(bm_spdlog_dir "${bm_INCLUDEDIR}/spdlog")
  else()
    set(bm_spdlog_dir "/usr/local/include/bm/spdlog")
  endif()
  set(bm_registry "${bm_spdlog_dir}/details/registry.h")
  if(EXISTS "${bm_registry}")
    file(READ "${bm_registry}" registry)
    if(registry MATCHES "registry_t<Mutex>\\(")
      # Files are only written when they change, so that configuring again does
      # not make P4sim rebuild
      set(p4sim_bm_overlay "${CMAKE_CURRENT_BINARY_DIR}/bm-spdlog-fix")
      file(COPY "${bm_spdlog_dir}" DESTINATION "${p4sim_bm_overlay}/bm"
           PATTERN "registry.h" EXCLUDE)
      string(REPLACE "registry_t<Mutex>(){}" "registry_t(){}" registry "${registry}")
      string(REPLACE "registry_t<Mutex>(const registry_t<Mutex>&)"
                     "registry_t(const registry_t<Mutex>&)" registry "${registry}")
      set(fixed_registry "${p4sim_bm_overlay}/bm/spdlog/details/registry.h")
      set(old_registry "")
      if(EXISTS "${fixed_registry}")
        file(READ "${fixed_registry}" old_registry)
      endif()
      if(NOT old_registry STREQUAL registry)
        file(WRITE "${fixed_registry}" "${registry}")
      endif()
      include_directories(BEFORE "${p4sim_bm_overlay}")
      message(STATUS "P4sim: using BMv2's spdlog headers with the C++20 fix (${p4sim_bm_overlay})")
    endif()
  endif()
endif()

# Prefer pkg-config, but also add fallback libraries from /usr/local/lib
# to avoid unresolved BMv2/Thrift symbols when module names differ.
find_library(RUNTIMESTUBS_LIB runtimestubs PATHS /usr/local/lib)
if(RUNTIMESTUBS_LIB)
  list(APPEND third_party_libs ${RUNTIMESTUBS_LIB})
endif()

# The "simple_switch" Thrift service of simple_switch_CLI (p4-core-v1model-thrift.cc)
find_library(SIMPLESWITCH_THRIFT_LIB simpleswitch_thrift PATHS /usr/local/lib)
if(SIMPLESWITCH_THRIFT_LIB)
  list(APPEND third_party_libs ${SIMPLESWITCH_THRIFT_LIB})
endif()

# The "psa_switch" Thrift service of psa_switch_CLI (p4-core-psa-thrift.cc)
find_library(PSASWITCH_THRIFT_LIB psaswitch_thrift PATHS /usr/local/lib)
if(PSASWITCH_THRIFT_LIB)
  list(APPEND third_party_libs ${PSASWITCH_THRIFT_LIB})
endif()

find_library(THRIFT_LIB thrift PATHS /usr/local/lib)
if(THRIFT_LIB)
  list(APPEND third_party_libs ${THRIFT_LIB})
endif()

list(APPEND third_party_libs -L/usr/local/lib)

# Core module construction
build_lib(
    LIBNAME p4sim
    SOURCE_FILES # equivalent to module.source        utils/format-utils.cc
        utils/format-utils.cc
        utils/switch-api.cc
        utils/p4-queue.cc
        utils/p4-traffic-manager.cc
        utils/fattree-topo-helper.cc
        model/switched-ethernet-channel.cc
        model/link-framing.cc
        model/eth-net-device.cc
        model/p4-switch-core.cc
        model/p4-core-v1model.cc
        model/p4-core-v1model-thrift.cc
        model/p4-core-psa.cc
        model/p4-core-psa-thrift.cc
        model/p4-nic-pna.cc
        model/p4-switch-net-device.cc
        helper/p4-helper.cc
        helper/switched-ethernet-helper.cc
        helper/build-flowtable-helper.cc
        model/p4-bridge-channel.cc
        model/p4-p2p-channel.cc
        model/custom-header.cc
        model/p4-topology-reader.cc
        model/p4-core-pipeline.cc
        model/custom-p2p-net-device.cc
        model/p4-controller.cc
        helper/p4-topology-reader-helper.cc
        helper/p4-p2p-helper.cc
    HEADER_FILES # equivalent to headers.source
        utils/p4-queue.h
        utils/p4-traffic-manager.h
        utils/format-utils.h
        utils/switch-api.h
        utils/register-access-v1model.h
        utils/primitives-v1model.h
        utils/primitives-pna.h
        utils/fattree-topo-helper.h
        utils/p4sim-ns3-compat.h
        model/switched-ethernet-channel.h
        model/link-framing.h
        model/eth-net-device.h
        model/p4-switch-core.h
        model/p4-core-v1model.h
        model/p4-core-psa.h
        model/p4-nic-pna.h
        model/p4-switch-net-device.h
        helper/p4-helper.h
        helper/switched-ethernet-helper.h
        helper/build-flowtable-helper.h
        model/p4-bridge-channel.h
        model/p4-p2p-channel.h
        model/custom-header.h
        model/p4-topology-reader.h
        model/p4-core-pipeline.h
        model/custom-p2p-net-device.h
        model/p4-controller.h
        helper/p4-topology-reader-helper.h
        helper/p4-p2p-helper.h
        helper/p4-net-builder.h
    LIBRARIES_TO_LINK 
        ${libcore} 
        ${libnetwork}  
        ${libtraffic-control}
        ${libapplications}
        ${libpoint-to-point}
        ${libcsma}
        ${libbridge}
        ${third_party_libs}
    TEST_SOURCES # equivalent to module_test.source
        test/p4-traffic-manager-test-suite.cc
        test/channel-state-test-suite.cc
        test/p4-egress-test-suite.cc
        test/p4-bridge-port-test-suite.cc
        test/p4-pna-test-suite.cc
        test/p4-switch-rate-test-suite.cc
        test/p4-pipeline-delay-test-suite.cc
        test/p4-config-swap-test-suite.cc
        test/switched-ethernet-host-test-suite.cc
        test/switched-ethernet-tc-test-suite.cc
        test/link-framing-test-suite.cc
        test/p4-controller-test-suite.cc
        test/p4sim-test-suite.cc
        test/format-utils-test-suite.cc
        test/p4-topology-reader-test-suite.cc
        test/p4-p2p-channel-test-suite.cc
        test/p4-queue-test-suite.cc
        test/p4-packet-test-suite.cc
        ${examples_as_tests_sources}
)

# GetP4SimDir() (utils/format-utils.cc) returns the p4sim folder of this build,
# so that every ns-3 tree reads its own P4 files
set_source_files_properties(
    utils/format-utils.cc
    PROPERTIES COMPILE_DEFINITIONS "P4SIM_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\""
)

# Programs outside this folder that use P4sim (scratch/, other modules) need the
# same ns-3 version define and spdlog headers
if(TARGET ${libp4sim})
  target_compile_definitions(${libp4sim} INTERFACE P4SIM_NS3_MINOR=${P4SIM_NS3_MINOR})
  if(p4sim_bm_overlay)
    target_include_directories(${libp4sim} BEFORE INTERFACE "$<BUILD_INTERFACE:${p4sim_bm_overlay}>")
  endif()
endif()
