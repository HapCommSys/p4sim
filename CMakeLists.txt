set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

list(APPEND third_party_libs -L/usr/local/lib)

# Core module construction
build_lib(
    LIBNAME p4sim
    SOURCE_FILES # equivalent to module.source        utils/format-utils.cc
        utils/format-utils.cc
        utils/switch-api.cc
        utils/p4-queue.cc
        utils/fattree-topo-helper.cc
        model/switched-ethernet-channel.cc
        model/switched-ethernet-host-device.cc
        model/p4-switch-core.cc
        model/p4-core-v1model.cc
        model/p4-core-psa.cc
        model/p4-nic-pna.cc
        model/p4-switch-net-device.cc
        helper/p4-helper.cc
        helper/switched-ethernet-helper.cc
        helper/build-flowtable-helper.cc
    HEADER_FILES # equivalent to headers.source
        utils/p4-queue.h
        utils/format-utils.h
        utils/switch-api.h
        utils/register-access-v1model.h
        utils/primitives-v1model.h
        utils/primitives-pna.h
        utils/fattree-topo-helper.h
        model/switched-ethernet-channel.h
        model/switched-ethernet-host-device.h
        model/p4-switch-core.h
        model/p4-core-v1model.h
        model/p4-core-psa.h
        model/p4-nic-pna.h
        model/p4-switch-net-device.h
        helper/p4-helper.h
        helper/switched-ethernet-helper.h
        helper/build-flowtable-helper.h
    LIBRARIES_TO_LINK 
        ${libcore} 
        ${libnetwork}  
        ${libtraffic-control}
        ${libapplications}
        ${third_party_libs}
    TEST_SOURCES # equivalent to module_test.source
        # test/p4-controller-test-suite.cc
        #  test/p4sim-test-suite.cc
        #  test/format-utils-test-suite.cc
        #  test/p4-topology-reader-test-suite.cc
        #  test/p4-p2p-channel-test-suite.cc
        ${examples_as_tests_sources}
)