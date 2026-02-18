# P4Sim: NS-3-Based P4 Simulation Environment

## Table of Contents

- [Local Deployment (ns-3.39)](#local-deployment-ns339) *(recommended)*
- [Virtual Machine Setup](#virtual-machine-as-virtual-env)
  - [ns-3 Version 3.x – 3.35 (waf)](#setup-ns335)
  - [ns-3 Version 3.36 – 3.39 (CMake)](#setup-ns339) *(recommended)*
- [Appendix](#appendix)
- [References](#references)

---

## Installation & Usage Guide

It is recommended to use a **virtual machine** with Vagrant to simplify the installation and ensure compatibility.

---

## <a name="local-deployment-ns339"></a> Local Deployment (ns-3.39)

This guide walks you through setting up a local environment to run P4Sim integrated with `ns-3.39` on Ubuntu 24.04. The full setup includes installing the behavioral model (`bmv2`), setting up SSH for remote access, and building the ns-3 project with P4Sim support. This has been tested with **Ubuntu 24.04 LTS Desktop**.

> **Note:** The bmv2 and P4 software installation step will take **1~2 hours** and consume up to **15 GB** of disk space.

> **Why ns-3.39?** Starting from ns-3.40, ns-3 requires C++20. However, the BMv2 library is currently built with C++17. We will upgrade to a newer ns-3 version once a C++20-compatible BMv2 build becomes available.

---

### 1. Initialize the Working Directory

Create a workspace and install basic development tools.

```bash
sudo apt update
mkdir ~/workdir
cd ~/workdir
sudo apt install git vim cmake
```

---

### 2. Install P4 Behavioral Model (bmv2) and Dependencies

This installs all necessary libraries and tools for P4 development via the official [p4lang/tutorials](https://github.com/p4lang/tutorials) repository.

```bash
cd ~
git clone https://github.com/p4lang/tutorials
mkdir ~/src
cd ~/src
../tutorials/vm-ubuntu-24.04/install.sh |& tee log.txt
```

After installation, verify that `simple_switch` is available:

```bash
simple_switch
```

---

### 3. Clone and Build ns-3.39 with P4Sim

#### Step 3.1: Clone ns-3.39

```bash
cd ~/workdir
git clone https://github.com/nsnam/ns-3-dev-git.git ns3.39
cd ns3.39
git checkout ns-3.39
```

#### Step 3.2: Add P4Sim Module

```bash
cd contrib
git clone https://github.com/HapCommSys/p4sim.git
cd p4sim
sudo ./set_pkg_config_env.sh
```

#### Step 3.3: Configure and Build

```bash
cd ../..
./ns3 configure --enable-tests --enable-examples
./ns3 build
```

#### Step 3.4: Set the `P4SIM_DIR` Environment Variable

All P4Sim example scripts resolve P4 artifact paths (JSON, flow tables, topology files) via the `P4SIM_DIR` environment variable. Add it to your `~/.bashrc` so it is available in every session:

```bash
# Add to ~/.bashrc — adjust the path to match your ns-3 workspace
echo 'export P4SIM_DIR="$HOME/workdir/ns3.39/contrib/p4sim"' >> ~/.bashrc
source ~/.bashrc
```

> **Tip:** If `P4SIM_DIR` is not set, the helper functions fall back to a path derived from the executable location, but setting the variable explicitly is recommended for reliability.

---

### 4. Run an Example

You can run a built-in example using:

```bash
./ns3 run p4-v1model-ipv4-forwarding
```

No manual path editing is required — all examples use portable path helpers.

---

### 5. How P4 Artifact Paths Work

All example scripts use two helper functions declared in `ns3/format-utils.h`:

| Function | Returns |
|---|---|
| `GetP4SimDir()` | Value of `$P4SIM_DIR` (or a fallback derived from the executable path) |
| `GetP4ExamplePath()` | `GetP4SimDir() + "/examples/p4src"` |

#### Recommended usage pattern in your own scripts

```cpp
#include "ns3/format-utils.h"

// Build paths relative to the P4Sim examples/p4src directory
std::string p4SrcDir         = GetP4ExamplePath() + "/p4_basic";
std::string p4JsonPath       = p4SrcDir + "/p4_basic.json";
std::string flowTableDirPath = p4SrcDir + "/";
std::string topoInput        = p4SrcDir + "/topo.txt";
```

This pattern keeps simulation scripts **portable** across different machines and user accounts — no hardcoded absolute paths are needed.

---

### 6. Done

You now have a working ns-3.39 simulator with P4 integration ready for your experiments.

---

### Feedback or Issues

If you encounter problems during installation, please check the [Appendix](#appendix) for expected outputs and verification steps. For other issues or suggestions, feel free to open an issue or contact the maintainer.

**Contact:** mingyu.ma@tu-dresden.de

---

## <a name="virtual-machine-as-virtual-env"></a> Virtual Machine Setup

`p4sim` integrates an NS-3-based P4 simulation environment with virtual machine configuration files sourced via sparse checkout from the [P4Lang Tutorials repository](https://github.com/p4lang/tutorials/tree/master).

The `vm` directory contains Vagrant configurations and bootstrap scripts for Ubuntu-based virtual machines (Ubuntu 24.04 recommended). These pre-configured environments streamline the setup process, ensuring compatibility and reducing installation issues.

Tested with:
- P4Lang Tutorials Commit: `7273da1c2ac2fd05cea0a9dd0504184b8c955eae`
- Date: `2025-01-25`

Prerequisites:
- Ensure you have `Vagrant` and `VirtualBox` installed before running `vagrant up dev`.
- The setup script (`set_pkg_config_env.sh`) configures the required environment variables for P4Sim.
- `Ubuntu 24.04` is the recommended OS for the virtual machine.

---

### <a name="setup-ns335"></a> Setup Instructions for ns-3 version 3.x – 3.35 (Build with `waf`)

This has been tested with ns-3 repo tag `ns-3.35`.

#### 1. Build the Virtual Machine

```bash
# with vm-ubuntu-24.04/Vagrantfile or vm-ubuntu-20.04/Vagrantfile
vagrant up dev

sudo apt update
sudo apt install git vim

cd ~
git clone https://github.com/p4lang/tutorials
mkdir ~/src
cd ~/src
../tutorials/vm-ubuntu-24.04/install.sh |& tee log.txt
```

See also: [Introduction — build venv of vm-ubuntu-24.04](https://github.com/p4lang/tutorials/tree/7273da1c2ac2fd05cea0a9dd0504184b8c955eae/vm-ubuntu-24.04#introduction). You may need to install the tools manually: [install instructions](https://github.com/p4lang/tutorials/tree/7273da1c2ac2fd05cea0a9dd0504184b8c955eae/vm-ubuntu-24.04#installing-open-source-p4-development-tools-on-the-vm).

This will create a virtual machine named "P4 Tutorial Development". Verify the installation by running `simple_switch` to confirm that `bmv2` is correctly installed.

#### 2. Clone the NS-3 Repository

```bash
cd
mkdir workdir
cd workdir
git clone https://github.com/nsnam/ns-3-dev-git.git ns3.35
cd ns3.35
git checkout ns-3.35
```

#### 3. Clone & Integrate `p4sim` into NS-3

```bash
cd /home/p4/workdir/ns3.35/contrib/
git clone https://github.com/HapCommSys/p4sim.git
```

#### 4. Set Up the Environment (external libs)

```bash
cd /home/p4/workdir/ns3.35/contrib/p4sim/
sudo ./set_pkg_config_env.sh
```

#### 5. Apply the ns-3 Patch

```bash
cd ../../  # back to ns-3 root directory
git apply ./contrib/p4sim/doc/changes.patch
```

#### 6. Configure & Build NS-3

```bash
./ns3 configure --enable-examples --enable-tests
./ns3 build
```

#### 7. Set the `P4SIM_DIR` Environment Variable & Run

```bash
# Add to ~/.bashrc — adjust the path to match your workspace
echo 'export P4SIM_DIR="$HOME/workdir/ns3.35/contrib/p4sim"' >> ~/.bashrc
source ~/.bashrc

# Run an example
./ns3 run "exampleA"
```

> P4 artifact paths are resolved automatically via `GetP4SimDir()` / `GetP4ExamplePath()`. See [Section 5](#5-how-p4-artifact-paths-work) in the Local Deployment guide for details.

---

### <a name="setup-ns339"></a> Setup Instructions for ns-3 version 3.36 – 3.39 (Build with `CMake`) *(recommended)*

This has been tested with ns-3 repo tag `ns-3.39`. The virtual machine builds BMv2 and its libraries with **C++17**, so ns-3 must also be built with **C++17**.

- Include path: `/usr/local/include/bm`
- Library: `/usr/local/lib/libbmall.so`

#### 1. Build the Virtual Machine

```bash
# with vm-ubuntu-24.04/Vagrantfile or vm-ubuntu-20.04/Vagrantfile
vagrant up dev

sudo apt update
sudo apt install git vim

cd ~
git clone https://github.com/p4lang/tutorials
mkdir ~/src
cd ~/src
../tutorials/vm-ubuntu-24.04/install.sh |& tee log.txt
```

See also: [Introduction — build venv of vm-ubuntu-24.04](https://github.com/p4lang/tutorials/tree/7273da1c2ac2fd05cea0a9dd0504184b8c955eae/vm-ubuntu-24.04#introduction). You may need to install the tools manually: [install instructions](https://github.com/p4lang/tutorials/tree/7273da1c2ac2fd05cea0a9dd0504184b8c955eae/vm-ubuntu-24.04#installing-open-source-p4-development-tools-on-the-vm).

This will create a virtual machine named "P4 Tutorial Development". Verify the installation by running `simple_switch` to confirm that `bmv2` is correctly installed.

#### 2. Install CMake

```bash
sudo apt update
sudo apt install cmake
```

#### 3. Clone the NS-3 Repository

```bash
cd
mkdir workdir
cd workdir
git clone https://github.com/nsnam/ns-3-dev-git.git ns3.39
cd ns3.39
git checkout ns-3.39
```

#### 4. Clone & Integrate `p4sim` into NS-3

```bash
cd /home/p4/workdir/ns3.39/contrib/
git clone https://github.com/HapCommSys/p4sim.git
```

#### 5. Set Up the Environment (external libs)

```bash
cd /home/p4/workdir/ns3.39/contrib/p4sim/
sudo ./set_pkg_config_env.sh
```

#### 6. Configure & Build NS-3

```bash
# In ns-3 root directory
./ns3 configure --enable-tests --enable-examples
./ns3 build
```

#### 7. Set the `P4SIM_DIR` Environment Variable & Run

```bash
# Add to ~/.bashrc — adjust the path to match your workspace
echo 'export P4SIM_DIR="$HOME/workdir/ns3.39/contrib/p4sim"' >> ~/.bashrc
source ~/.bashrc

# Run an example
./ns3 run "exampleA"
```

> P4 artifact paths are resolved automatically via `GetP4SimDir()` / `GetP4ExamplePath()`. See [Section 5](#5-how-p4-artifact-paths-work) above for details.

---

## <a name="references"></a> References

1. [Add a specific folder with submodule to a repository](https://www.reddit.com/r/git/comments/sme7k4/add_specific_folder_with_submodule_to_a_repository/)
2. [P4Lang Tutorials repository](https://github.com/p4lang/tutorials/tree/master)

---

## <a name="appendix"></a> Appendix

After installing the P4 Behavioral Model (bmv2) and its dependencies, you should see the following:

```bash
# Libraries
$ ls /usr/local/lib/ | grep bm
libbmall.a
libbmall.la
libbmall.so
libbmall.so.0
libbmall.so.0.0.0
libbm_grpc_dataplane.a
libbm_grpc_dataplane.la
libbm_grpc_dataplane.so
libbm_grpc_dataplane.so.0
libbm_grpc_dataplane.so.0.0.0
libbmp4apps.a
libbmp4apps.la
libbmp4apps.so
libbmp4apps.so.0
libbmp4apps.so.0.0.0
libbmpi.a
libbmpi.la
libbmpi.so
libbmpi.so.0
libbmpi.so.0.0.0

# Include files
$ ls /usr/local/include/bm
bm_apps     PI                      PsaSwitch.h                 SimplePreLAG.h             SimpleSwitch.h         standard_types.h
bm_grpc     pna_nic_constants.h     psa_switch_types.h          simple_pre_lag_types.h     simple_switch_types.h  thrift
bm_runtime  PnaNic.h                simple_pre_constants.h      simple_pre_types.h         spdlog
bm_sim      pna_nic_types.h         SimplePre.h                 simple_switch              standard_constants.h
config.h    psa_switch_constants.h  simple_pre_lag_constants.h  simple_switch_constants.h  Standard.h
```

After running `sudo ./set_pkg_config_env.sh`, verify the registered packages (P4Sim only requires `bm`):

```bash
$ pkg-config --list-all | grep -E "bm|simple_switch|boost_system"
bm                             BMv2 - Behavioral Model
simple_switch                  simple switch - Behavioral Model Target Simple Switch
boost_system                   Boost System - Boost System
```

> **Note:** The spdlog bundled with BMv2 is intentionally excluded — ns-3 uses its own logging system.