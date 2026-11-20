# Installing P4sim

This guide installs P4sim with ns-3.39, on an Ubuntu 24.04 machine (recommended) or in
a virtual machine.

P4sim is tested with Ubuntu 24.04 LTS, ns-3.39, BMv2 1.15.8 and p4c 1.2.5.19.

> **Note:** Installing BMv2 and the P4 tools takes **1–2 hours** and up to **15 GB** of
> disk space.

> **Why ns-3.39?** Starting from ns-3.40, ns-3 requires C++20. The BMv2 library is built
> with C++17, so P4sim supports ns-3.39 and earlier. We will upgrade once a
> C++20-compatible BMv2 build is available.

- [Install on Ubuntu 24.04](#install-on-ubuntu-2404) *(recommended)*
- [Install in a virtual machine](#install-in-a-virtual-machine)
- [Check the installation](#check-the-installation)

---

## Install on Ubuntu 24.04

### 1. Tools

```bash
sudo apt update
sudo apt install git vim cmake
mkdir ~/workdir
```

### 2. BMv2 and the P4 tools

The install script of [p4lang/tutorials](https://github.com/p4lang/tutorials) installs
BMv2, p4c and their dependencies:

```bash
cd ~
git clone https://github.com/p4lang/tutorials
mkdir ~/src
cd ~/src
../tutorials/vm-ubuntu-24.04/install.sh |& tee log.txt
```

Check that BMv2 is installed:

```bash
simple_switch --version
```

### 3. ns-3.39 and P4sim

```bash
cd ~/workdir
git clone https://github.com/nsnam/ns-3-dev-git.git ns3.39
cd ns3.39
git checkout ns-3.39

cd contrib
git clone https://github.com/HapCommSys/p4sim.git
cd p4sim
sudo ./set_pkg_config_env.sh
```

`set_pkg_config_env.sh` registers BMv2 as the pkg-config package `bm`. Then configure
and build ns-3:

```bash
cd ../..
./ns3 configure --enable-tests --enable-examples
./ns3 build
```

### 4. Run an example and the tests

```bash
./ns3 run p4-v1model-ipv4-forwarding
./test.py -s p4-packet
```

[examples.md](examples.md) lists the examples, and
[test/Readme.md](../test/Readme.md) the test suites.

### 5. Where P4sim finds the P4 files

P4sim reads P4 files (JSON programs, flow tables, topology files) from the p4sim folder
of the build, so no setup is needed, and several ns-3 trees can live side by side. The
examples build their paths with two functions of `ns3/format-utils.h`:

| Function | Returns |
|---|---|
| `GetP4SimDir()` | The p4sim folder of the build |
| `GetP4ExamplePath()` | `GetP4SimDir() + "/examples/p4src"` |

```cpp
#include "ns3/format-utils.h"

std::string p4SrcDir         = GetP4ExamplePath() + "/p4_basic";
std::string p4JsonPath       = p4SrcDir + "/p4_basic.json";
std::string flowTableDirPath = p4SrcDir + "/";
std::string topoInput        = p4SrcDir + "/topo.txt";
```

> **Note:** Earlier versions asked you to set `P4SIM_DIR` in `~/.bashrc`. It is no longer
> needed; you can remove it. If it names another p4sim folder, it is ignored and a notice
> says so.

---

## Install in a virtual machine

p4lang/tutorials also has a Vagrant configuration for an Ubuntu 24.04 virtual machine
with the P4 tools (`vm-ubuntu-24.04/Vagrantfile`). It was tested with the tutorials at
commit `7273da1c2ac2fd05cea0a9dd0504184b8c955eae` (2025-01-25).

You need [Vagrant](https://www.vagrantup.com/) and
[VirtualBox](https://www.virtualbox.org/).

1. Build the virtual machine, named "P4 Tutorial Development":

   ```bash
   git clone https://github.com/p4lang/tutorials
   cd tutorials/vm-ubuntu-24.04
   vagrant up dev
   ```

2. In the virtual machine, install the P4 tools as in
   [step 2](#2-bmv2-and-the-p4-tools) (see also the
   [tutorials' instructions](https://github.com/p4lang/tutorials/tree/7273da1c2ac2fd05cea0a9dd0504184b8c955eae/vm-ubuntu-24.04#introduction)),
   and check with `simple_switch --version`.

3. Install CMake (`sudo apt install cmake`), then follow
   [steps 3 to 5](#3-ns-339-and-p4sim).

---

## Check the installation

BMv2 installs its libraries in `/usr/local/lib` and its headers in
`/usr/local/include/bm`. P4sim links `libbmall` and finds BMv2 through the
pkg-config package `bm`, which `sudo ./set_pkg_config_env.sh` registers:

```bash
ls /usr/local/lib/libbmall.so /usr/local/include/bm/bm_sim
pkg-config --list-all | grep -E "^bm "
```

If `./ns3 configure` does not find `bm`, run `set_pkg_config_env.sh` again.

---

## Feedback

For problems or suggestions, open an issue on
[GitHub](https://github.com/HapCommSys/p4sim/issues) or contact the maintainer,
mingyu.ma@tu-dresden.de.
