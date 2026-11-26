# Installing P4sim

P4sim is an ns-3 module: it lives in `contrib/p4sim` of an ns-3 tree and needs
BMv2 (its libraries, headers and runtime CLIs) and the P4 compiler p4c. It builds
with ns-3.39 to ns-3.49 and is tested with ns-3.39 and ns-3.49 and BMv2 1.15.8, on
Ubuntu 24.04 and 26.04.

- [Quick installation](#quick-installation) with `install.sh` *(recommended)*
- [Docker](docker.md): nothing is installed on the host
- [Install step by step](#install-step-by-step), with the P4 tools of p4lang/tutorials
- [Install in a virtual machine](#install-in-a-virtual-machine)
- [Check the installation](#check-the-installation)
- [Where P4sim finds the P4 files](#where-p4sim-finds-the-p4-files)

---

## Quick installation

On Ubuntu 24.04 or 26.04, natively or in WSL2:

```bash
sudo apt update && sudo apt install -y git
mkdir -p ~/workdir && cd ~/workdir
git clone --depth 1 -b ns-3.39 https://github.com/nsnam/ns-3-dev-git.git ns3.39
git clone https://github.com/HapCommSys/p4sim.git ns3.39/contrib/p4sim
ns3.39/contrib/p4sim/install.sh
```

For ns-3.49, replace `ns-3.39` and `ns3.39` by `ns-3.49` and `ns3.49`. Run
`install.sh` as yourself, not with sudo: it asks for your password once and uses
sudo only for the system steps. It takes about 6 minutes on 16 cores, about two
of them for building BMv2, which happens only once. It ends with the number of
passed test suites and examples.

### What it does

| Step | What | Where |
|---|---|---|
| `apt` | Build tools, CMake, Ninja, ccache, Thrift and the libraries of BMv2 and P4sim from Ubuntu; p4c, prebuilt, from the p4lang repository (`home:p4lang` on download.opensuse.org) | system |
| `bmv2` | BMv2 1.15.8 from source: shared libraries, the targets `simple_switch` and `psa_switch`, and the runtime CLIs | `/usr/local` |
| `ns3` | Registers BMv2 for pkg-config (`set_pkg_config_env.sh`), configures ns-3 with the modules P4sim needs and P4sim's tests and examples, and builds it | the ns-3 tree |
| `test` | p4c, the runtime CLIs, one example, then all test suites and examples of P4sim | |

Without arguments, `install.sh` runs the four steps and downloads and builds BMv2
while apt and ns-3 are busy. It can run again: BMv2 is built only once, and an
ns-3 tree that is configured already keeps its modules. A single step runs with
its name, for example `install.sh test`, which needs no sudo. After a change to
P4sim, `./ns3 build` is enough.

- P4sim compiles against the headers and the Thrift service libraries of BMv2 in
  `/usr/local` (`set_pkg_config_env.sh` registers that place), so BMv2 is built
  from source and installed there.
- A new ns-3 configuration gets `--enable-modules='p4sim;nix-vector-routing'`
  (and the modules they need) and `--filter-module-examples-and-tests=p4sim`,
  which keeps the build short. The example `p4-ipv4-animation` needs netanim and
  is not built. To build all of ns-3 later:

  ```bash
  ./ns3 configure --enable-tests --enable-examples --enable-modules='' --filter-module-examples-and-tests=''
  ./ns3 build
  ```

- If a BMv2 is installed in `/usr/local` already, for example by p4lang/tutorials,
  `install.sh` uses it; `BMV2_REBUILD=1` replaces it by BMv2 1.15.8. A BMv2
  elsewhere, such as the package `p4lang-bmv2` in `/usr`, is not used.
- With a Python virtual environment or conda active: `install.sh` installs BMv2's
  Python modules for the system Python, but the runtime CLIs run the `python3`
  found first in `PATH`, so that environment needs the package `thrift`
  (`pip install thrift`), or deactivate it.
- ns-3.39's `./ns3` does not run on Python 3.14, the Python of Ubuntu 26.04:
  Python 3.14 rejects the way it declares its sub-commands. `install.sh` then
  changes these lines of `ns3` in your tree, as later ns-3 releases did.
- **WSL2**: keep the ns-3 tree in the Linux file system (for example
  `~/workdir`), not under `/mnt/c`, where builds are much slower. WSL adds the
  Windows folders to `PATH`; `install.sh` leaves them out, because
  `./ns3 configure` stores `PATH` and every start of a runtime CLI would then
  search them. A later `./ns3 configure` in a normal WSL shell stores them again;
  `appendWindowsPath = false` in the `[interop]` section of `/etc/wsl.conf`
  (then `wsl --shutdown`) leaves them out for good.

Settings, as environment variables (for example `JOBS=4 ns3.39/contrib/p4sim/install.sh`):

| Variable | Default | Meaning |
|---|---|---|
| `JOBS` | one per CPU | Parallel build jobs; use fewer on a machine with little memory |
| `NS3_MODULES` | `p4sim;nix-vector-routing` | The ns-3 modules to build; set it to change the modules of a configured tree |
| `BMV2_REBUILD` | `0` | `1` builds and installs BMv2 1.15.8 even if a BMv2 is installed |
| `LOGDIR` | `~/.cache/p4sim-install` | Logs: `install.log`, and one file per build part |

---

## Install step by step

These steps install the P4 tools with the install script of
[p4lang/tutorials](https://github.com/p4lang/tutorials), on Ubuntu 24.04. It
installs more than P4sim needs (Mininet, PI, gRPC, ...), takes **1–2 hours** and
up to **15 GB** of disk space, and installs the BMv2 and p4c versions that the
tutorials pin, which may differ from the tested BMv2 1.15.8.

### 1. Tools

```bash
sudo apt update
sudo apt install git vim cmake
mkdir ~/workdir
```

### 2. BMv2 and the P4 tools

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
git clone --depth 1 -b ns-3.39 https://github.com/nsnam/ns-3-dev-git.git ns3.39
cd ns3.39/contrib
git clone https://github.com/HapCommSys/p4sim.git
cd p4sim
sudo ./set_pkg_config_env.sh
```

`set_pkg_config_env.sh` registers BMv2 as the pkg-config package `bm`. Then
configure and build ns-3:

```bash
cd ../..
./ns3 configure --enable-tests --enable-examples
./ns3 build
```

For another release from ns-3.40 to ns-3.49, clone that tag instead (for example
`-b ns-3.49`). From ns-3.41 on, ns-3 builds as C++20 or C++23, and the spdlog
that BMv2 bundles does not compile as C++20; P4sim then builds with a copy of
these headers that has the fix
([patches/bmv2-spdlog-cxx20.patch](../patches/bmv2-spdlog-cxx20.patch)). The
installed BMv2 is not changed.

### 4. Run an example and the tests

```bash
./ns3 run p4-v1model-ipv4-forwarding
./test.py -s p4-packet
```

[examples.md](examples.md) lists the examples, and
[test/Readme.md](../test/Readme.md) the test suites.

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
   [steps 3 and 4](#3-ns-339-and-p4sim).

---

## Check the installation

```bash
p4c --version
simple_switch --version
ls /usr/local/lib/libbmall.so /usr/local/include/bm/bm_sim
pkg-config --list-all | grep -E "^bm "
```

BMv2 installs its libraries in `/usr/local/lib` and its headers in
`/usr/local/include/bm`. P4sim links `libbmall` and finds BMv2 through the
pkg-config package `bm`, which `sudo ./set_pkg_config_env.sh` registers. If
`./ns3 configure` does not find `bm`, run `set_pkg_config_env.sh` again, then
`./ns3 configure` again: P4sim looks for the BMv2 libraries when ns-3 is
configured.

---

## Where P4sim finds the P4 files

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

## Feedback

For problems or suggestions, open an issue on
[GitHub](https://github.com/HapCommSys/p4sim/issues) or contact the maintainer,
mingyu.ma@tu-dresden.de.
