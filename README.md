# P4sim in ns-3

<p align="center">
<a href="https://arxiv.org/abs/2503.17554" target="_blank"><img src="https://img.shields.io/badge/arXiv-2503.17554-red"></a>
<a href="https://github.com/HapCommSys/p4sim-artifact-icns3" target="_blank">
  <img src="https://img.shields.io/badge/GitHub-HapCommSys%2Fp4sim--artifact--icns3-blue?logo=github" alt="GitHub Repo">
</a>
<a href="https://github.com/p4lang/gsoc/blob/main/2025/ideas_list.md#project-5" target="_blank">
  <img src="https://img.shields.io/badge/Program%20Google%20Summer%20of%20Code-2025-fbbc05?style=flat&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAMAAABHPGVmAAAALVBMVEVHcEz7vQD7vQD8vQD7vQD8vQD7vQD8vQD8vQD7vQD7vQD8vQD7vQD7vQD7vQAgxtLpAAAADnRSTlMAZvVQ6QrVPhl6oSmHvzL6LQUAAASGSURBVHjatdnZdusgDAVQELMY%2Fv9zb2%2Bwc%2BIKDzQLvTXB3gYBFqmaDVeKU4sCBlFyy43WqLjlBpR1BpR1BpR1xjoFxmIFBpSVBpSVBpSVBpSVBpQ1xvdK1oPgblhfOWltjNaJq7ddYT2IfImYJqMDrENUChGDZn%2FWQ%2FMHxBcD4BMyBc5XCHkNQTq60vfIgXAx5xByju6T8V8itsT3%2FUPi6r39Ce8rp%2FCWYrHfIDXs95FZJs%2FvTob6Z4T2buQE4eikvHeG%2FoZY7TpRfDsNWzrjtP0L4s12NYhh%2BO1ZjJ9HfOjdYGo3QZx7YvwEAgOPdx3eQJlArMFA3wXSZ%2BwMQvplJGoPY6sqNU0gxcGYUVx5jtSIx3oS6HysTxEbMMDPAmkM9iFSXnPXt8nwuQ%2FYI8TH%2F425TQe7%2FnBPEH2bECI6T4t%2Bgvh4N1istR50FJdeIX1Ek%2FqJdGGQOWmAa4u7rn18vuuIzUq52gbxvpiSuzIau%2BuO9FUUfTvvCjcoQ4MMltRnEOqF0pdD%2FwiBZWxoqGCn8r2VGKIUCHOoTyHK2g7y1bsJRRqNe3%2FlXv5GbNhWEWXxbsf1UITRF4kYcM4KiI%2FbeFIevNNq7P2EIg0bVL%2BfqCcyYV2rbDdExWSPjUPPGBRh9JTowTscW0Dqf%2BwLXGmPthgKKMJo1f1OSQ29hf1Mbdlmg5NFV1H7KoICA3mruIQ4vl4TTFhvuAlxxrdb1J55KMJoBatEPCv6mr3sJzK%2F9RQKDAx49Ji5ctSLwsxAxgyuiduOAeVtIG14zppPKtAka9lcMZz71IHyNoAcCpvIx6UfxGLleCim3ggUpe0dQhe7I86mWvQERZmCIocryAqPsdYOSQlVIjCgyMRbLSaXxi3GD4LEw4AipzCyyvS5a5ThMpJTGAYUuQljhiWL53R11FN5BxhQsK0UWbE747E7evGV2FaEAUWmDave0H4LQxg6nErl1IEBBRdmOzjkBPpdqFB%2BpUtUGb0tDKloZP44hQLthQoDwXYiXlowpMJIymExdARL8SViYzymhGEMFR%2FR3cOyNoRCpQcZFu1s6AsNhlQuSiJP%2B1Kk90dNRHW9BYyhwlszhNgdb05CjmGcKDb3DotAoYIYV9wWxjDSZcHNmN%2Fj0KpPm3R7dMjq7HlrSokvjIqjww3SEhb4XJDpg3CLvM9%2BPG%2FMHOcaOwzYRFScNe8QHJb9nOEDhvkGwV48eZC3BgfzWwSHZaXthKEVMvkMaQnKhKESzSCkJ37uQqlJ7RmCIcbr%2By5qUEjiIwQK3q4yZKHqYDxEUIo4U6%2BNahxKr0kEZwv8HC%2BDqo69UaI2ieBAujN2RNhOoPybQjBr9oNSKNXSoQ%2B2luCUQuk1iSCIg9oiZl24Vv8TtXLROaotAtO3%2F9ooWSFcjDnH6BQio2SZQSRz%2FpsPfsifQ2RY1tmNBM3oxQRCbRjkOZn%2FEACT2J%2B1vkZiGESyG1SZS%2FqJ1wTogE1hEFHNh9yNCbvvREwqCwwoawwoKw0oKw0oKw0oKw0oKw0oKw0oMFYqMFYqMFYqMBYq88Y%2FxB7wiOJRvWkAAAAASUVORK5CYII%3D" height="20"/></a>
</p>

P4sim is a high-performance simulation framework that brings P4-programmable data plane processing into the [ns-3 network simulator](https://www.nsnam.org/). It enables researchers and developers to model, execute, and evaluate P4 programs within realistic end-to-end network simulations, tightly coupling a P4-driven packet processing engine with ns-3's flexible network modeling for fine-grained analysis of programmable networks at scale.

P4sim is open-source software licensed under the Apache License 2.0.

### Key Features

* **Behavioral accuracy**: the packet processing pipeline is based on [BMv2](https://github.com/p4lang/behavioral-model), ensuring the same reference behavior model used by the broader P4 community.
* **ns-3 integration**: network topology, traffic generation, and timing are fully managed by ns-3, making it straightforward to configure experiments or compose P4sim with other ns-3 modules.
* **BMv2 compatibility**: existing P4 programs and flow-table entry scripts written for BMv2 can be used directly in P4sim without modification.
* **Accurate timing models**: packet scheduling and queuing faithfully reflect realistic network timing behavior.
* **High-performance simulation**: designed to handle large-scale network scenarios and high traffic rates in ns-3 simulation environments.

---

### Publications

- Mingyu Ma, Giang T. Nguyen. **"P4sim: Programming Protocol-independent Packet Processors in ns-3."** 2025. [[ACM DL]](https://dl.acm.org/doi/10.1145/3747204.3747210) [[arXiv]](https://arxiv.org/abs/2503.17554)
- **Reproducibility artifact:** [p4sim-artifact-icns3](https://github.com/HapCommSys/p4sim-artifact-icns3) — accepted at the 2025 International Conference on ns-3 (ICNS3).

Our implementation builds upon the P4-driven Network Simulator Module described in:

- Bai, Jiasong, *et al.* **"NS4: Enabling programmable data plane simulation."** Proc. of the Symposium on SDN Research, pp. 1–7, 2018. [[ACM DL]](https://dl.acm.org/doi/abs/10.1145/3185467.3185470)
- Fan, Chengze, *et al.* **"NS4: A P4-driven network simulator."** Proc. of the SIGCOMM Posters and Demos, pp. 105–107, 2017. [[ACM DL]](https://dl.acm.org/doi/10.1145/3123878.3132002)

---

## Installation & Setup

The following steps set up a local environment to run P4sim with **ns-3.39** on **Ubuntu 24.04 LTS**.

> **Note:** The BMv2 and P4 software installation will take **1–2 hours** and consume up to **15 GB** of disk space.

> **Why ns-3.39 or earlier?** Starting from ns-3.40, ns-3 requires C++20. However, BMv2 is currently built with C++17. P4sim therefore supports ns-3.39 and earlier versions. We plan to upgrade once a C++20-compatible BMv2 build becomes available.

### Step 1: Initialize the Working Directory

```bash
sudo apt update
sudo apt install git vim cmake
mkdir ~/workdir && cd ~/workdir
```

### Step 2: Install BMv2 and P4 Dependencies

Install all required libraries and tools via the official [p4lang/tutorials](https://github.com/p4lang/tutorials) repository:

```bash
cd ~
git clone https://github.com/p4lang/tutorials
mkdir ~/src && cd ~/src
../tutorials/vm-ubuntu-24.04/install.sh |& tee log.txt
```

Verify the installation:

```bash
simple_switch --version
```

### Step 3: Clone and Build ns-3.39 with P4sim

```bash
cd ~/workdir
git clone https://github.com/nsnam/ns-3-dev-git.git ns3.39
cd ns3.39 && git checkout ns-3.39
```

Add the P4sim module:

```bash
cd contrib
git clone https://github.com/HapCommSys/p4sim.git
cd p4sim && sudo ./set_pkg_config_env.sh
```

Configure and build:

```bash
cd ../..
./ns3 configure --enable-tests --enable-examples
./ns3 build
```

### Step 4: Set the `P4SIM_DIR` Environment Variable

P4sim resolves P4 artifact paths (JSON pipelines, flow tables, topology files) via the `P4SIM_DIR` environment variable. Add it to your shell profile:

```bash
echo 'export P4SIM_DIR="$HOME/workdir/ns3.39/contrib/p4sim"' >> ~/.bashrc
source ~/.bashrc
```

> **Tip:** If `P4SIM_DIR` is not set, P4sim falls back to a path derived from the executable location, but setting it explicitly is recommended for reliability.

### Step 5: Run an Example

```bash
./ns3 run p4-v1model-ipv4-forwarding
```

No manual path editing is required — all examples use portable path helpers. A full list of available example names can be found in [`examples/CMakeLists.txt`](examples/CMakeLists.txt).

See the full step-by-step guide (including VM setup) in [doc/vm-env.md](doc/vm-env.md).

---

## Supported P4 Architectures

| Value | Architecture | BMv2 Target |
|-------|-------------|-------------|
| 0 | V1model | `simple_switch` |
| 1 | PSA | `psa_switch` |
| 2 | PNA | `pna_nic` |

---

## Switch Parameters

The forwarding behaviour is defined by the P4 program and its flow-table configuration. The following ns-3 attributes on `ns3::P4SwitchNetDevice` control simulation-level settings:

| Attribute | Description |
|---|---|
| `JsonPath` | Path to the compiled P4 JSON file |
| `FlowTablePath` | Path to the flow-table configuration file |
| `P4SwitchArch` | Architecture selector (0 = V1model, 1 = PSA, 2 = PNA) |
| `ChannelType` | Channel type (0 = CSMA, 1 = point-to-point) |
| `SwitchRate` | Processing rate in packets per second |
| `QueueBufferSize` | Total queue buffer size (packets) |
| `InputBufferSizeLow` | Input buffer size for low-priority (external) packets |
| `InputBufferSizeHigh` | Input buffer size for high-priority (internal) packets |
| `EnableTracing` | Enable basic throughput tracing |
| `EnableSwap` | Enable runtime swapping of the P4 configuration |

> **Notes:**
> 1. When using a CSMA channel, the P4 program must handle ARP explicitly.
> 2. Buffer attributes only take effect if the selected architecture models that buffer.
> 3. `EnableTracing` currently supports basic throughput measurement only.

---

## P4sim Development Workflow

Using P4sim typically involves the following steps:

1. **Develop the P4 program** — implement your packet processing logic in P4 (headers, parsers, match-action tables, control flow).
2. **Compile the P4 program** — use `p4c` to generate the corresponding JSON pipeline description.
3. **Create an ns-3 simulation script** — write a simulation script (e.g. in `scratch/` or `examples/`) and assign P4-enabled switches to the desired nodes.
4. **Configure the control plane** — populate match-action tables and implement any required control-plane logic before or during the simulation.
5. **Run and observe** — execute the simulation and collect performance metrics such as throughput, latency, and packet traces.

---

## Examples

See the full list and descriptions in [doc/examples.md](doc/examples.md).

Selected examples:

| Script | Description |
|---|---|
| `p4-v1model-ipv4-forwarding` | 2-host, 1-switch IPv4 forwarding (V1model) |
| `p4-psa-ipv4-forwarding` | Same topology, PSA architecture |
| `p4-pna-ipv4-forwarding` | Same topology, PNA architecture |
| `p4-basic-example` | 4-host, 4-switch mesh (V1model) |
| `p4-basic-tunnel` | 3-host tunnel with custom header |
| `p4-firewall` | Stateful firewall |
| `p4-l3-router` | 3-router line topology, L3 forwarding |
| `p4-link-monitoring` | In-band link utilisation probes |
| `p4-spine-leaf-topo` | Spine-leaf with ECMP load balancing |
| `p4-topo-fattree` | Auto-generated fat-tree topology |
| `p4-queue-test` | QoS-aware queuing |
| `p4-source-routing` | Source routing with custom headers |
| `p4-basic-controller` | Runtime controller flow-table updates |

In the [paper](https://dl.acm.org/doi/10.1145/3747204.3747210), P4sim is evaluated using representative networking scenarios demonstrating its capability to model basic tunneling (custom header encapsulation/decapsulation) and load balancing (distributing traffic across multiple network paths using P4 pipelines).

---

## Known Limitations

The packet processing rate `SwitchRate` (packets per second) must currently be configured manually for each switch. An inappropriate value can cause the switch to enter an idle polling loop, leading to wasted CPU cycles. Automatic rate tuning is planned for a future release.

---

## Generating Doxygen Documentation

```bash
sudo apt install doxygen graphviz dia
./ns3 configure --enable-tests --enable-examples
./ns3 build
./ns3 docs doxygen
xdg-open build/doxygen/html/index.html
```

---

## Maintainers & Contributors

- **Maintainers**: [Mingyu Ma](mailto:mingyu.ma@tu-dresden.de)
- **Contributors**: Thanks to [GSoC 2025](https://summerofcode.withgoogle.com/) with [Davide](mailto:d.scano89@gmail.com) support and contributor [Vineet](https://github.com/Vineet1101).
