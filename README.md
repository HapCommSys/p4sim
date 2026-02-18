# P4sim in ns-3

<p align="center">
<a href="https://arxiv.org/abs/2503.17554" target="_blank"><img src="https://img.shields.io/badge/arXiv-2503.17554-red"></a>
<a href="https://github.com/HapCommSys/p4sim-artifact-icns3" target="_blank">
  <img src="https://img.shields.io/badge/GitHub-HapCommSys%2Fp4sim--artifact--icns3-blue?logo=github" alt="GitHub Repo">
</a>
<a href="https://github.com/p4lang/gsoc/blob/main/2025/ideas_list.md#project-5" target="_blank">
  <img src="https://img.shields.io/badge/Program%20Google%20Summer%20of%20Code-2025-fbbc05?style=flat&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAMAAABHPGVmAAAALVBMVEVHcEz7vQD7vQD8vQD7vQD8vQD7vQD8vQD8vQD7vQD7vQD8vQD7vQD7vQD7vQAgxtLpAAAADnRSTlMAZvVQ6QrVPhl6oSmHvzL6LQUAAASGSURBVHjatdnZdusgDAVQELMY%2Fv9zb2%2Bwc%2BIKDzQLvTXB3gYBFqmaDVeKU4sCBlFyy43WqLjlBpR1BpR1BpR1xjoFxmIFBpSVBpSVBpSVBpSVBpQ1xvdK1oPgblhfOWltjNaJq7ddYT2IfImYJqMDrENUChGDZn%2FWQ%2FMHxBcD4BMyBc5XCHkNQTq60vfIgXAx5xByju6T8V8itsT3%2FUPi6r39Ce8rp%2FCWYrHfIDXs95FZJs%2FvTob6Z4T2buQE4eikvHeG%2FoZY7TpRfDsNWzrjtP0L4s12NYhh%2BO1ZjJ9HfOjdYGo3QZx7YvwEAgOPdx3eQJlArMFA3wXSZ%2BwMQvplJGoPY6sqNU0gxcGYUVx5jtSIx3oS6HysTxEbMMDPAmkM9iFSXnPXt8nwuQ%2FYI8TH%2F425TQe7%2FnBPEH2bECI6T4t%2Bgvh4N1istR50FJdeIX1Ek%2FqJdGGQOWmAa4u7rn18vuuIzUq52gbxvpiSuzIau%2BuO9FUUfTvvCjcoQ4MMltRnEOqF0pdD%2FwiBZWxoqGCn8r2VGKIUCHOoTyHK2g7y1bsJRRqNe3%2FlXv5GbNhWEWXxbsf1UITRF4kYcM4KiI%2FbeFIevNNq7P2EIg0bVL%2BfqCcyYV2rbDdExWSPjUPPGBRh9JTowTscW0Dqf%2BwLXGmPthgKKMJo1f1OSQ29hf1Mbdlmg5NFV1H7KoICA3mruIQ4vl4TTFhvuAlxxrdb1J55KMJoBatEPCv6mr3sJzK%2F9RQKDAx49Ji5ctSLwsxAxgyuiduOAeVtIG14zppPKtAka9lcMZz71IHyNoAcCpvIx6UfxGLleCim3ggUpe0dQhe7I86mWvQERZmCIocryAqPsdYOSQlVIjCgyMRbLSaXxi3GD4LEw4AipzCyyvS5a5ThMpJTGAYUuQljhiWL53R11FN5BxhQsK0UWbE747E7evGV2FaEAUWmDave0H4LQxg6nErl1IEBBRdmOzjkBPpdqFB%2BpUtUGb0tDKloZP44hQLthQoDwXYiXlowpMJIymExdARL8SViYzymhGEMFR%2FR3cOyNoRCpQcZFu1s6AsNhlQuSiJP%2B1Kk90dNRHW9BYyhwlszhNgdb05CjmGcKDb3DotAoYIYV9wWxjDSZcHNmN%2Fj0KpPm3R7dMjq7HlrSokvjIqjww3SEhb4XJDpg3CLvM9%2BPG%2FMHOcaOwzYRFScNe8QHJb9nOEDhvkGwV48eZC3BgfzWwSHZaXthKEVMvkMaQnKhKESzSCkJ37uQqlJ7RmCIcbr%2By5qUEjiIwQK3q4yZKHqYDxEUIo4U6%2BNahxKr0kEZwv8HC%2BDqo69UaI2ieBAujN2RNhOoPybQjBr9oNSKNXSoQ%2B2luCUQuk1iSCIg9oiZl24Vv8TtXLROaotAtO3%2F9ooWSFcjDnH6BQio2SZQSRz%2FpsPfsifQ2RY1tmNBM3oxQRCbRjkOZn%2FEACT2J%2B1vkZiGESyG1SZS%2FqJ1wTogE1hEFHNh9yNCbvvREwqCwwoawwoKw0oKw0oKw0oKw0oKw0oKw0oMFYqMFYqMFYqMBYq88Y%2FxB7wiOJRvWkAAAAASUVORK5CYII%3D" height="20"/></a>
</p>

P4sim is a P4-driven network simulator that integrates [P4](https://p4.org/), the programmable data plane language, with [ns-3](https://www.nsnam.org/), one of the most widely used network simulators. It embeds the [BMv2 behavioral model](https://github.com/p4lang/behavioral-model) so that user-written P4 programs execute inside ns-3 simulations, producing bit-accurate forwarding behaviour.

P4sim is open-source software licensed under the Apache License 2.0.

### Publications

- Mingyu Ma, Giang T. Nguyen. **"P4sim: Programming Protocol-independent Packet Processors in ns-3."** 2025. [[ACM DL]](https://dl.acm.org/doi/10.1145/3747204.3747210) [[arXiv]](https://arxiv.org/abs/2503.17554) 
- **Reproducibility artifact:** [p4sim-artifact-icns3](https://github.com/HapCommSys/p4sim-artifact-icns3) — accepted at the 2025 International Conference on ns-3 (ICNS3).

Our implementation builds upon the P4-driven Network Simulator Module described in:

- Bai, Jiasong, *et al.* **"NS4: Enabling programmable data plane simulation."** Proc. of the Symposium on SDN Research, pp. 1–7, 2018. [[ACM DL]](https://dl.acm.org/doi/abs/10.1145/3185467.3185470)
- Fan, Chengze, *et al.* **"NS4: A P4-driven network simulator."** Proc. of the SIGCOMM Posters and Demos, pp. 105–107, 2017. [[ACM DL]](https://dl.acm.org/doi/10.1145/3123878.3132002)

---

## Installation & Setup

See the full step-by-step guide in [doc/vm-env.md](doc/vm-env.md).

**Quick start** (assuming BMv2 is already installed):

```bash
cd <ns-3-root>/contrib
git clone https://github.com/HapCommSys/p4sim.git
cd p4sim && sudo ./set_pkg_config_env.sh
cd ../..
./ns3 configure --enable-tests --enable-examples
./ns3 build

# Set the environment variable (add to ~/.bashrc for persistence)
export P4SIM_DIR="$PWD/contrib/p4sim"

# Run an example
./ns3 run p4-v1model-ipv4-forwarding
```

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

## Examples

See the full list and descriptions in [doc/examples.md](doc/examples.md).

Selected examples:

| Script | Description |
|---|---|
| `p4-v1model-ipv4-forwarding` | 2-host, 1-switch IPv4 forwarding (V1model) |
| `p4-psa-ipv4-forwarding` | Same topology, PSA architecture |
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

---

## Generating Doxygen Documentation

```bash
sudo apt install doxygen graphviz dia
./ns3 configure --enable-tests --enable-examples
./ns3 build
./ns3 docs doxygen
xdg-open build/doxygen/html/index.html
```
