#! /usr/bin/env python3
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

# Smoke tests: test.py runs every example below and only checks that it
# finishes with exit code 0. Tests that check results live in the test suites.
#
# Each tuple is (example name with arguments, do_run, do_valgrind_run). test.py
# reads this file as text: write every argument literally (no variables) and do
# not use a closing square bracket inside the list.
#
# The BMv2 pipeline log is off by default (BmLogLevel), which keeps the examples
# fast and leaves nothing in /tmp. They run in parallel safely: every switch
# reserves its own Thrift port (see the ThriftPort attribute).

cpp_examples = [
    ("p4-v1model-ipv4-forwarding", "True", "False"),
    ("p4-psa-ipv4-forwarding", "True", "False"),
    ("p4-pna-ipv4-forwarding", "True", "False"),
    ("p4-basic-example", "True", "False"),
    ("p4-basic-tunnel", "True", "False"),
    ("p4-basic-controller", "True", "False"),
    ("p4-l2-learning", "True", "False"),
    ("p4-controller-action-profile", "True", "False"),
    ("p4-calc", "True", "False"),
    ("p4-firewall", "True", "False"),
    ("p4-l3-router", "True", "False"),
    ("p4-link-monitoring", "True", "False"),
    ("p4-source-routing", "True", "False"),
    ("p4-queue-test", "True", "False"),
    ("p4-priority-queues", "True", "False"),
    ("p4-priority-queues --priority=0", "True", "False"),
    ("p4-latency", "True", "False"),
    ("p4-ipv4-animation", "True", "False"),
    ("p4-custom-header-test", "True", "False"),
    ("p4-p2p-custom-header-test", "True", "False"),
    ("p4-topo-fattree", "True", "False"),
    ("p4-spine-leaf-topo --numFlows=10 --duration=2", "True", "False"),
    ("topo-fattree", "True", "False"),
    ("p4-v1model-ipv4-forwarding-bridge --channelType=csma", "True", "False"),
    ("p4-voq-fabric-integration", "True", "False"),
    ("p4-voq-fabric-priority", "True", "False"),
    ("p4-voq-fabric-throughput", "True", "False"),
]

python_examples = []
