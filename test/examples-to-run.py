#! /usr/bin/env python3
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

# Smoke tests: test.py runs every example below and only checks that it
# finishes with exit code 0. Tests that check results live in the test suites.
#
# Each tuple is (example name with arguments, do_run, do_valgrind_run). test.py
# reads this file as text: write every argument literally (no variables) and do
# not use a closing square bracket inside the list.
#
# The examples with P4 switches turn the BMv2 pipeline log off, which keeps them fast and
# leaves nothing in /tmp. They run in parallel safely: every switch reserves its
# own Thrift port (see the ThriftPort attribute).

cpp_examples = [
    ("p4-v1model-ipv4-forwarding --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-psa-ipv4-forwarding --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-pna-ipv4-forwarding --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-basic-example --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-basic-tunnel --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-basic-controller --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-controller-action-profile --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-calc --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-firewall --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-l3-router --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-link-monitoring --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-source-routing --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-queue-test --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-ipv4-animation --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-custom-header-test", "True", "False"),
    ("p4-p2p-custom-header-test", "True", "False"),
    ("p4-topo-fattree --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("p4-spine-leaf-topo --numFlows=10 --duration=2 --ns3::P4SwitchNetDevice::BmLogLevel=off", "True", "False"),
    ("topo-fattree", "True", "False"),
]

python_examples = []
