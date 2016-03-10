# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from pytest import mark

TOPOLOGY = """
#
# +-------+
# |  sw1  |
# +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
"""


@mark.platform_incompatible(['docker'])
def test_intervlan_knet(topology, step):
    sw1 = topology.get('sw1')

    assert sw1 is not None

    system_mac = None
    buf = sw1("ovs-vsctl list system", shell='bash')

    for cur_line in buf.split('\n'):
        # Match the systemMac
        if "system_mac" in cur_line:
            system_mac = cur_line.split()[2]

    system_mac = system_mac.replace('"', '')
    # Remove preceding 0s in mac
    system_mac = system_mac.replace(':0', ':')

    step("Verify bridge_normal knet interface creation")
    appctl_command = "ovs-appctl plugin/debug knet netif"
    buf = sw1(appctl_command, shell='bash')
    assert "bridge_normal" in buf
    print("Verified bridge_normal knet interface")

    step("Configure vlan interface 10")
    sw1('configure terminal')
    sw1('int vlan 10')
    sw1('ip add 10.0.0.1/24')
    sw1('ipv6 add 1000::1/120')
    sw1('end')

    step("Verify vlan interface in ASIC")
    appctl_command = "ovs-appctl plugin/debug l3intf"
    buf = sw1(appctl_command, shell='bash')
    assert system_mac in buf

    print("Verified vlan interface in ASIC")

    step("Uncofiguring VLAN interface")
    sw1('configure terminal')
    sw1("no interface vlan10")
    sw1('end')

    # Verify L3 interface is deleted in ASIC
    step("Verify vlan interface is deleted in ASIC")
    appctl_command = "ovs-appctl plugin/debug l3intf"
    buf = sw1(appctl_command, shell='bash')
    assert system_mac not in buf
