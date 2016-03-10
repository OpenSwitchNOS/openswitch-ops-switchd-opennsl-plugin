#!/usr/bin/python

# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import pytest
from opstestfw import *
from opstestfw.switch.CLI import *
from opstestfw.switch.OVS import *

# Topology definition
topoDict = {"topoExecution": 1000,
            "topoType": "physical",
            "topoTarget": "dut01",
            "topoDevices": "dut01 dut02",
            "topoLinks": "lnk01:dut01:dut02, \
                          lnk02:dut01:dut02, \
                          lnk03:dut01:dut02",
            "topoFilters": "dut01:system-category:switch, \
                            dut02:system-category:switch"}

def config_creation(**kwargs):
    switch01 = kwargs.get('switch01', None)
    switch02 = kwargs.get('switch02', None)

    # Enabling interfaces on switch1
    # Enabling interface 1 on switch1
    LogOutput('info', "Enabling interface1 on switch01")
    retStruct = InterfaceEnable(
        deviceObj=switch01,
        enable=True,
        interface=switch01.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface1 on switch1"

    LogOutput('info', "Configuring ipv4 address 1.0.0.1 on interface 1 on switch 1")
    retStruct = InterfaceIpConfig(
        deviceObj=switch01,
        interface=switch01.linkPortMapping['lnk01'],
        addr="1.0.0.1",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 1 on switch 1"

    # Enabling interface 2 on switch1
    LogOutput('info', "Enabling interface2 on switch01")
    retStruct = InterfaceEnable(
        deviceObj=switch01,
        enable=True,
        interface=switch01.linkPortMapping['lnk02'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface2 on switch1"

    LogOutput('info', "Configuring ipv4 address 2.0.0.1 on interface 2 switch 1")
    retStruct = InterfaceIpConfig(
        deviceObj=switch01,
        interface=switch01.linkPortMapping['lnk02'],
        addr="2.0.0.1",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 2 on switch 1"

    # Enabling interface 3 on switch1
    LogOutput('info', "Enabling interface3 on switch01")
    retStruct = InterfaceEnable(
        deviceObj=switch01,
        enable=True,
        interface=switch01.linkPortMapping['lnk03'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface2 on switch1"

    LogOutput('info', "Configuring ipv4 address 3.0.0.1 on interface 3 switch 2")
    retStruct = InterfaceIpConfig(
        deviceObj=switch01,
        interface=switch01.linkPortMapping['lnk03'],
        addr="3.0.0.1",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 3 on switch 1"

    #Enabling static routes on switch1
    LogOutput('info', "Configuring static route  70.0.0.0/24 next hop 1.0.0.2")
    retStruct = IpRouteConfig(deviceObj=switch01, route="70.0.0.0", mask=24,
                              nexthop="1.0.0.2", config=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('info', "\nFailed to configure ipv4 address route")
        assert(False)

    LogOutput('info', "Configuring static route  70.0.0.0/24 next hop 2.0.0.2")
    retStruct = IpRouteConfig(deviceObj=switch01, route="70.0.0.0", mask=24,
                              nexthop="2.0.0.2", config=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('info', "\nFailed to configure ipv4 address route")
        assert(False)

    LogOutput('info', "Configuring static route  70.0.0.0/24 next hop 3.0.0.2")
    retStruct = IpRouteConfig(deviceObj=switch01, route="70.0.0.0", mask=24,
                              nexthop="3.0.0.2", config=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('info', "\nFailed to configure ipv4 address route")
        assert(False)

    LogOutput('info', "Configuring static route  80.0.0.0/24 next hop 1.0.0.2")
    retStruct = IpRouteConfig(deviceObj=switch01, route="80.0.0.0", mask=24,
                              nexthop="1.0.0.2", config=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('info', "\nFailed to configure ipv4 address route")
        assert(False)

def ecmp_check_status(switch, number_of_intf):

    appctl_command = "ovs-appctl plugin/debug l3ecmp"
    retStruct = switch.DeviceInteract(command=appctl_command)

    buf = retStruct.get('buffer')
    for curLine in buf.split('\n'):
        if "Interfaces:" in curLine:
            str_tok_len = len(curLine.split())
            if str_tok_len != number_of_intf + 1:
               LogOutput('info', "\nECMP object has incorrect Interfaces")

def check_status(switch, is_enabled):

    retStruct = switch.VtyshShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "show ip route"
    retStruct = switch.DeviceInteract(command=cmd)
    buf = retStruct.get('buffer')
    start_flag = 0
    for curLine in buf.split('\n'):
        if "distance" in curLine:
            continue
        if not curLine.strip():
            continue
        print "%s" % curLine
        if "80.0.0.0" in curLine and is_enabled == False:
            LogOutput("error", "Static route 80.0.0.0/24 still available after shutting down interface 2")
            assert(False)
        if "70.0.0.0" in curLine:
            start_flag = 1
            continue
        if start_flag == 1 and "24" in curLine:
            start_flag = 2
            continue
        if start_flag == 1:
            if  "1.0.0.2" in curLine and is_enabled == False:
                 LogOutput("error", "1.0.0.2 available after shut interface")
                 assert(False)
            if  "1.0.0.2" in curLine and is_enabled:
                 start_flag = 0
                 continue
    retStruct = switch.VtyshShell(enter=False)
    if start_flag > 0 and is_enabled == True:
        LogOutput('error', "1.0.0.2  nexthop not configured at all")
        assert(False)

def intf_shut_noshut_test(**kwargs):

    LogOutput('info', "Checking for sanity of config in switch01")
    switch = kwargs.get('switch', None)
    check_status(switch, True)
    ecmp_check_status(switch, 3)
    LogOutput('info', "Disabling interface1 on switch01")
    retStruct = InterfaceEnable(
        deviceObj=switch,
        enable=False,
        interface=switch.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface1 on switch1"
    check_status(switch, False)
    ecmp_check_status(switch, 2)

    LogOutput('info', "Enabling interface1 on switch01")
    retStruct = InterfaceEnable(
        deviceObj=switch,
        enable=True,
        interface=switch.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface1 on switch1"
    check_status(switch, True)
    ecmp_check_status(switch, 3)

class Test_interface_shut_noshut_ct:

    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_interface_shut_noshut_ct.testObj = testEnviron(topoDict=topoDict)
        # Get topology object
        Test_interface_shut_noshut_ct.topoObj = Test_interface_shut_noshut_ct.testObj.topoObjGet()

    def teardown_class(cls):
        Test_interface_shut_noshut_ct.topoObj.terminate_nodes()

    def test_ecmp_resilient_ct(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        dut02Obj = self.topoObj.deviceObjGet(device="dut02")
        config_creation(
            switch01 = dut01Obj,
            switch02 = dut02Obj)
        retValue = intf_shut_noshut_test(switch=dut01Obj)
        if retValue != 0:
            assert "Test failed"
        else:
            LogOutput('info', "\n### Test Passed ###\n")
