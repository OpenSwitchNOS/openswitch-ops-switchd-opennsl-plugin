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

    LogOutput('info', "Configuring ipv4 address 1.0.0.1 on interface 1")
    retStruct = InterfaceIpConfig(
        deviceObj=switch01,
        interface=switch01.linkPortMapping['lnk01'],
        addr="1.0.0.1",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 1i on switch 1"

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

    # Enabling interfaces on switch2
    # Enabling interface 1 on switch2
    LogOutput('info', "Enabling interface1 on switch02")
    retStruct = InterfaceEnable(
        deviceObj=switch02,
        enable=True,
        interface=switch02.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface1 on switch2"

    LogOutput('info', "Configuring ipv4 address 1.0.0.2 on interface 1")
    retStruct = InterfaceIpConfig(
        deviceObj=switch02,
        interface=switch02.linkPortMapping['lnk01'],
        addr="1.0.0.2",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 1 on switch 2"

    # Enabling interface 2 on switch2
    LogOutput('info', "Enabling interface2 on switch02")
    retStruct = InterfaceEnable(
        deviceObj=switch02,
        enable=True,
        interface=switch02.linkPortMapping['lnk02'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface2 on switch2"

    LogOutput('info', "Configuring ipv4 address 2.0.0.2 on interface 2 switch 2")
    retStruct = InterfaceIpConfig(
        deviceObj=switch02,
        interface=switch02.linkPortMapping['lnk01'],
        addr="2.0.0.2",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 2"

    # Enabling interface 3 on switch2
    LogOutput('info', "Enabling interface2 on switch02")
    retStruct = InterfaceEnable(
        deviceObj=switch02,
        enable=True,
        interface=switch02.linkPortMapping['lnk03'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface3 on switch2"

    LogOutput('info', "Configuring ipv4 address 2.0.0.2 on interface 3 switch 2")
    retStruct = InterfaceIpConfig(
        deviceObj=switch02,
        interface=switch02.linkPortMapping['lnk03'],
        addr="3.0.0.2",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 3"

    # Enabling static routes on switch1
    LogOutput('info', "Configuring static route  70.0.0.0/24 next hop 1.0.0.1")
    #retStruct = switch01.DeviceInteract(command="ip route 70.0.0.0/24 1.0.0.1")
    retCode   = retStruct['returnCode']
    assert retCode==0, "Failed to perform ip route 70.0.0.0/24 1.0.0.1"

    LogOutput('info', "Configuring static route  70.0.0.0/24 next hop 2.0.0.1")
    retStruct = switch01.DeviceInteract(command="ip route 70.0.0.0/24 2.0.0.1")
    retCode   = retStruct['returnCode']
    assert retCode==0, "Failed to perform ip route 70.0.0.0/24 2.0.0.1"

    LogOutput('info', "Configuring static route  70.0.0.0/24 next hop 3.0.0.1")
    retStruct = switch01.DeviceInteract(command="ip route 70.0.0.0/24 3.0.0.1")
    retCode   = retStruct['returnCode']
    assert retCode==0, "Failed to perform ip route 70.0.0.0/24 3.0.0.1"

    LogOutput('info', "Configuring static route  80.0.0.0/24 next hop 1.0.0.1")
    retStruct = switch01.DeviceInteract(command="ip route 80.0.0.0/24 1.0.0.1")
    retCode   = retStruct['returnCode']
    assert retCode==0, "Failed to perform ip route 80.0.0.0/24 1.0.0.1"

def check_status(switch, is_enabled):

    retStruct = switch.VtyshShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "exit"
    retStruct = switch.DeviceInteract(command=cmd)
    cmd = "exit"
    retStruct = switch.DeviceInteract(command=cmd)
    cmd = "show ip route"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure interface 2")
        assert(False)
    buf = retStruct.get('buffer')
    start_flag = False
    for curLine in buf.split('\n'):
        if "80.0.0.0/24" in curLine and is_enabled == False:
            LogOutput("error", "Static route 80.0.0.0/24 still available after shutting down interface 2")
            assert(False)
        if "70.0.0.0/24" in curLine:
            start_flag = True
            continue
        if start_flag and "/24" in curLine:
            start_flag = false
            continue
        if start_flag:
            if  "1.0.0.1" in curLine and is_enabled == False:
                 LogOutput("error", "Static route 70.0.0.0/24 available after shutting down interface 2")
                 assert(False)
            if  "1.0.0.1" in curLine and is_enabled:
                 start_flag = false
                 continue
    retStruct = switch.VtyshShell(enter=False)

def intf_shut_noshut_test(**kwargs):

    switch = kwargs.get('switch', None)
    check_status(switch, True)
    switch.VtyshShell(enter=True)
    retStruct = switch.ConfigVtyShell(enter=True)
    LogOutput('info', "Going to shutdown interface 2\n")
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "interface 2"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure interface 2")
        assert(False)
    cmd = "shutdown"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to shutdown interface 2")
        assert(False)

    check_status(switch, False)
    LogOutput('info', "Going to bring back interface 2\n")
    cmd = "no shutdown"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to shutdown interface 2")
        assert(False)
    check_status(switch, True)

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
