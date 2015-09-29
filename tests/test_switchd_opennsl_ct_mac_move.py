#!/usr/bin/env python

# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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
            "topoDevices": "dut01 wrkston01 wrkston02 wrkston03",
            "topoLinks": "lnk01:dut01:wrkston01,lnk02:dut01:wrkston02,lnk03:dut01:wrkston03",
            "topoFilters": "dut01:system-category:switch,wrkston01:system-category:workstation,wrkston02:system-category:workstation,wrkston03:system-category:workstation"}

def mac_move(**kwargs):
    switch = kwargs.get('switch',None)
    host1 = kwargs.get('host1',None)
    host2 = kwargs.get('host2',None)
    host3 = kwargs.get('host3',None)


    #Enabling interfaces
    LogOutput('info', "Enabling interface1 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=True, interface=switch.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to enable interface1 on switch1"


    # Create interface2 but put it in shut state so that MAC's are not learnt on
    # it.
    LogOutput('info', "Create interface2, but put it in 'shutdown' state on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=False, interface=switch.linkPortMapping['lnk02'])
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to create interface2 on switch1"


    LogOutput('info', "Enabling interface3 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=True, interface=switch.linkPortMapping['lnk03'])
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to enable interface3 on switch1"


    LogOutput('info', "Enabling interface vlan 10 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=True, vlan=10)
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to enable interface on switch"

    LogOutput('info', "Enabling interface vlan 20 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=True, vlan=20)
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to enable interface on switch"

    interface1=int(switch.linkPortMapping['lnk01'])

    interface2=int(switch.linkPortMapping['lnk02'])

    interface3=int(switch.linkPortMapping['lnk03'])

    returnStructure = switch.VtyshShell(enter=True)
    returnCode = returnStructure.returnCode()
    assert returnCode==0, "Failed to get vtysh config prompt"

    returnStructure = switch.ConfigVtyShell(enter=True)

    LogOutput('info', "Configuring VLAN 10")
    returnStructure =switch.DeviceInteract(command="vlan 10")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to enter interface context for vlan"

    returnStructure =switch.DeviceInteract(command="no shutdown")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no shut"

    returnStructure = switch.DeviceInteract(command="exit")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to exit vlan"

    LogOutput('info', "Configuring VLAN 20")
    returnStructure =switch.DeviceInteract(command="vlan 20")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to enter interface context for vlan"

    returnStructure =switch.DeviceInteract(command="no shutdown")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no shut"
    returnStructure = switch.DeviceInteract(command="exit")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to exit vlan"

    # Add interface 1 to vlan 10
    LogOutput('info', "Configuring interface %d to VLAN 10" % interface1)
    returnStructure =switch.DeviceInteract(command="interface %d" % interface1)
    retCode = returnStructure['returnCode']
    assert returnCode==0, "Failed to enter interface context"

    returnStructure =switch.DeviceInteract(command="no routing")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no shut"

    returnStructure =switch.DeviceInteract(command="no shutdown")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no shut"

    returnStructure =switch.DeviceInteract(command="vlan access 10")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform vlan access"

    returnStructure = switch.DeviceInteract(command="exit")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to exit interface"

    # Add interface 2 to vlan 10
    LogOutput('info', "Configuring interface %d to VLAN 10" % interface2)
    returnStructure =switch.DeviceInteract(command="interface %d" % interface2)
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to enter interface context"

    returnStructure =switch.DeviceInteract(command="no routing")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no routing"

    returnStructure =switch.DeviceInteract(command="vlan access 10")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform vlan access"

    returnStructure = switch.DeviceInteract(command="exit")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to exit interface"

    # Add interface 3 to vlan 20
    LogOutput('info', "Configuring interface %d to VLAN 20" % interface3)
    returnStructure =switch.DeviceInteract(command="interface %d" % interface3)
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to enter interface context"

    returnStructure =switch.DeviceInteract(command="no routing")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no routing"

    returnStructure =switch.DeviceInteract(command="no shutdown")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no shut"

    returnStructure =switch.DeviceInteract(command="vlan access 20")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform vlan access"

    returnStructure = switch.DeviceInteract(command="exit")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to exit interface"

    # TODO: Why is "enter=False"?
    returnStructure = switch.ConfigVtyShell(enter=False)
    returnCode = returnStructure.returnCode()
    assert returnCode==0, "Failed to exit vtysh config prompt"

    # TODO: Why is "enter=False"?
    returnStructure = switch.VtyshShell(enter=False)
    returnCode = returnStructure.returnCode()
    assert returnCode==0, "Failed to exit vtysh prompt"

    LogOutput('info', "Configuring ipv4 address 10.0.0.1 on interface vlan10")
    retStruct = InterfaceIpConfig(deviceObj=switch, vlan=10, addr="10.0.0.1", mask=24, config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address on vlan address"

    LogOutput('info', "Configuring ipv6 address 1000::1 on interface vlan10")
    retStruct = InterfaceIpConfig(deviceObj=switch, vlan=10, addr="1000::1", mask=120, ipv6flag=True, config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address on vlan"

    LogOutput('info', "Configuring ipv4 address 11.0.0.1 on interface vlan20")
    retStruct = InterfaceIpConfig(deviceObj=switch, vlan=20, addr="11.0.0.1", mask=24, config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address on vlan address"

    LogOutput('info', "Configuring ipv6 address 2000::1 on interface vlan20")
    retStruct = InterfaceIpConfig(deviceObj=switch, vlan=20, addr="2000::1", mask=120, ipv6flag=True, config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address on vlan"



    #Configure host 1

    # TODO: Isn't broadcast address 10.0.0.255?
    LogOutput('info',"\n\n\nConfiguring host 1 ipv4")
    retStruct = host1.NetworkConfig(ipAddr="10.0.0.2", netMask="255.255.255.0", interface=host1.linkPortMapping['lnk01'], broadcast="10.255.255.255", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address"

    LogOutput('info',"\n\n\nConfiguring host 1 ipv6")
    retStruct = host1.Network6Config(ipAddr="1000::2", netMask=120, interface=host1.linkPortMapping['lnk01'], broadcast="1000::0", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address"

    retStruct = host1.DeviceInteract(command="ifconfig eth1 down")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to shutdown eth1 on host1")
        caseReturnCode = 1

    retStruct = host1.DeviceInteract(command="ifconfig eth1 hw ether 00:01:02:03:04:05")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure mac-addr on host1")
        caseReturnCode = 1

    retStruct = host1.DeviceInteract(command="ifconfig eth1 up")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to bring up eth1 on host1")
        caseReturnCode = 1

    # Configure a default IPv4 route
    retStruct = host1.IPRoutesConfig(config=True, destNetwork="0.0.0.0", netMask=24, gateway="10.0.0.1")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv4 address route")
        caseReturnCode = 1

    # Configure a default routes for IPv6
    retStruct = host1.IPRoutesConfig(config=True, destNetwork="::", netMask=120, gateway="1000::1", ipv6Flag=True)
    retCode = retStruct.returnCode()
    if retCode:
         LogOutput('error', "\nFailed to configure ipv6 address route")
         caseReturnCode = 1

    #Configure host 2

    LogOutput('info',"\n\n\nConfiguring host 2 ipv4")
    retStruct = host2.NetworkConfig(ipAddr="10.0.0.3", netMask="255.255.255.0", interface=host2.linkPortMapping['lnk02'], broadcast="10.255.255.255", config=True )
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address"

    LogOutput('info',"\n\n\nConfiguring host 2 ipv6")
    retStruct = host2.Network6Config(ipAddr="1000::10", netMask=120, interface=host2.linkPortMapping['lnk02'], broadcast="1000::0", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address"

    retStruct = host2.DeviceInteract(command="ifconfig eth1 down")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to shutdown eth1 on host2")
        caseReturnCode = 1

    retStruct = host2.DeviceInteract(command="ifconfig eth1 hw ether 00:01:02:03:04:05")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure mac-addr on host2")
        caseReturnCode = 1

    retStruct = host2.DeviceInteract(command="ifconfig eth1 up")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to bring up eth1 on host2")
        caseReturnCode = 1

    retStruct = host2.IPRoutesConfig(config=True, destNetwork="0.0.0.0", netMask=24, gateway="10.0.0.1")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv4 address route")
        caseReturnCode = 1

    retStruct = host2.IPRoutesConfig(config=True, destNetwork="::", netMask=120, gateway="1000::1", ipv6Flag=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv6 address route")
        caseReturnCode = 1


    #Configure host 3

    LogOutput('info',"\n\n\nConfiguring host 3 ipv4")
    retStruct = host3.NetworkConfig(ipAddr="11.0.0.2", netMask="255.255.255.0", interface=host3.linkPortMapping['lnk03'], broadcast="20.255.255.255", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address"

    LogOutput('info',"\n\n\nConfiguring host 3 ipv6")
    retStruct = host3.Network6Config(ipAddr="2000::10", netMask=120, interface=host3.linkPortMapping['lnk03'], broadcast="2000::0", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address"

    retStruct = host3.IPRoutesConfig(config=True, destNetwork="0.0.0.0", netMask=24, gateway="11.0.0.1")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv4 address route")
        caseReturnCode = 1

    retStruct = host3.IPRoutesConfig(config=True, destNetwork="::", netMask=120, gateway="2000::1", ipv6Flag=True)
    retCode = retStruct.returnCode()
    if retCode:
       LogOutput('error', "\nFailed to configure ipv6 address route")
       caseReturnCode = 1



    # TEST: IPv4 ping from host 1 to host 3
    LogOutput('info',"\n\n\nTEST: IPv4 ping from host1 to host3")
    retStruct = host1.Ping(ipAddr="11.0.0.2", packetCount=1)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv4 ping, Case Failed #####"
    LogOutput('info',"\n##### Ping Passed, Case Passed #####\n\n")

    LogOutput('info',"\n\n\nTEST: IPv6 ping from host1 to default gateway")
    retStruct = host1.Ping(ipAddr="1000::1", packetCount=1)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv6 ping to gateway, Case Failed #####"
    LogOutput('info',"\n##### Ping Passed, Case Passed #####\n\n")

    LogOutput('info',"\n\n\nTEST: IPv6 ping from host1 to host3")
    retStruct = host1.Ping(ipAddr="2000::2", packetCount=1)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv6 ping to host3, Case Failed #####"
    LogOutput('info',"\n##### Ping Passed, Case Passed #####\n\n")

    # TODO: shutdown interface 1 on switch and no-shut interface 2.
    #       Ping from host 2 to host 3
    LogOutput('info', "Shutdown interface1 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=False, interface=switch.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to shutdown interface1 on switch1"

    LogOutput('info', "no-shutdown interface2 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=True, interface=switch.linkPortMapping['lnk02'])
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to no-shutdown interface2 on switch1"

    # TEST: Ping from host 2 to host 3
    LogOutput('info',"\n\n\nTEST: IPv4 ping from host2 to host3")
    retStruct = host2.Ping(ipAddr="11.0.0.2", packetCount=1)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv4 ping, Case Failed #####"
    LogOutput('info',"\n##### Ping Passed, Case Passed #####\n\n")

    LogOutput('info',"\n\n\nTEST: IPv6 ping from host2 to host3")
    retStruct = host1.Ping(ipAddr="2000::10", packetCount=1, ipv6Flag=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv6 ping, Case Failed #####"
    LogOutput('info',"\n##### Ping Passed, Case Passed #####\n\n")

class Test_mac_move:
    def setup_class (cls):
        # Test object will parse command line and formulate the env
        Test_mac_move.testObj = testEnviron(topoDict=topoDict)
        #    Get topology object
        Test_mac_move.topoObj = Test_mac_move.testObj.topoObjGet()
    def teardown_class (cls):
        Test_mac_move.topoObj.terminate_nodes()

    def test_mac_move(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        wrkston01Obj = self.topoObj.deviceObjGet(device="wrkston01")
        wrkston02Obj = self.topoObj.deviceObjGet(device="wrkston02")
        wrkston03Obj = self.topoObj.deviceObjGet(device="wrkston03")
        mac_move(switch=dut01Obj, host1=wrkston01Obj, host2=wrkston02Obj, host3=wrkston03Obj)
