#!/usr/bin/python

# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
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
            "topoDevices": "dut01",
            "topoFilters": "dut01:system-category:switch"}


def ecmp_resilient_check_status(switch, is_enabled):

    appctl_command = "ovs-appctl plugin/debug l3ecmp"
    retStruct = switch.DeviceInteract(command=appctl_command)
    if (is_enabled):
        ecmp_res_status = 'TRUE'
        ecmp_dynamic_size = 512
    else:
        ecmp_res_status = 'FALSE'
        ecmp_dynamic_size = 0

    buf = retStruct.get('buffer')
    for curLine in buf.split('\n'):
        if "ECMP Resilient" in curLine:
            str_tok = curLine.split()
            if str_tok[2] != ecmp_res_status\
                LogOutput("error", "ECMP %s resilient not working properly" %
                                   (log_ip_str))
        if "dynamic size" in curLine:
            str_tok = curLine.split()
            if str_tok[2] != ecmp_dynamic_size\
                LogOutput("error", "ECMP %s resilient not working properly" %
                                   (log_ip_str))


def ecmp_resilient_test(**kwargs):

    switch = kwargs.get('switch', None)

    switch.VtyshShell(enter=True)
    switch.ConfigVtyShell(enter=True)
    switch.DeviceInteract(command="ip ecmp load-balance resilient disable")
    switch.ConfigVtyShell(enter=False)
    switch.VtyshShell(enter=False)

    ecmp_resilient_check_status(switch, False)

    switch.VtyshShell(enter=True)
    switch.ConfigVtyShell(enter=True)
    switch.DeviceInteract(command="no ip ecmp load-balance resilient disable")
    switch.ConfigVtyShell(enter=False)
    switch.VtyshShell(enter=False)

    ecmp_resilient_check_status(switch, True)


class Test_ecmp_resilient_ct:

    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_ecmp_resilient_ct.testObj = testEnviron(topoDict=topoDict)
        # Get topology object
        Test_ecmp_resilient_ct.topoObj = Test_ecmp_resilient_ct.testObj.topoObjGet()

    def teardown_class(cls):
        Test_ecmp_resilient_ct.topoObj.terminate_nodes()

    def test_ecmp_resilient_ct(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        retValue = ecmp_resilient_test(switch=dut01Obj)
        if retValue != 0:
            assert "Test failed"
        else:
            LogOutput('info', "\n### Test Passed ###\n")
