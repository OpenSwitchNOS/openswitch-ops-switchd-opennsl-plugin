# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
# GNU Zebra is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.
#
# GNU Zebra is distributed in the hope that it will be useful, but
# WITHoutput ANY WARRANTY; withoutput even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Zebra; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

from time import sleep
from random import randint

# Topology definition. the topology contains two back to back switches
# having two links between them.


TOPOLOGY = """
# +-------+
# |  sw2  |
# +---^---+
#     |
#     |
# +---v---+       +-------+
# |  sw1  <------->  hs1  |
# +-------+       +-------+


# Nodes
[type=openswitch name="Switch 1"] sw1
[type=openswitch name="Switch 2"] sw2
[type=host name="Host 1"] hs1

# Links
sw1:if01 -- sw2:if01
sw1:if02 -- sw2:if02
sw1:if03 -- hs1:eth1
"""


# Two ECMP nexthops are configured and two separate flows are sent through the
# ECMP links. Different ECMP hash methods are configured and the test confirms
# that the flows pick different nexthops based on the 4-tuples in the flow.
# The 4-tuples for the flows are selected manually today based on trial and
# error, but the right way would be to select the tuples by using  ASIC APIs
# that calculate nexthop link for an input tuple.
# Note: There is a possibility that the tuples this script uses would not
# cause the ASIC to pick different nexthops when ECMP configuration changes
# in the future or for different ASICs. We should use the ASIC APIs to pick
# the right tuples programatically.

sw1 = None
sw2 = None
hs1 = None
intf1sw1 = ""
intf2sw1 = ""
intf1sw2 = ""
intf2sw2 = ""
num_pkts = ""
intf3sw1 = ""

# NOT supported yet
"""
def switch_reboot(sw1):
    # Reboot switch
    step("Reboot switch")
    sw1.Reboot()
    rebootRetStruct = returnStruct(returnCode=0)
    return rebootRetStruct
"""


def get_tx_stats(sw, intf1, intf2):
    intf1_stats = sw.libs.vtysh.show_interface(intf1)
    intf2_stats = sw.libs.vtysh.show_interface(intf2)
    tx1 = intf1_stats['tx_packets']
    tx2 = intf2_stats['tx_packets']
    return tx1, tx2


# If txstop has atleast 70% of num pkts sent, then pick that as the selected
# interface
def get_selected_intf(tx1start, tx1stop, tx2start, tx2stop, num_pkts, intf1,
                      intf2):
    selected_intf = "None"
    if (tx1stop > (tx1start + (num_pkts * .7))):
        selected_intf = intf1
    if (tx2stop > (tx2start + (num_pkts * .7))):
        selected_intf = intf2
    return selected_intf


def enable_ecmp_hash(sw, hashmethod):
    with sw.libs.vtysh.Configure() as cnf:
        if hashmethod == "src-ip":
            cnf.no_ip_ecmp_load_balance_src_ip_disable()
        elif hashmethod == "dst-ip":
            cnf.no_ip_ecmp_load_balance_dst_ip_disable()
        elif hashmethod == "src-port":
            cnf.no_ip_ecmp_load_balance_src_port_disable()
        elif hashmethod == "dst-port":
            cnf.no_ip_ecmp_load_balance_dst_port_disable()


def disable_ecmp_hash(sw, hashmethod):
    with sw.libs.vtysh.Configure() as cnf:
        if hashmethod == "src-ip":
            cnf.ip_ecmp_load_balance_src_ip_disable()
        elif hashmethod == "dst-ip":
            cnf.ip_ecmp_load_balance_dst_ip_disable()
        elif hashmethod == "src-port":
            cnf.ip_ecmp_load_balance_src_port_disable()
        elif hashmethod == "dst-port":
            cnf.ip_ecmp_load_balance_dst_port_disable()


def disable_all_ecmp_hash(sw):
    with sw.libs.vtysh.Configure() as cnf:
        cnf.ip_ecmp_load_balance_src_ip_disable()
        cnf.ip_ecmp_load_balance_dst_ip_disable()
        cnf.ip_ecmp_load_balance_src_port_disable()
        cnf.ip_ecmp_load_balance_dst_port_disable()


def enable_all_ecmp_hash(sw):
    with sw.libs.vtysh.Configure() as cnf:
        cnf.no_ip_ecmp_load_balance_src_ip_disable()
        cnf.no_ip_ecmp_load_balance_dst_ip_disable()
        cnf.no_ip_ecmp_load_balance_src_port_disable()
        cnf.no_ip_ecmp_load_balance_dst_port_disable()


def run_nexthop_calc(sw, intf1, intf2,
                     srcport1, dstip1, dstport1,
                     srcport2, dstip2, dstport2, step):
    tx1start, tx2start = get_tx_stats(sw, intf1, intf2)
    send_udp_packets(srcport1, dstip1, dstport1, num_pkts)
    sleep(10)
    tx1stop, tx2stop = get_tx_stats(sw, intf1, intf2)

    selected_intf1 = get_selected_intf(tx1start, tx1stop, tx2start, tx2stop,
                                       num_pkts, intf1, intf2)
    step("Nexthop interface for (" + str(srcport1) + ", " +
         dstip1 + ", " + str(dstport1) + ") is " + selected_intf1)

    tx1start, tx2start = get_tx_stats(sw, intf1, intf2)
    send_udp_packets(srcport2, dstip2, dstport2, num_pkts)
    sleep(10)
    tx1stop, tx2stop = get_tx_stats(sw, intf1sw1, intf2sw1)

    selected_intf2 = get_selected_intf(tx1start, tx1stop, tx2start, tx2stop,
                                       num_pkts, intf1, intf2)
    step("Nexthop interface for (" + str(srcport2) + ", " +
         dstip2 + ", " + str(dstport2) + ") is " + selected_intf2)
    return selected_intf1, selected_intf2


# Send some UDP packets with the given srcport, dstport, dstip, numpkts.
# Quite hacky way of doing this, but generate a python socket program to
# send packets, save the program to host filesystem and execute it. Any better
# way to do this? host iperf doesn't seem to support changing source port
# or to sent a specified number of packets. Also, this method does not require
# an iperf server to be configured and running on another host.
def send_udp_packets(src_port, dst_ip, dst_port, num_pkts):
        filename = "/tmp/testfile{}".format(randint(1, 1000))
        cmd = """echo -e \"
#!/usr/bin/env python3
import socket
import sys
import time
message = 'Hello OpenSwitch.'
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_address = ('0.0.0.0', {src_port})
sock.bind(client_address)
server_address = ('{dst_ip}\', {dst_port})
for x in range(0, {num_pkts}):
   sock.sendto(message.encode(), server_address)
   time.sleep(0.1)
\" >  {filename}""".format(**locals())
        hs1(cmd)
        hs1("sed -i '1d' {}".format(filename))
        hs1("chmod +x {}".format(filename))
        hs1(filename)
        hs1("rm -f {}".format(filename))


# NOT supported yet
"""
def clean_up(sw1, sw2):
    list_dut = [sw1, sw2]
    for currentDut in list_dut:
        devRebootRetStruct = switch_reboot(currentDut)
        if devRebootRetStruct.returnCode() != 0:
            LogOutput('error', "Failed to reboot Switch")
            assert(False)
    else:
        step("Passed Switch Reboot ")
"""


##########################################################################
# Step 2 - Configure the switches
##########################################################################


def configure_switches(step):

    step("\n###############################################")
    step("# Step 1 - Configure ecmp routes in the switches")
    step("################################################")
    # Switch configuration

    with sw1.libs.vtysh.ConfigInterface('if01') as cnf:
        cnf.no_shutdown()
        cnf.ip_address("100.0.0.1/24")

    with sw1.libs.vtysh.ConfigInterface('if02') as cnf:
        cnf.no_shutdown()
        cnf.ip_address("200.0.0.1/24")

    with sw1.libs.vtysh.ConfigInterface('if03') as cnf:
        cnf.no_shutdown()
        cnf.ip_address("10.0.0.2/24")

    with sw2.libs.vtysh.ConfigInterface('if01') as cnf:
        cnf.no_shutdown()
        cnf.ip_address("100.0.0.2/24")

    with sw2.libs.vtysh.ConfigInterface('if02') as cnf:
        cnf.no_shutdown()
        cnf.ip_address("200.0.0.2/24")

    with sw1.libs.vtysh.Configure() as cnf:
        cnf.ip_route("30.0.0.0/24", "100.0.0.2")
        cnf.ip_route("30.0.0.0/24", "200.0.0.2")

    hs1.libs.ip.interface("eth1", "10.0.0.4/24", up=True)
    hs1.libs.ip.add_route("30.0.0.0/24", "10.0.0.2")


def disable_all_hash(step):
    step("\n###############################################")
    step("# Step 2 - Test disable all hash")
    step("################################################")

    disable_all_ecmp_hash(sw1)
    intf1, intf2 = run_nexthop_calc(sw1, intf1sw1, intf2sw1,
                                    10024, "30.0.0.1", 10024,
                                    10023, "30.0.0.4", 10023, step)

    assert intf1 == intf2, "Disable all hashing failed"


def l4src_hash(step):
    step("\n###############################################")
    step("# Step 3 - Test src port hash")
    step("################################################")
    step("Step 3.II - Test disable src port hash")

    disable_ecmp_hash(sw1, "src-port")
    intf1, intf2 = run_nexthop_calc(sw1, intf1sw1, intf2sw1,
                                    10024, "30.0.0.1", 10024,
                                    10023, "30.0.0.1", 10024, step)

    assert intf1 == intf2, "src port hashing failed"


def l4dst_hash(step):
    step("\n###############################################")
    step("# Step 4 - Test dst port hash")
    step("################################################")
    step("Step 4.II - Test disable dst port hash")

    disable_ecmp_hash(sw1, "dst-port")
    intf1, intf2 = run_nexthop_calc(sw1, intf1sw1, intf2sw1,
                                    10024, "30.0.0.1", 10024,
                                    10024, "30.0.0.1", 10023, step)

    assert intf1 == intf2, "dst port hashing failed"


def l3dst_hash(step):
    step("\n###############################################")
    step("# Step 5 - Test dest IP hash")
    step("################################################")
    step("Step 5.II - Test disable dst IP hash")

    disable_ecmp_hash(sw1, "dst-ip")
    intf1, intf2 = run_nexthop_calc(sw1, intf1sw1, intf2sw1,
                                    10024, "30.0.0.1", 10024,
                                    10024, "30.0.0.4", 10024, step)

    assert intf1 == intf2, "dst IP hashing failed"


def l3src_hash(step):
    step("\n###############################################")
    step("# Step 6 - Test src IP hash")
    step("################################################")

    enable_all_ecmp_hash(sw1)
    tx1start, tx2start = get_tx_stats(sw1, intf1sw1, intf2sw1)
    send_udp_packets(10024, "30.0.0.1", 10024, num_pkts)
    sleep(10)
    tx1stop, tx2stop = get_tx_stats(sw1, intf1sw1, intf2sw1)
    intf1 = get_selected_intf(tx1start, tx1stop, tx2start, tx2stop,
                              num_pkts, intf1sw1, intf2sw1)
    step("Nexthop interface for (" + str(10024) + ", " +
         "src:10.0.0.4" + ", " + str(10024) + ") is " + intf1)

    hs1.libs.ip.interface("eth1", "10.0.0.1/24", up=True)

    tx1start, tx2start = get_tx_stats(sw1, intf1sw1, intf2sw1)
    send_udp_packets(10024, "30.0.0.1", 10024, num_pkts)
    sleep(10)
    tx1stop, tx2stop = get_tx_stats(sw1, intf1sw1, intf2sw1)
    intf2 = get_selected_intf(tx1start, tx1stop, tx2start, tx2stop,
                              num_pkts, intf1sw1, intf2sw1)
    step("Nexthop interface for (" + str(10024) + ", " +
         "src:10.0.0.1" + ", " + str(10024) + ") is " + intf2)

    step("Step 6.II - Test disable src IP hash")

    disable_ecmp_hash(sw1, "src-ip")
    tx1start, tx2start = get_tx_stats(sw1, intf1sw1, intf2sw1)
    send_udp_packets(10024, "30.0.0.1", 10024, num_pkts)
    sleep(10)
    tx1stop, tx2stop = get_tx_stats(sw1, intf1sw1, intf2sw1)
    intf1 = get_selected_intf(tx1start, tx1stop, tx2start, tx2stop,
                              num_pkts, intf1sw1, intf2sw1)
    step("Nexthop interface for (" + str(10024) + ", " +
         "src:10.0.0.1" + ", " + str(10024) + ") is " + intf1)

    tx1start, tx2start = get_tx_stats(sw1, intf1sw1, intf2sw1)
    send_udp_packets(10024, "30.0.0.1", 10024, num_pkts)
    sleep(10)
    tx1stop, tx2stop = get_tx_stats(sw1, intf1sw1, intf2sw1)
    intf2 = get_selected_intf(tx1start, tx1stop, tx2start, tx2stop,
                              num_pkts, intf1sw1, intf2sw1)
    step("Nexthop interface for (10024, "
         "src:10.0.0.4, 10024) is " + intf2)
    assert intf1 == intf2, "disabling src IP hashing failed"


def test_layer3_ft_ecmp_hash(topology, step):
    global list_dut
    global sw1
    global sw2
    global hs1
    global intf1sw1
    global intf2sw1
    global intf1sw2
    global intf2sw2
    global num_pkts
    global intf3sw1

    sw1 = topology.get("sw1")
    assert sw1 is not None
    sw2 = topology.get("sw2")
    assert sw2 is not None
    hs1 = topology.get("hs1")
    assert hs1 is not None
    intf1sw1 = 'if01'
    intf2sw1 = 'if02'
    intf3sw1 = 'if03'
    intf1sw2 = 'if01'
    intf2sw2 = 'if02'
    num_pkts = 100

    list_dut = [sw1, sw2]

    configure_switches(step)
    disable_all_hash(step)
    l4src_hash(step)
    enable_all_ecmp_hash(sw1)
    l4dst_hash(step)
    enable_all_ecmp_hash(sw1)
    l3dst_hash(step)
    enable_all_ecmp_hash(sw1)
    l3src_hash(step)
