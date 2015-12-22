Copp (Control plane policing) Feature Test Cases
________________________________________________
________________________________________________

The (CoPP) control plane policing feature on openswitch limits the number of
control plane packets destined for CPU of a switch or a router. Control plane
packets  are defined as the packets which are meant to be processed or consumed
by the routing processesor. Different control plane packets can be rate limited
so that these control plane packets are pushed to CPU only at the programmed
or configured rate. If the control plane packets arrive at a rate which is
higher than the rate specified for that control plane packet, then the
packets are dropped in hardware. Along with the rate, the Copp feature also
allows a burst of packets to be allowed to be pushed to CPU. The number of
control plane packets received by the CPU are usually measured by linux tools
like tcpdump or tshark.

## Contents

- [Testing the Broadcom qualifiers to qualify the different control packet
   types]
- [Testing the control packet rates]
- [Testing the control packet burst]
- [Tuning system performance for tuning control packet rates and burst]

## Testing the Broadcom qualifiers to qualify the different control packet
   types.

### Objective
This test verifies that control plane packet qualifiers are correctly
identified and programmed in the hardware.

### Requirements
- Physical switch/workstations test setup

### Setup
#### Topology diagram
```ditaa

                                |                                   |
                 _______________|_________________       ___________|_________
                |        (123.0.0.1/24)          |       |    (143.0.0.1/24)  |
 ______         |         interface 3            |       |      interface 3   |
|      |        |                                |       |                    |
|      |        | (10.1.1.1/24)   (10.1.2.1/24)) |       |       (Device2)    |
|(Ixia)|--------| interface 1      interface 2   |-------|(10.1.2.2/24)       |
|______|        |                                |       | interface 1        |
                |                                |       |                    |
                |         (Device1)              |       |     (10.1.3.1/24)  |
                |                                |       |     (interface 2)  |
                |________________________________|       |____________________|
                                                                   |
                                                            _______|________
                                                           |  10.1.3.2/24   |
                                                           |    eth0        |
                                                           |                |
                                                           |    (Host)      |
                                                           |________________|
```

### Description
This test ensures that the field programmable rules for control packets are
correctly identified and programmed in the hardware. For different control
packet streams from Ixia, the 'tcpdump' command on either Device1, Device2
or the host should give the appropriate output. For example, BGP packets for
Device1 should have the destination IP address of either 123.0.0.1, 10.1.1.1
or 10.1.2.1, should be encapsulated in TCP packet and should be destined for
L4 port 179. When such a packet stream is formed from Ixia and BGP packets are
generated, the 'tcpdump' command on Device1 should dump the details of the BGP
packets that are received. The 'tcpdump' on Device2 should not dump any output.
Similarily, BGP packets destined for Device2 should not cause 'tcpdump' command
on Device1 to show any output. 'tcpdump' on Device2 should dump output in this
case. Moreover, the control packets destined to CPU should be directed to their
respective CPU queues. The appctl commands would be used to dump the number of
packets queued on a given CPU queue. The CPU queue number for the control
packets should be as per the table given in appendix.

1.  Setup the topology as shown in the figure.
2.  Configure static routes on Device1 to reach subnets 10.1.2.0/24,
    10.1.3.0/24 and 143.0.0.0/24.
3.  Configure static routes on Device2 to reach subnets 10.1.3.0/24.
4.  Run TCP dump on Device1, Device2 and Host as
    "tcpdump tcp -i 2 dst port 179"
5.  Generate BGP packets from Ixia which are destined to Device1.
    Generate using L4 destination port 179, destination IP address
    as 123.0.0.1, 10.1.1.1 or 10.1.2.1 and L4 protocol as TCP.
6.  The "tcpdump" on Device1 should show some output. The "tcpdump"
    command on Device2 and Host should not show any output. Execute the
    appctl command to dump the queue stats on queue 0 (refer to table in
    appendix) to verify that the BGP packets were queued in CPU queue 0.
7.  Generate BGP packets from Ixia which are destined to Device2.
    Generate using L4 destination port 179, destination IP address
    as 143.0.0.1, 10.1.3.1 and L4 protocol as TCP.
8.  The "tcpdump" on Device1 and Host should not show any output. The
    "tcpdump" command on Device2 should show some output.
9.  Generate BGP packets from Ixia which are destined to Host.
    Generate using L4 destination port 179, destination IP address
    as 10.1.3.2 and L4 protocol as TCP.
10. The "tcpdump" on Device1 and Device2 should not show any output.
11. Change L4 destination port for BGP packets from 179 to any other
    value. The "tcpdump" tool should not show any output on Device1
    and Device2. The queue counters using the appctl command for
    queue 0 should not increment on either Device1 or Device2. The
    appctl counters for the default queue (queue 42) should get
    incremented.
12. Change L4 protocol for BGP packets from TCP to UDP
    value. The "tcpdump" tool should not show any output on Device1
    and Device2. The queue counters using the appctl command for
    queue 0 should not increment on either Device1 or Device2. The
    appctl counters for the default queue (queue 42) should get
    incremented.
13. Repeat steps 1-12 for the packets types given in the appendix.

#### Test fail criteria
If the "tcpdump" output is not expected as per steps 6, 8, 10, 11 and 12,
then the test case is deemed to have failed otherwise the test case is deemed
to have passed.


## Testing the control packet rates

### Objective
This test verifies the rate at which different control packets are delivered
to the CPU at the specified rate.

### Requirements
- Physical switch/workstations test setup

### Setup
#### Topology diagram
```ditaa
                                |
                 _______________|_________________       _____________________
                |        (123.0.0.1/24)          |       |                    |
 ______         |         interface 3            |       |                    |
|      |        | (10.1.1.1/24)   (10.1.2.1/24)) |       |       (Host)       |
|(Ixia)|--------| interface 1      interface 2   |-------|(10.1.2.2/24)       |
|______|        |                                |       | eth0               |
                |         (Device1)              |       |                    |
                |                                |       |                    |
                |________________________________|       |____________________|
```
### Description
This test ensures that the control packets that are pushed to the CPU are rate
limited. For example, if the BGP control packets are rate limited at
200 packets/second by the CoPP feature, then the no more than
200 packets/second should be delivered to CPU. The "tcpdump" command should
not display more than 200 BGP packets/second. The number of BGP packets
captured by "tcpdump" command should be averaged over few seconds before
computing the rate at which the BGP packets were captured by "tcpdump".

1.  Setup the topology as shown in the figure.
2.  Configure static routes on Device1 to reach subnets 10.1.2.0/24,
    10.1.3.0/24 and 143.0.0.0/24.
3.  Run TCP dump on Device1 and Host as "tcpdump tcp -i 2 dst port 179"
4.  Generate BGP packets from Ixia which are destined to Device1. Generate
    using L4 destination port 179, destination IP address as 123.0.0.1,
    10.1.1.1 or 10.1.2.1 and L4 protocol as TCP. Set the BGP packet rate
    from Ixia to be higher than the supported rate for BGP packets.
5.  The "tcpdump" on Device1 should show BGP packets at the supported rate.
    Average the rate for BGP packets over few seconds.
6.  Generate BGP packets from Ixia which are destined to Device1. Generate
    using L4 destination port 179, destination IP address as 123.0.0.1,
    10.1.1.1 or 10.1.2.1 and L4 protocol as TCP. Set the BGP packet rate
    from Ixia to be lower than the supported rate for BGP packets.
7.  The "tcpdump" on Device1 should show BGP packets at the rate at which they
    are being generated from Ixia.
8.  Generate BGP packets from Ixia which are destined to Device1. Generate
    using L4 destination port 179, destination IP address as 123.0.0.1,
    10.1.1.1 or 10.1.2.1 and L4 protocol as TCP. Set the BGP packet rate
    from Ixia to be equal to the supported rate for BGP packets.
9.  The "tcpdump" on Device1 should show BGP packets at the supported rate.
    Average the rate for BGP packets over few seconds.
10. Repeat steps 1-9 for all the packets types and their respective rates
    given in the appendix.

#### Test fail criteria
If the "tcpdump" output is not expected as per steps 5, 7 and 9, then the test
case is deemed to have failed otherwise the test case is deemed to have
passed.

## Testing the control packet burst

### Objective
This test verifies the rate at which different control packets are delivered
to the CPU at the specified burst.

### Requirements
- Physical switch/workstations test setup

### Setup
#### Topology diagram
```ditaa
                                |
                 _______________|_________________       _____________________
                |        (123.0.0.1/24)          |       |                    |
 ______         |         interface 3            |       |                    |
|      |        | (10.1.1.1/24)   (10.1.2.1/24)) |       |       (Host)       |
|(Ixia)|--------| interface 1      interface 2   |-------|(10.1.2.2/24)       |
|______|        |                                |       | eth0               |
                |         (Device1)              |       |                    |
                |                                |       |                    |
                |________________________________|       |____________________|
```
### Description
This test ensures that the control packets that are pushed to the CPU at the
specified burst size. This test case is applicable to bursty traffic. For example,
if the BGP control packets are rate limited at 200 packets/second and a burst
of 400 packets by the CoPP feature, then the no more than 400 packets should be
delivered to CPU for a given BGP packet burst. The "tcpdump" command should
not display more than 400 BGP packets/second for the packet burst. The number
of BGP packets captured by "tcpdump" command for a given burst size should be
averaged over many such bursts of BGP packets.

1.  Setup the topology as shown in the figure.
2.  Configure static routes on Device1 to reach subnets 10.1.2.0/24,
    10.1.3.0/24 and 143.0.0.0/24.
3.  Run TCP dump on Device1 and Host as "tcpdump tcp -i 2 dst port 179"
4.  Generate BGP packets from Ixia which are destined to Device1. Generate
    using L4 destination port 179, destination IP address as 123.0.0.1,
    10.1.1.1 or 10.1.2.1 and L4 protocol as TCP. Set the BGP packet stream
    to bursty with the burst size higher than the supported burst size for
    BGP packets in Ixia. Set the bursty BGP packet stream to be periodic.
5.  The "tcpdump" on Device1 should show BGP packets at the supported burst.
    Average the burst for BGP packets over few seconds.
6.  Generate BGP packets from Ixia which are destined to Device1. Generate
    using L4 destination port 179, destination IP address as 123.0.0.1,
    10.1.1.1 or 10.1.2.1 and L4 protocol as TCP. Set the BGP packet stream
    to bursty with the burst size lower than the supported burst size for
    BGP packets in Ixia. Set the bursty BGP packet stream to be periodic.
7.  The "tcpdump" on Device1 should show BGP packets at the burst at which
    they are being generated from Ixia. Average the burst for BGP packets
    over few seconds.
8.  Generate BGP packets from Ixia which are destined to Device1. Generate
    using L4 destination port 179, destination IP address as 123.0.0.1,
    10.1.1.1 or 10.1.2.1 and L4 protocol as TCP. Set the BGP packet stream
    to bursty with the burst size equal to the supported burst size for
    BGP packets in Ixia. Set the bursty BGP packet stream to be periodic.
9.  The "tcpdump" on Device1 should show BGP packets at the burst at which
    they are being generated from Ixia. Average the burst for BGP packets
10. Repeat steps 1-9 for all the packets types and their respective rates
    given in the appendix.

#### Test fail criteria
If the "tcpdump" output is not expected as per steps 5, 7 and 9, then the test
case is deemed to have failed otherwise the test case is deemed to have
passed.


## Tuning system performance for tuning control packet rates and burst

### Objective
This test will help in tuning the rate and burst paramters of the Copp feature
according to the CPU utilization.

### Requirements
- Physical switch/workstations test setup

### Setup
#### Topology diagram
```ditaa
                                |                                   |
                 _______________|_________________       ___________|_________
                |        (123.0.0.1/24)          |       |    (143.0.0.1/24)  |
 ______         |         interface 3            |       |      interface 3   |
|      |        |                                |       |                    |
|      |        | (10.1.1.1/24)   (10.1.2.1/24)) |       |       (Device2)    |
|(Ixia)|--------| interface 1      interface 2   |-------|(10.1.2.2/24)       |
|______|        |                                |       | interface 1        |
                |                                |       |                    |
                |         (Device1)              |       |     (10.1.3.1/24)  |
                |                                |       |     (interface 2)  |
                |________________________________|       |____________________|
                                                                   |
                                                            _______|________
                                                           |  10.1.3.2/24   |
                                                           |    eth0        |
                                                           |                |
                                                           |    (Host)      |
                                                           |________________|

```

### Description
TBD

#### Test fail criteria
TBD

## Appendix
Rules to identify the various control packets destined to the local routing
processor.

    Control Packet Type               Identification Criteria                 CPU Queue   Rate  Burst
------------------------------------------------------------------------------------------------------
    a.  Broadcast ARP                 - Check ether type as 0x0806               12       100    100
                                      - Check whether the destination
                                        MAC is broadcast

    b.  Unicast ARP                   - Check ether type as 0x0806               18       100    100
                                      - Check whether the destination MAC
                                        is unicast

    c.  BGP (IPv4/IPV6)               - Check if the packet has L4 port as        0       100    100
                                        179.
                                      - Check if the destination IPv4/IPv6
                                        address is a local address.
                                      - Check if the Layer-4 protocol is TCP

    d.  BGP+ (IPv4/IPV6)              - Check if the packet has L4 port as        0       100    100
                                        179.
                                      - Check if the destination IPv4/IPv6
                                        address is a local address.
                                      - Check if the Layer-4 protocol is TCP

    e.  DHCP (client/server)          - Check if the packet has L4 port as       13       100    100
                                        68/67.
                                      - Check if the destination IPv4 address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP


    f.  DHCPv6 (client/server)        - Check if the packet has L4 port as       14       100    100
                                        546/547.
                                      - Check if the destination IPv6 address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP

    g.  GMRP
    h.  GVRP

    i.  HTTP (IPv4/IPV6)              - Check if the packet has L4 port as 80.   30       100    100
                                      - Check if the destination IPv4/IPv6
                                        address is a local address.
                                      - Check if the Layer-4 protocol is TCP

    j.  HTTPS (IPv4/IPV6)             - Check if the packet has L4 port as       31       100    100
                                        443.
                                      - Check if the destination IPv4/IPv6
                                        address is a local address.
                                      - Check if the Layer-4 protocol is TCP

    k.  Broadcast ICMP (IPv4)         - Check if the IP protocol value is 1.     19       100    100
                                      - Check if the destination IP is
                                        255.255.255.255

    l.  Unicast ICMP (IPv4)           - Check if the IP protocol value is 1.     20       100    100
                                      - Check if the destination IP is Local

    m.  Multicast ICMP (IPv6)         - Check if the IPv6 protocol value is      21       100    100
                                        58.
                                      - Check if the destination IPv6 is
                                        multicast address

    n.  Unicast ICMP (IPv6)           - Check if the IPv6 protocol value is      22       100    100
                                        58.
                                      - Check if the destination IPv6 is
                                        local address

    o.  LACP                          - Check if the destination MAC address      6       100    100
                                        is 01:80:c2:00:00:02

    p.  LLDP                          - Check if the EtherType in the frame       7       100    100
                                        is 0x88CC.

    q.  NTP                           - Check if the packet has L4 port as       15       100    100
                                        123.
                                      - Check if the destination address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP

    r.  Multicast OSPFv2 (IPv4)       - Check if the IP protocol value is 89.    24       100    100
                                      - Check if the destination IP is either
                                        224.0.0.5 or 224.0.0.6.

    s.  Unicast OSPFv2 (IPv4)         - Check if the IP protocol value is 89.    25       100    100
                                      - Check if the destination IP is a local
                                        address on the box.

    t.  Multicast OSPFv3 (IPv6)       - Check if the IPv6 protocol value is      26       100    100
                                        89.
                                      - Check if the destination IPv6 is
                                        either FF02::5 or FF02::6.

    u.  Unicast OSPFv3 (IPv6)         - Check if the IPv6 protocol value is      27       100    100
                                        89.
                                      - Check if the destination IPv6 is a
                                        local address on the box.

    v.  Radius                        - Check if the packet has L4 port as       28       100    100
                                        1812.
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP

    w.  RIP                           - Check if the packet has L4 port as       29       100    100
                                        520.
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP

    x.  SNMP                          - Check if the packet has L4 port as 161.  32       100    100
                                      - Check if the destination IP address is
                                        a local address.
                                      - Check if the Layer-4 protocol is UDP

    y.  STP

    z.  TACACS                        - Check if the packet has L4 port as 49.   33       100    100
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is TCP

    aa. VRRP (IPv4)                   - Check if the IP protocol value is        34       100    100
                                        112.
                                      - Check if the destination IP is
                                        either 224.0.0.18.

    ab. VRRPV6 (IPv6)                 - Check if the IPv6 protocol value is      35       100    100
                                        112.
                                      - Check if the destination IPv6 is either
                                        FF02:0:0:0:0:0:0:12

    ac. IP packets with               - Check if the destination IP is local.     1       100    100
        V4 options                    - Check if the Options field in the IP
                                        datagram is set.

    ad. IPv6 packets with             - Check if the destination IPv6 is local.   2       100    100
        V6 options                    - Check if the either of the single
                                        extension header or multiple
                                        extension headers are set.

    ae. SSH                           - Check if the packet has L4 port as 22.   36       100    100
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is TCP

    af. SFLOW                         - Check if the packet has L4 port as       37       100    100
                                        6343.
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP

    ag. TELNET                        - Check if the packet has L4 port as 23.   38       100    100
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is TCP

    ah. Unknown multicast             - Check if the Destination IP is           23       100    100
        destination (IPv4/IPv6)         unknown multicast

    ai. Unknown unicast               - Check if the Destination IP is           39       100    100
        destination (IPv4/IPv6)         unknown unicast

    aj. Unclassified multicast
        destination (IPv4/IPv6)

    ak. Unclassified unicast
        destination (IPv4/IPv6)

    al. Catch all other packets      - Category of control packets which         42       100    100
                                       not match any supported control
                                       packets
