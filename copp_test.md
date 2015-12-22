#CoPP (Control Plane Policing) Feature Test Cases
________________________________________________
________________________________________________

## Contents

- [CoPP feature test cases introduction](#copp-feature-test-cases-introduction)
- [Testing the Broadcom qualifiers to qualify the different control packet types](#testing-the-broadcom-qualifiers-to-qualify-the-different-control-packet-types)
- [Testing the control packet rates](#testing-the-control-packet-rates)
- [Testing the control packet burst](#testing-the-control-packet-burst)
- [Appendix](#appendix)
- [References](#references)

## CoPP feature test cases introduction
The control plane policing (CoPP) feature on Openswitch limits the number of
control plane packets destined for the CPU of a switch or a router.

Control plane packets are defined as packets which are processed or
consumed by the routing processor. Different control plane packets can be
rate limited so that those packets are pushed to the CPU only
at the programmed or configured rate. If the control plane packets arrive at
a rate which is higher than the rate specified for the packets, then
the packets are dropped by the hardware.

Along with the rate limit, the CoPP feature also allows a burst of packets to be
pushed to the CPU. The number of control plane packets received
by the CPU are usually measured by the Linux tools, such as `tcpdump` or `tshark`.

These test cases are applicable to the following platforms:
- AS5712
- AS6712
- AS7712

## Testing the Broadcom qualifiers to qualify the different control packet types

### Objective
This test verifies that the control plane packet qualifiers are correctly
identified and programmed in the hardware.

### Requirements
- Physical switches and workstations test setup is required.

### Setup
#### Topology diagram
```ditaa

                                              |                                   |
                               _______________|_________________       ___________|_________
                              |        (123.0.0.1/24)          |       |    (143.0.0.1/24)  |
 ____________________         |         interface 3            |       |      interface 3   |
|                    |        |                                |       |                    |
|                    |        | (10.1.1.1/24)   (10.1.2.1/24)) |       |       (Device2)    |
|(Traffic Generator) |--------| interface 1      interface 2   |-------|(10.1.2.2/24)       |
|____________________|        |                                |       | interface 1        |
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
correctly identified and programmed into the hardware. For different control
packet streams from traffic generator, the `tcpdump` command on either Device1,
Device2, or the host must display the appropriate output.

For example, BGP packets for Device1 have the destination IP address of either
123.0.0.1, 10.1.1.1, or 10.1.2.1, and are encapsulated in A TCP packet and
destined for L4 port 179. When a packet stream is formed from traffic generator,
and the BGP packets are generated, the `tcpdump` command on Device1 dumps the
details of the BGP packets that are received. The `tcpdump` on Device2 does
not dump any output. Similarily, BGP packets destined for Device2 do not
cause the `tcpdump`command on Device1 to show any output. The `tcpdump`
command on Device2 dumps the output in this case.

oreover, the control packets destined for a CPU must be directed to the
respective CPU queues. The `appctl` commands are used to dump the number of
packets queued in a given CPU queue. The CPU queue number for the control
packets are shown in the appendix.

To start the test:
1.  Set up the topology as shown in the above figure.
2.  Configure the static routes on Device1 to reach subnets 10.1.2.0/24,
    10.1.3.0/24, and 143.0.0.0/24. Enable BGP daemon on Device1.
3.  Configure the static routes on Device2 to reach the subnet 10.1.3.0/24.
    Enable BGP daemon on Device2.
4.  Run `tcpdump` on Device1, Device2, and Host as:
    `tcpdump tcp -i 2 dst port 179`
5.  Generate the BGP packets from traffic generator that are destined to go to
    Device1. Generate the packets using the following information:
    - L4 destination port: 179
    - Destination IP address:  123.0.0.1, 10.1.1.1,  or 10.1.2.1
    - L4 protocol: TCP
    The `tcpdump` on Device1 displays some output. The `tcpdump`
    command on Device2 and Host does not display any output.
6.  Execute the `appctl` command to dump the queue stats on queue 0 (refer
    to the table in the appendix) to verify that the BGP packets were queued in CPU
    queue 0.
7.  Generate the BGP packets from traffic generator that are destined to go
    to Device2. Generate the packets using the following information:
    - L4 destination port: 179
    - Destination IP addresses: 143.0.0.1, 10.1.3.1
    - L4 protocol: TCP
    The `tcpdump` on Device1 and Host does not display any output. The
    `tcpdump` command on Device2 display some output.
8.  Generate the BGP packets from traffic generator that are destined to go to
    the Host. Generate the packets using the following information:
    - L4 destination port: 179
    - Destination IP addresses: 10.1.3.2
    - L4 protocol: TCP
    The `tcpdump` command on Device1 and Device2 does not display any output.
9.  Change the L4 destination port for BGP packets from 179 to any other
    value. The `tcpdump` tool does not display any output on Device1
    or Device2. The queue counters using the `appctl` command for
    queue 0 do not increment on either Device1 or Device2. The
    `appctl` counters for the default queue (queue 42) do increment.
10. Change the L4 protocol for BGP packets from TCP to UDP.
    The `tcpdump` tool does not display any output on Device1
    or Device2. The queue counters using the `appctl` command for
    queue 0 should not increment on either Device1 or Device2. The
    `appctl` counters for the default queue (queue 42) do increment.
11. Repeat steps 1-10 for the packets types given in the appendix.

#### Test fail criteria
If the `tcpdump` output is not expected as per steps 5, 7, 8, 9, and 10,
then the test case is deemed to have failed. Otherwise, the test case is deemed
to have passed.


## Testing the control packet rates

### Objective
This test verifies the specified rate at which different control packets are
delivered to the CPU.

### Requirements
- Physical switch and workstations test setup is required.

### Setup
#### Topology diagram
```ditaa
                                              |
                               _______________|_________________       _____________________
                              |        (123.0.0.1/24)          |       |                    |
 ____________________         |         interface 3            |       |                    |
|                    |        | (10.1.1.1/24)   (10.1.2.1/24)) |       |       (Host)       |
|(Traffic Generator) |--------| interface 1      interface 2   |-------|(10.1.2.2/24)       |
|____________________|        |                                |       | eth0               |
                              |         (Device1)              |       |                    |
                              |                                |       |                    |
                              |________________________________|       |____________________|
```
### Description
This test ensures that the control packets that are pushed to the CPU are rate
limited. For example, if the BGP control packets are rate limited at 200 packets
per second by the CoPP feature, then no more than 200 packets per second
are delivered to the CPU. The `tcpdump` command does not display more than 200
BGP packets per second. The number of BGP packets captured by the `tcpdump`
command are averaged over a few seconds before computing the rate at which the
BGP packets were captured by `tcpdump`.

To start the test:
1.  Set up the topology as shown in the above figure.
2.  Configure the static routes on Device1 to reach subnets 10.1.2.0/24,
    10.1.3.0/24, and 143.0.0.0/24. Enable BGP daemon on Device1.
3.  Run `tcpdump` on Device1 and Host as:
    `tcpdump tcp -i 2 dst port 179`
4.  Generate the BGP packets from traffic generator that are destined to go
    to Device1. Generate the packets using the following information:
    - L4 destination port: 179
    - Destination IP address:  123.0.0.1, 10.1.1.1, or 10.1.2.1
    - L4 protocol: TCP
    Set the BGP packet rate from traffic generator to be higher than the
    supported rate for BGP packets. The `tcpdump` on Device1 displays BGP
    packets at the supported rate. Average the rate for BGP packets over
    a few seconds.
5.  Generate the BGP packets from traffic generator that are destined to
    go to Device1. Generate the packets using the following information:
    - L4 destination port: 179
    - Destination IP address:  123.0.0.1, 10.1.1.1, or 10.1.2.1
    - L4 protocol: TCP
    Set the BGP packet rate from traffic generator to be lower than the
    supported rate for BGP packets. The `tcpdump` on Device1 displays the BGP
    packets at the rate in which they are being generated from traffic
    generator.
6.  Generate the BGP packets from traffic generator that are destined to go to
    Device1. Generate the packets using the following information:
    - L4 destination port: 179
    - Destination IP address:  123.0.0.1, 10.1.1.1,  or 10.1.2.1
    - L4 protocol: TCP
    Set the BGP packet rate from traffic generator to be equal to the supported
    rate for BGP packets. The `tcpdump` on Device1 displays the BGP packets at
    the supported rate. Average the rate for BGP packets over a few seconds.
7.  Repeat steps 1 through 6 for each of the packets types and their
    respective rates given in the appendix.

#### Test fail criteria
If the `tcpdump` output is not expected as per steps 4, 5 and 6, then the test
case is deemed to have failed. Otherwise, the test case is deemed to have
passed.

## Testing the control packet burst

### Objective
This test verifies the rate at which different control packets are delivered
to the CPU at the specified burst.

### Requirements
- Physical switch and workstations test setup is required.

### Setup
#### Topology diagram
```ditaa
                                              |
                               _______________|_________________       _____________________
                              |        (123.0.0.1/24)          |       |                    |
 ____________________         |         interface 3            |       |                    |
|                    |        | (10.1.1.1/24)   (10.1.2.1/24)) |       |       (Host)       |
|(Traffic Generator) |--------| interface 1      interface 2   |-------|(10.1.2.2/24)       |
|____________________|        |                                |       | eth0               |
                              |         (Device1)              |       |                    |
                              |                                |       |                    |
                              |________________________________|       |____________________|
```
### Description
This test ensures that the control packets are pushed to the CPU at the
specified burst size. This test case is applicable to bursty traffic.
For example, if the BGP control packets are rate limited to 200 packets
per second and a burst of 400 packets is issued by the CoPP feature,
then no more than 400 packets should be delivered to the CPU for a given
BGP packet burst.

The `tcpdump` command does not display more than 400 BGP packets per second
for the packet burst. The number of BGP packets captured by the `tcpdump`
command for a given burst size is averaged over many BGP packet bursts.

To start the test:
1.  Set up the topology as shown in the above figure.
2.  Configure the static routes on Device1 to reach subnets 10.1.2.0/24,
    10.1.3.0/24, and 143.0.0.0/24. Enable BGP daemon on Device1.
3.  Run `tcpdump` on Device1 and Host as:
    `tcpdump tcp -i 2 dst port 179`
4.  Generate the BGP packets from traffic generator that are destined to go to
    Device1. Generate the packets using the following information:
    - L4 destination port: 179
    - Destination IP address:  123.0.0.1, 10.1.1.1, or 10.1.2.1
    - L4 protocol: TCP
    Set the BGP packet to stream to bursty with the burst size higher than
    the supported burst size for the BGP packets in traffic generator. Set the
    bursty BGP packet stream to be periodic.
    The `tcpdump` on Device1 displays the BGP packets at the supported burst.
    Average the burst for the BGP packets over a few seconds.
5.  Generate the BGP packets from traffic generator that are destined to go to
    Device1. Generate the packets using the following information:
    - L4 destination port: 179
    - Destination IP address:  123.0.0.1, 10.1.1.1, or 10.1.2.1
    - L4 protocol: TCP
    Set the BGP packet stream to bursty with the burst size lower than the
    supported burst size for BGP packets in traffic generator.
    The `tcpdump` on Device1 displays the BGP packets at the burst in which
    they are being generated from traffic generator. Average the burst for the
    BGP packets over a few seconds.
6.  Generate the BGP packets from traffic generator that are destined to go to
    Device1. Generate the packets using the following information:
    - L4 destination port: 179
    - Destination IP address:  123.0.0.1, 10.1.1.1,  or 10.1.2.1
    - L4 protocol: TCP
    Set the BGP packet stream to bursty with the burst size equal to the
    supported burst size for the BGP packets in traffic generator. Set the
    bursty BGP packet stream to be periodic.
    The `tcpdump` on Device1 displays the BGP packets at the burst in which
    they are being generated from traffic generator. Average the burst for the
    BGP packets over a few seconds.
7.  Repeat steps 1 through 6 for each of the packet types and their respective
    burst sizes given in the appendix.

#### Test fail criteria
If the `tcpdump` output is not expected as per steps 4, 5 and 6, then the test
case failed. Otherwise, the test case passed.

## Appendix
The appendix displays the rules to the various control packets that are
destined to the local routing processor.

    Control Packet Type               Identification Criteria                 CPU Queue   Rate  Burst
------------------------------------------------------------------------------------------------------
    a.  Broadcast ARP                 - Check ether type as 0x0806               12
                                      - Check whether the destination
                                        MAC is broadcast.

    b.  Unicast ARP                   - Check ether type as 0x0806               18
                                      - Check whether the destination MAC
                                        is unicast.

    c.  BGP (IPv4/IPV6)               - Check if the packet has L4 port as        0
                                        179.
                                      - Check if the destination IPv4/IPv6
                                        address is a local address.
                                      - Check if the Layer-4 protocol is TCP.

    d.  BGP+ (IPv4/IPV6)              - Check if the packet has L4 port as        0
                                        179.
                                      - Check if the destination IPv4/IPv6
                                        address is a local address.
                                      - Check if the Layer-4 protocol is TCP.

    e.  DHCP (client/server)          - Check if the packet has L4 port as       13
                                        68/67.
                                      - Check if the destination IPv4 address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP.


    f.  DHCPv6 (client/server)        - Check if the packet has L4 port as       14
                                        546/547.
                                      - Check if the destination IPv6 address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP.

    g.  GMRP
    h.  GVRP

    i.  HTTP (IPv4/IPV6)              - Check if the packet has L4 port as 80.   30
                                      - Check if the destination IPv4/IPv6
                                        address is a local address.
                                      - Check if the Layer-4 protocol is TCP.

    j.  HTTPS (IPv4/IPV6)             - Check if the packet has L4 port as       31
                                        443.
                                      - Check if the destination IPv4/IPv6
                                        address is a local address.
                                      - Check if the Layer-4 protocol is TCP.

    k.  Broadcast ICMP (IPv4)         - Check if the IP protocol value is 1.     19
                                      - Check if the destination IP is
                                        255.255.255.255.

    l.  Unicast ICMP (IPv4)           - Check if the IP protocol value is 1.     20
                                      - Check if the destination IP is Local.

    m.  Multicast ICMP (IPv6)         - Check if the IPv6 protocol value is      21
                                        58.
                                      - Check if the destination IPv6 is a
                                        multicast address.

    n.  Unicast ICMP (IPv6)           - Check if the IPv6 protocol value is      22
                                        58.
                                      - Check if the destination IPv6 is a
                                        local address.

    o.  LACP                          - Check if the destination MAC address      6
                                        is 01:80:c2:00:00:02

    p.  LLDP                          - Check if the EtherType in the frame       7
                                        is 0x88CC.

    q.  NTP                           - Check if the packet has L4 port as       15
                                        123.
                                      - Check if the destination address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP.

    r.  Multicast OSPFv2 (IPv4)       - Check if the IP protocol value is 89.    24
                                      - Check if the destination IP is either
                                        224.0.0.5 or 224.0.0.6.

    s.  Unicast OSPFv2 (IPv4)         - Check if the IP protocol value is 89.    25
                                      - Check if the destination IP is a local
                                        address on the box.

    t.  Multicast OSPFv3 (IPv6)       - Check if the IPv6 protocol value is      26
                                        89.
                                      - Check if the destination IPv6 is
                                        either FF02::5 or FF02::6.

    u.  Unicast OSPFv3 (IPv6)         - Check if the IPv6 protocol value is      27
                                        89.
                                      - Check if the destination IPv6 is a
                                        local address on the box.

    v.  Radius                        - Check if the packet has L4 port as       28
                                        1812.
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP

    w.  RIP                           - Check if the packet has L4 port as       29
                                        520.
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP

    x.  SNMP                          - Check if the packet has L4 port as 161.  32
                                      - Check if the destination IP address is
                                        a local address.
                                      - Check if the Layer-4 protocol is UDP.

    y.  STP

    z.  TACACS                        - Check if the packet has L4 port as 49.   33
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is TCP.

    aa. VRRP (IPv4)                   - Check if the IP protocol value is        34
                                        112.
                                      - Check if the destination IP is
                                        either 224.0.0.18.

    ab. VRRPV6 (IPv6)                 - Check if the IPv6 protocol value is      35
                                        112.
                                      - Check if the destination IPv6 is
                                        FF02:0:0:0:0:0:0:12.

    ac. IP packets with               - Check if the destination IP is local.     1
        V4 options                    - Check if the Options field in the IP
                                        datagram is set.

    ad. IPv6 packets with             - Check if the destination IPv6 is local.   2
        V6 options                    - Check if either the single
                                        extension header or multiple
                                        extension headers are set.

    ae. SSH                           - Check if the packet has L4 port as 22.   36
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is TCP.

    af. SFLOW                         - Check if the packet has L4 port as       37
                                        6343.
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is UDP.

    ag. TELNET                        - Check if the packet has L4 port as 23.   38
                                      - Check if the destination IP address
                                        is a local address.
                                      - Check if the Layer-4 protocol is TCP.

    ah. Unknown multicast             - Check if the Destination IP is           23
        destination (IPv4/IPv6)         unknown multicast.

    ai. Unknown unicast               - Check if the Destination IP is           39
        destination (IPv4/IPv6)         unknown unicast.

    aj. Unclassified multicast
        destination (IPv4/IPv6)

    ak. Unclassified unicast
        destination (IPv4/IPv6)

    al. Catch all other packets      - Category of control packets which         42
                                       not match any supported control
                                       packets.

## References
https://danielmiessler.com/study/tcpdump/
