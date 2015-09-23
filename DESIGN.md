# High level design of ops-switchd-opennsl-plugin
ops-switchd-opennsl-plugin is *OpenSwitch* switch driver plugin for Broadcom switch ASCIs.

## Contents
[toc]

## Overview
*OpenSwitch* is Database driven Switch software for OCP compliant switch hardware.
In high level, the following diagram depicts the relations between various daemons in the switch firmware.

```
+----------------+  +-------------+  +---------------+
|                |  |             |  |               |
|  Management    |  |  Layer2     |  |  Layer3       |
|  CL/REST       |  |  Daemons    |  |  Daemons      |
|                |  |             |  |               |
+-------------+--+  +----+--------+  +----+----------+
              |          |                |
              +-----+    |      +---------+
                    |    |      |
                    |    |      |
               +----+----+------+-------+
               |                        |
               |         OVS DB         |
               +-----------+------------+
                           |
                   +-------+---------+
                   |   ovs-vSwitchd  |
             +-------------+----------------+
             |      switchd opennsl plugin  |
             +------------------------------+
             |        OpenNsl SDK           |
             |                              |
             +------------------------------+
  +-------------------------------------------+
  |                                           |
  | OpenNsl                                   |
  | Kernel Drivers               Linux        |
  | (knet, bde)                  Kernel       |
  |                                           |
  +-------------------------------------------+
  |                                           |
  |            Switch Hardware                |
  |                                           |
  +-------------------------------------------+
```
In *OpenSwitch* the Switch driver is based on the "Open vSwitch" architecture. In the above diagram ovs-vSwitchd is a very generic hardware independent layer, and it is derived from the "Open vSwitch/".

"Switchd-opennsl-plugin" a dynamically loadable module which manages Broadcom switch ASCIs. It uses APIs published in OpenNsl SDK (Open source SDK for Broadcom switch ASICs). The plugin is primarily divided into two layers 1. Netdev layer, 2. Ofproto layer.

## Terminology
Across the switch driver different layers uses different terminologies.

### In OVS-DB:
---------------------
Layer 3 router is called as "vrf".
Layer 2 switch is called as "bridge".
Logical layer2 switch port, Trunk/LAG, layer3 routable port, layer3 routable vlan interface are called as "port".
Layer1 physical interface is called as "interface".

### In ovs-vSwitchd
ovs-vSwitch uses the same naming convention as ovs-db.

### In switchd-opennsl-plugin netdev layer.
#### In netdev layer.
In opennsl-plugin, netdev layer primary scope is Layer1 device configuration. It calls the ASIC ports as "Interfaces"
#### In ofproto layer
Layer 3 router is called as "vrf".
Layer 2 switch is called as "bridge".
Logical layer2 switch port, Trunk/LAG, layer3 routable port, layer3 routable vlan interface are called as "bundle".
Layer1 physical interface is called as "port".

#### In OpenNSL API code
Layer1 physical interface - port
Layer2 Logical switch port  - port,
Trunk/LAG - trunk,
layer3 routable port, layer3 routable vlan interface - L3 interface

## Design
Switchd plugin is responsible for configuring the switch ASIC based on the configuration passed down by the ovs-vSwitchd. The configuration passed down is hardware independent. Switchd plugin has to configure the switch ASIC as per the passed down configuration to achieve the required functionality.

In a high level the OpenNsl switch plugin functionality can be divided in to the following categories.
1. Layer 1 physical port configuration.
   * Layer 1 port configuration
        * Knet Linux virtual ethernet interfaces
   * Trunk configuration
2. Layer2 switching
3. Layer3 routing
4. Advanced statistics

### Physical port configuration:
In *OpenSwitch* software "ops-intfd" daemon is responsible for the Physical port configuration. It derives a interface hardware configuration based on the user configuration(Interface:user_config), and other interface related information. Switch plugin should configure the switch ASIC (and other peripheral devices like Phys, MACs) as per the given hardware configuration.

Switchd plugin should also create one Linux virtual ethernet interface per every physical port present in the ASIC. Protocol BPDUs received in the switch ASIC should be readable via these ethernet interfaces for Layer2 & Layer3 daemon consumption. These daemons will also write the protocol BPDUs in to these virtual ethernet devices. These frames should be transmitted out of the Switch ASIC ports. Opennsl-plugin achieves this functionality by creating virtual ethernet devices called "Knet interfaces".

These two functionalities are in the netdev layer of the opennsl-plugin.

#### Trunk/LAG configuration:
OpenSwitch supports both static and dynamic link aggregation. One or more physical switch ASIC ports can be grouped to create a trunk. Currently a maximum of eight interfaces can be combined as one trunk.
Based on the user configuration "ops-lacpd" daemon updates Interface:hw_bond_config column in the database. Switchd plugin should configure trunks based on this information & user configuration.
Trunk functionality is handled in the ofproto layer of the opennsl-plugin.

#### Layer2 switching:
In OVS-DB port vlan information is stored in three important fields.
* Port:tag
* Port:trunks
* port:vlan_mode

vlan_mode has four possible values.
1. VLAN_ACCESS: Port carries packets on exactly one VLAN specified in Port:tag
2. VLAN_TRUNK: Port carries packets on one or more VLANs specified in Port:trunks. If Port:trunks is empty, then it can carry all the vlans defined in the system.
3. VLAN_NATIVE_TAGGED: Port resembles a trunk port, with the exception that all untagged packets go to Port:tag vlan.
4. VLAN_NATIVE_UNTAGGED: Port resembles a native-tagged port, but packets from Port:tag vlan will egress untagged.

This functionality is handled in ofproto layer.

#### Layer3 routing:

#### Advanced statistics:

## References
[OpenvSwitch Porting Guide](http://git.openvswitch.org/cgi-bin/gitweb.cgi?p=openvswitch;a=blob;f=PORTING)
