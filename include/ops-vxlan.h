/*
 * Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
 * All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 *
 * File: ops-vxlan.h
 *
 * Purpose: This file provides public definitions for BCMSDK VXLAN applications.
 */

#ifndef __OPS_VXLAN_H__
#define __OPS_VXLAN_H__ 1

#include <ovs/dynamic-string.h>
#include <opennsl/types.h>



#define BCMSDK_VXLAN_DISABLE        0
#define BCMSDK_VXLAN_ENABLE         1

#define BCMSDK_VXLAN_INVALID        0
#define BCMSDK_VXLAN_VALID          1

/* Error return codes */
#define BCMSDK_VXLAN_E_NONE         OPENNSL_E_NONE
#define BCMSDK_VXLAN_E_INTERNAL     OPENNSL_E_INTERNAL
#define BCMSDK_VXLAN_E_MEMORY       OPENNSL_E_MEMORY
#define BCMSDK_VXLAN_E_UNIT         OPENNSL_E_UNIT
#define BCMSDK_VXLAN_E_PARAM        OPENNSL_E_PARAM
#define BCMSDK_VXLAN_E_EMPTY        OPENNSL_E_EMPTY
#define BCMSDK_VXLAN_E_FULL         OPENNSL_E_FULL
#define BCMSDK_VXLAN_E_NOT_FOUND    OPENNSL_E_NOT_FOUND
#define BCMSDK_VXLAN_E_EXISTS       OPENNSL_E_EXISTS
#define BCMSDK_VXLAN_E_TIMEOUT      OPENNSL_E_TIMEOUT
#define BCMSDK_VXLAN_E_BUSY         OPENNSL_E_BUSY
#define BCMSDK_VXLAN_E_FAIL         OPENNSL_E_FAIL
#define BCMSDK_VXLAN_E_DISABLED     OPENNSL_E_DISABLED
#define BCMSDK_VXLAN_E_BADID        OPENNSL_E_BADID
#define BCMSDK_VXLAN_E_RESOURCE     OPENNSL_E_RESOURCE
#define BCMSDK_VXLAN_E_CONFIG       OPENNSL_E_CONFIG
#define BCMSDK_VXLAN_E_UNAVAIL      OPENNSL_E_UNAVAIL
#define BCMSDK_VXLAN_E_INIT         OPENNSL_E_INIT
#define BCMSDK_VXLAN_E_PORT         OPENNSL_E_PORT



/* Default destination UDP port defined by
   RFC7348 Virtual eXtensible Local Area Network (VXLAN) */
#define VXLAN_DEFAULT_DST_UDP_PORT  4789



typedef enum bcmsdk_vxlan_opcode_t_ {
    BCMSDK_VXLAN_OPCODE_UNKNOWN,    /* Unknown opcode */
    BCMSDK_VXLAN_OPCODE_CREATE,     /* Create object */
    BCMSDK_VXLAN_OPCODE_GET,        /* Read Object */
    BCMSDK_VXLAN_OPCODE_UPDATE,     /* Update Object */
    BCMSDK_VXLAN_OPCODE_DESTROY,    /* Destroy Object */
    BCMSDK_VXLAN_OPCODE_MAX,
} bcmsdk_vxlan_opcode_t;


typedef enum bcmsdk_vxlan_port_type_t_ {
    BCMSDK_VXLAN_PORT_TYPE_UNKNOWN,    /* Unknown port type */
    BCMSDK_VXLAN_PORT_TYPE_ACCESS,     /* Access port type */
    BCMSDK_VXLAN_PORT_TYPE_NETWORK,    /* Network port type */
    BCMSDK_VXLAN_PORT_TYPE_MAX,
} bcmsdk_vxlan_port_type_t;


/*
 * struct bcmsdk_vxlan_logical_switch_t
 *      Structure for configuring/modifying logical switch.
 *
 * [In] vnid:
 *      Vxlan VNI.
 *
 * [In] broadcast_group:
 *      Broadcast group for this VNI.
 *
 * [In] unknown_multicast_group:
 *      Unknown multicast group for this VNI.
 *
 * [In] unknown_unicast_group:
 *      Unknown unicast group for this VNI.
 *
 * [Out] vpn_id:
 *      Reference to this logical switch.
 *
 */
typedef struct bcmsdk_vxlan_logical_switch_ {
    uint32_t vnid;
    int broadcast_group;
    int unknown_multicast_group;
    int unknown_unicast_group;
    uint16_t vpn_id;
} bcmsdk_vxlan_logical_switch_t;


/*
 * struct bcmsdk_vxlan_tunnel_t
 *      Structure for configuring/modifying tunnel.
 *
 * tunnel_ip:
 *      this tunnel's IP address.
 *
 * remote_ip:
 *      The remote endpoint's IP address.
 *
 * udp_src_port:
 *      UDP source port to be used while creating UDP header for encapsulation.
 *
 * udp_dst_port:
 *      UDP destinaiton port to be used while creating UDP header for
 *      encapsulation.
 *
 * vlan:
 *      VLAN id.
 *
 * ttl:
 *      Time to live to be used while creating L3 header.
 */
typedef struct bcmsdk_vxlan_tunnel_t_ {
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t udp_src_port;
    uint16_t udp_dst_port;
    uint16_t vlan;
    int ttl;
    int tunnel_id;
} bcmsdk_vxlan_tunnel_t;


/*
 * struct bcmsdk_vxlan_port_t
 *      Structure for storing configuration of vxlan access/network port (virtual for BCM).
 *
 * [In] port:
 *      Port number of the access/network port.
 *
 * [In] vlan:
 *      VLAN for access/network port.
 *
 * [In] vnid:
 *      Vxlan VNID.
 *
 * [In] vrf:
 *      VRF of routing table for access port/network.
 *
 * [In] local_mac:
 *      local MAC for tunnel.Only used for network port.
 *
 * [In] next_hop_mac
 *      Next hop MAC for tunnel. Only used for network port.
 *
 * [In] tunnel_id
 *      Tunnel initiator/terminator ID. Only used for network port.
 *
 * [Out] port_id:
 *      Virtual port ID.
 *
 * l3_intf_id:
 *      Internal use (access/network port).
 *
 * egr_obj_id:
 *      Internal use (access/network port).
 *
 * station_id
 *      Internal use (network port).
 */

typedef struct bcmsdk_vxlan_port_t_ {
    int port;
    bcmsdk_vxlan_port_type_t port_type;
    int vlan;
    int vnid;
    int vrf;
    uint8_t local_mac[6];
    uint8_t next_hop_mac[6];
    int tunnel_id;
    int vxlan_port_id;
    int l3_intf_id;
    int egr_obj_id;
    int station_id;
} bcmsdk_vxlan_port_t;


/*
 * struct bcmsdk_vxlan_multicast_t
 *      Structure for configuring/modifying Vxlan multicast.
 *
 * [In/Out] group_id:
 *       Multicast group ID
 */
typedef struct bcmsdk_vxlan_multicast_t_ {
    int32_t group_id;
} bcmsdk_vxlan_multicast_t;



/* Public API */
/*
 * Function: ops_vxlan_init
 *      Initialize Vxlan
 *      This API must be called before using Vxlan APIs
 *
 * [In] unit
 *      HW unit
 *
 * [Out] return
 *       See BCMSDK_VXLAN_E_XXX
 */
extern int
ops_vxlan_init(int unit);

/*
 * Function: ops_vxlan_cleanup
 *      Cleanup Vxlan
 *      This API must be called when no longer use Vxlan
 *
 * [In] unit
 *      HW unit
 *
 * [Out] return
 *       See BCMSDK_VXLAN_E_XXX
 */
extern int
ops_vxlan_cleanup(int unit);

/*
 * Function: bcmsdk_vxlan_endis_global
 *     Enable/Disable VxLAN globally on ASIC.
 *
 * [In] unit:
 *     HW unit
 *
 * [In] endis:
 *     BCMSDK_VXLAN_ENABLE/BCMSDK_VXLAN_DISABLE
 *
 * [Out] return
 *       See BCMSDK_VXLAN_E_XXX
 */
extern int
bcmsdk_vxlan_endis_global(int unit, int endis);

/*
 * Function: vxlan_logical_switch_operation
 *      Vxlan logical switch operation
 *
 * [In] unit:
 *      HW unit
 *
 * [In] opcode:
 *     opcode, see bcmsdk_vxlan_opcode_t
 *
 * [In/Out] logical_sw_p
 *     Varies Please see corresponding vxlan_xxx_logical_switch() for detail
 *
 * [Out] return
 *     See BCMSDK_VXLAN_E_XXX
 */
extern int
bcmsdk_vxlan_logical_switch_operation(int unit, bcmsdk_vxlan_opcode_t opcode,
                    bcmsdk_vxlan_logical_switch_t *logical_sw_p);

/*
 * Function: bcmsdk_vxlan_tunnel_operation
 *      Tunnel initiator and terminator operation.
 *
 * [In] unit:
 *      HW unit
 *
 * [In] opcode:
 *     opcode, see bcmsdk_vxlan_opcode_t
 *
 * [In/Out] tunnel_p
 *     Varies Please see corresponding vxlan_xxx_tunnel() for detail
 *
 * [Out] return
 *     See BCMSDK_VXLAN_E_XXX
 */
extern int
bcmsdk_vxlan_tunnel_operation(int unit, bcmsdk_vxlan_opcode_t opcode,
                              bcmsdk_vxlan_tunnel_t *tunnel_p);

/*
 * Function: bcmsdk_vxlan_port_operation
 *      Vxlan port operation.
 *
 * [In] unit:
 *      HW unit
 *
 * [In] opcode:
 *     opcode, see bcmsdk_vxlan_opcode_t
 *
 * [In/Out] tunnel_p
 *     Varies Please see corresponding vxlan_xxx_port() for detail
 *
 * [Out] return
 *     See BCMSDK_VXLAN_E_XXX
 */
extern int
bcmsdk_vxlan_port_operation(int unit, bcmsdk_vxlan_opcode_t opcode,
                            bcmsdk_vxlan_port_t *port_p);

/*
 * Function: bcmsdk_vxlan_multicast_operation
 *      Vxlan Multicast operation.
 *      Note: Temporary implement multicast in Vxlan module.
 *            Multicast feature is still under development by other
 *            team. Here we temorary implement a subset of multicast
 *            functionalities just for Vxlan purpose. These codes should
 *            be deleted and should use the APIs provided by multicast
 *            feature when multicast feature is available.
 *
 * [In] unit:
 *      HW unit
 *
 * [In] opcode:
 *     opcode, see bcmsdk_vxlan_opcode_t
 *
 * [In/Out] multicast_p
 *     Varies Please see corresponding vxlan_xxx_multicast() for detail
 *
 * [Out] return
 *     See BCMSDK_VXLAN_E_XXX
 */
extern int
bcmsdk_vxlan_multicast_operation(int unit, bcmsdk_vxlan_opcode_t opcode,
                                 bcmsdk_vxlan_multicast_t *multicast_p);




#endif /* __OPS_VXLAN_H__ */
