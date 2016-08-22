/*
 * Copyright (C) 2016 Hewlett-Packard Enterprise Development, L.P.
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
 * File: ops-vport.h
 *
 * Purpose: This file provides public definitions for VXLAN applications.
 */

#ifndef __OPS_VPORT_H__
#define __OPS_VPORT_H__ 1


#include <opennsl/types.h>
#include "ops-vxlan.h"

struct netdev;


#define  UPDATE_NEXTHOP_MAC 0x1
#define  UPDATE_PORT        0x2
#define  UPDATE_SRC_IP      0x4
#define  UPDATE_FULL        0xF


enum tnl_key_action_ {
    TUNNEL_KEY_BIND,    /* bind access port to a logical switch */
    TUNNEL_KEY_UNBIND,  /* unbind access port from a logical switch */
};

enum port_type_ {
    TUNNEL,          /* tunnel  */
    PORT_VNI,        /* port with tunnel key (VNI) configured */
    PORT_VLAN        /* port with VLAN */
};
int   ops_vport_init(int hw_unit);
int   ops_vport_create_tunnel(struct netdev *netdev);
int   ops_vport_delete_tunnel(struct netdev *netdev);
int   ops_vport_bind_access_port(int hw_unit, opennsl_pbmp_t pbm,
                                 int vni, int vlan);
int   ops_vport_unbind_access_port(int hw_unit, opennsl_pbmp_t pbm, int vni);
int   ops_vport_bind_net_port(struct netdev *netdev, int vni);
int   ops_vport_unbind_net_port(struct netdev *netdev, int vni);
int   ops_vport_bind_mac(int hw_unit, char *vport, int ptype, int vni,
                         struct eth_addr *ether_mac);
int   ops_vport_unbind_mac(int hw_unit, int vni, struct eth_addr *ether_mac);
int   ops_vport_unbind_all(struct netdev *netdev);
int   ops_vport_update_egr(struct netdev *netdev, int egr_id);
#endif /* __OPS_VPORT_H__ */
