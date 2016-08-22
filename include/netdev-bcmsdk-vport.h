/*
 * Copyright (C) 2015-2016 Hewlett-Packard Enterprise Development, L.P.
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * File: netdev-bcmsdk-vport.h
 */

#ifndef NETDEV_BCMSDK_VPORT_H
#define NETDEV_BCMSDK_VPORT_H 1


#include "openvswitch/types.h"
#include "ops-vxlan.h"

struct netdev;
struct netdev_class;
struct netdev_stats;
struct netdev_tunnel_config;


#define UDP_PORT_MIN 32768
#define UDP_PORT_MAX 61000
#define TUNNEL_KEY_MIN 0
#define TUNNEL_KEY_MAX 0xFFFFFF  /* 24 bit VNI */

#define PORT_MIN  0
#define INVALID_VALUE (-1)
#define VALID_VALUE(val)      (val  != INVALID_VALUE)
#define VALID_PORT(port)      (port > PORT_MIN)
#define VALID_TUNNEL_KEY(key) \
        ((key >= TUNNEL_KEY_MIN) && (key <= TUNNEL_KEY_MAX))
#define MAC_IS_ZERO(mac)  \
                   (((mac)[0] | (mac)[1] | (mac)[2] | \
                     (mac)[3] | (mac)[4] | (mac)[5]) == 0)

#define VALID_EGRESS_ID(id)   VALID_VALUE(id)


enum events {
    HOST_ADD,     /* Host add event from PI */
    HOST_DELETE,  /* Host delete event from PI */
    ROUTE_ADD,    /* Route add event from PI */
    ROUTE_DELETE  /* Route delete event from PI */
};
enum tnl_state {
    TNL_UNDEFINED,       /* After successful malloc */
    TNL_INIT,            /* When configuration is set */
    TNL_CREATED,         /* When tunnel is created */
    TNL_DOWN,            /* Tunnel is bound but route is down */
    TNL_UP,              /* When tunnel is successfully bound to net port,
                          * and vxlan port is created */
};

/*
 * Information required by BCM to bind tunnel to logical network
 */
typedef struct carrier_t_ {

    int port;                /* egress port for this tunnel */
    int vrf;                 /* port's vrf */
    int vlan;                /* used if this is l2 port */
    int l3_intf_id;          /* l3 intf id  */
    uint8_t local_mac[6];    /* local MAC */
    uint8_t next_hop_mac[6]; /* MAC of neighbor */
    bool status;             /* link status */
} carrier_t;

/* BCM provider API. */
int  netdev_bcmsdk_vport_get_tunnel_id(struct netdev *netdev, int *tunnel_id);
void netdev_bcmsdk_vport_set_tunnel_id(struct netdev *netdev,
                                       int tunnel_id, int state);
void netdev_bcmsdk_vport_set_tunnel_state(struct netdev *netdev, int state);
void netdev_bcmsdk_vport_register(void);
void netdev_bcmsdk_vport_get_hw_info(struct netdev *netdev, int *hw_unit,
                                     int *hw_id, uint8_t *hwaddr);
struct netdev* netdev_bcmsdk_vport_tnl_from_name(char *port);
const carrier_t * netdev_bcmsdk_vport_get_carrier(struct netdev *netdev);
void netdev_vport_update_host_chg(int event, char *ip_addr, int l3_egress_id);
void netdev_vport_update_route_chg(int event, char* route_prefix);

#endif /* NETDEV_BCMSDK_VPORT_H */
