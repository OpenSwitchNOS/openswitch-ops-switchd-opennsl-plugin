/*
 * Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
 * Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
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
#define NETDEV_BCMSDK_VPORT_H


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

/*
 * We use -1 as uninitialized/invalid value for bcm id.
 * BCM said they wouldn't use value -1 for id.
 * They currently use values like 0x8000001, for 1st tunnel
 * and 0x8000002 for next etc...
 * To reach -1, there needs to be about 4.29 billions tunnels
 * These below checking for valid ids are NOT a MUST -- but
 * rather a preventive care which can avoid problem going further
 * to BCM functions
 */
#define VALID_VPORT_ID(port)  VALID_VALUE(port)
#define VALID_TUNNEL_ID(id)   VALID_VALUE(id)
#define VALID_EGRESS_ID(id)   VALID_VALUE(id)


enum events {
    HOST_ADD,
    HOST_DELETE,
    ROUTE_ADD,
    ROUTE_DELETE
};
enum tnl_state {
    TNL_UNDEFINED,       /* After successful malloc */
    TNL_INIT,            /* When configuration is set */
    TNL_CREATED,         /* When tunnel is created */
    TNL_BOUND            /* When bind successful, vxlan port is created */
};

typedef struct carrier_t_{

    int port;                /* physical port for this tunnel */
    int vrf;                 /* vrf the port belongs */
    uint8_t local_mac[6];    /* local MAC of carrier port */
    uint8_t next_hop_mac[6]; /* MAC of neighbor */
    int status;              /* link status of this port */
} carrier_t;

typedef struct bcmsdk_vport_t_ {
    int vlan;           /* BCM assign 4095 always */
    int tunnel_id;      /* If tnl creation successful, get 0x4C000000 etc...*/
    int vxlan_port_id;  /* If bind successful, get 0x8000001 etc..*/
    int l3_intf_id;     /* l3 intf id of the carrier port */
    int egr_obj_id;     /* vxlan egress object */
    int station_id;     /*   */
} bcmsdk_vport_t;


/* BCM provider API. */
int  netdev_bcmsdk_vport_get_tunnel_id (struct netdev *netdev, int *tunnel_id);
int  netdev_bcmsdk_vport_set_tunnel_id (struct netdev *netdev, int tunnel_id);
void netdev_bcmsdk_vport_set_tunnel_vport (struct netdev *netdev,
                                           bcmsdk_vxlan_port_t * vport);
void netdev_bcmsdk_vport_reset_tunnel_vport(struct netdev *netdev);
int  netdev_bcmsdk_vport_get_vport_id(char *port);
void netdev_bcmsdk_vport_register(void);
void netdev_bcmsdk_vport_get_hw_info(struct netdev *netdev, int *hw_unit,
                                     int *hw_id, uint8_t *hwaddr);
const bcmsdk_vport_t * netdev_bcmsdk_vport_get_tunnel_vport
                                                 (struct netdev *netdev);
const carrier_t * netdev_bcmsdk_vport_get_carrier(struct netdev *netdev);
void netdev_vport_update_host_chg(int event, int port, char *ip_addr,
                                  int l3_egress_id);
void netdev_vport_update_route_chg(int event, char* route_prefix);

#endif /* NETDEV_BCMSDK_VPORT_H */
