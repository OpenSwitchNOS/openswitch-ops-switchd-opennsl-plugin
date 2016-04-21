/*
 * Copyright (C) 2015-2016 Hewlett-Packard Enterprise Development Company, L.P.
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * File: ops-vport.c
 *
 * Purpose: This file contains OpenSwitch VXLAN related application codes.
 * It provides APIs to ofproto-provider on top of ops-vxlan.c
 *
 */

#include "unixctl.h"
#include "util.h"
#include "errno.h"
#include <netinet/ether.h>
#include <openvswitch/vlog.h>
#include <vswitch-idl.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/l2.h>
#include "byte-order.h"
#include "platform-defines.h"
#include "netdev-provider.h"
#include "ops-debug.h"
#include "ops-vxlan.h"
#include "ops-routing.h"
#include "ops-vport.h"
#include "netdev-bcmsdk-vport.h"
#include "netdev-bcmsdk.h"
#include "ofproto-bcm-provider.h"

VLOG_DEFINE_THIS_MODULE(ops_vport);

/****** For terminal diag ******/
bcmsdk_vxlan_logical_switch_t  lsw;
/*******************************/

/* To avoid compiler warning... */
OVS_UNUSED static void netdev_change_seq_changed(const struct netdev *);

static  uint16_t tnl_udp_port = UDP_PORT_MIN;

#define mac_format(mac) \
        "ETHR ADDR: %02x:%02x:%02x:%02x:%02x:%02x\n", \
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]

#define NULL_CHECK(p) \
        if(!p) {      \
            VLOG_ERR("Null Pointer %s", __func__);\
            return 1;\
        }

typedef struct bcm_vport_t_{
    int tunnel_id;      /* Tunnel's ID when successfully created */
    int vxlan_port_id;  /* If bind successful, get id = 0x8000001 etc..*/
    int egr_obj_id;     /* vxlan egress object */
    int station_id;     /*   */
}bcm_vport_t;

typedef struct vport_node_ {
    struct hmap_node node;     /* */
    int vni;                   /* tunnel key of a logical network */
    void * netdev;             /* pointer to tunnel */
    bcm_vport_t vport;         /* Storing bcm-returned ID */
}vport_node;

/* Hash map for bcmsdk virtual vxlan port created when
 * a tunnel is bound to a VNI
 * Each tunnel-VNI pair creates a unique bcm vport with a unique
 * id saved as vxlan_port_id
 */
struct hmap vport_hmap = HMAP_INITIALIZER(&vport_hmap);

static void vxlan_tunnel_dump(bcmsdk_vxlan_tunnel_t *tunnel);
static void opennsl_l2_addr_dump(opennsl_l2_addr_t *l2_addr);
static void bcm_vport_dump(bcm_vport_t *vport);
static void ops_vport_dump(bcmsdk_vxlan_port_t *vport);
static void hmap_vnode_print(struct ds *ds);
/*
 * Hash tunnel key(VNI) and the tunnel netdev pointer
 * for vport element
 */
static uint32_t
hash_vport(int vni, void* netdev)
{
    return hash_2words((uint32_t)vni, hash_pointer(netdev, 0));
}

/* vport_insert
 * Caller has to validate dev */
/* hash vni and tunnel pointer to index to the vport element
 */
static void
vport_insert(struct netdev* dev, int vni, bcmsdk_vxlan_port_t  *vxlan_port)
{
    vport_node *vnode = xmalloc(sizeof *vnode);
    if(vnode) {
        uint32_t hash = hash_vport(vni, dev);
        hmap_insert(&vport_hmap, &vnode->node, hash);
        vnode->vni = vni;
        vnode->netdev = dev;
        vnode->vport.tunnel_id = vxlan_port->tunnel_id;
        vnode->vport.vxlan_port_id = vxlan_port->vxlan_port_id;
        vnode->vport.egr_obj_id = vxlan_port->egr_obj_id;
        vnode->vport.station_id = vxlan_port->station_id;
        VLOG_DBG("%s --------vni %d, tunnel_id 0x%x\n"
                 "vxport 0x%x egress id 0x%x\n",
                 __func__, vni, vnode->vport.tunnel_id,
                 vnode->vport.vxlan_port_id, vnode->vport.egr_obj_id);
    }
}

/* caller has to validate *dev */
static vport_node *
vport_lookup(struct netdev *dev, int vni)
{
    vport_node *node;
    uint32_t hash = hash_vport(vni, dev);
    HMAP_FOR_EACH_WITH_HASH(node, node, hash, &vport_hmap) {
        if (node->vni == vni && node->netdev == dev) {
            VLOG_DBG("%s FOUND vport: [tnl_id: 0x%x, vni %d]\n",
                     __func__, node->vport.tunnel_id, vni);
            return node;
        }
    }
    return NULL;
}

static void
vport_remove(struct netdev *dev, int vni)
{
    vport_node *node = vport_lookup(dev, vni);
    if(node) {
        hmap_remove(&vport_hmap, &node->node);
        VLOG_DBG("%s successfully remove vport: [tnl_id: 0x%x, vni %d]\n",
                 __func__, node->vport.tunnel_id, vni);
        free(node);
    }
}

static int
get_src_udp(void)
{
    uint16_t next = tnl_udp_port++;
    if(tnl_udp_port == UDP_PORT_MAX)
        tnl_udp_port = UDP_PORT_MIN;
    return (int)next;
}
/* Caller checks for valid carrier */
static inline bool
is_ready_to_bind(const carrier_t *carrier)
{
    return (VALID_PORT(carrier->port) &&
            !MAC_IS_ZERO(carrier->next_hop_mac));
}

OVS_UNUSED static bool
is_tunnel(char *port)
{
    const char *type = netdev_get_type_from_name(port);
    if(type && (!strcmp(type, OVSREC_INTERFACE_TYPE_VXLAN))) {
        return true;
    }
    return false;
}
/* Caller has to validate dev and vport_id
 * If a tunnel is not bound to a vni yet, bind it
 */
static int
get_tnl_vport_id( struct netdev* dev, int vni, int *vport_id)
{
    vport_node * vnode;
    vnode = vport_lookup(dev, vni);
    if(vnode) {
        *vport_id = vnode->vport.vxlan_port_id;
        VLOG_DBG("%s Bound, Success getting tunnel vport id 0x%x",
                             __func__, *vport_id);
        return 0;
    }
    /*
     * Come here when this VNI is not bind to this tunnel
     * Take this as command to bind extra VNI to this
     * tunnel for now.
     * It's better to have separate command
     * from PI to bind/unbind VNI to a tunnel
     * TODO
     */
    if(!ops_vport_bind_net_port(dev, vni)) {
        vnode = vport_lookup(dev, vni);
        if(vnode) {
            *vport_id = vnode->vport.vxlan_port_id;
            VLOG_DBG("%s Newly Bound - Success getting tunnel vport id 0x%x",
                     __func__, *vport_id);
            return 0;
        }
    }
    return 1;
}
/* Caller has to validate port, port_id */
static int
get_vport_id(char *port, int vni, int ptype, int *port_id)
{
    opennsl_gport_t gport;
    struct netdev* dev;
    int rc = 0;
    VLOG_DBG("%s entered port %s vni %d ptype %d\n",
             __func__, port, vni, ptype);
    switch(ptype) {
        case TUNNEL:
            dev = netdev_bcmsdk_vport_tnl_from_name(port);
            if(dev) {
                return get_tnl_vport_id(dev, vni, port_id);
            }
        case PORT_VNI:
            netdev_bcmsdk_get_vport_id(0, atoi(port), port_id);
            break;
        case PORT_VLAN:
            rc = opennsl_port_gport_get(0, atoi(port), &gport);
            if (rc) {
                VLOG_ERR("%s, failed to get gport rc:%s port:%s\n",
                          __func__, opennsl_errmsg(rc), port);
                return rc;
            }
            *port_id = gport;
            break;
        default:
            VLOG_ERR("%s invalid port type %d\n", __func__, ptype);
            return EINVAL;
    }
    return rc;
}

static inline int
get_vni(struct netdev *netdev)
{
    const struct netdev_tunnel_config *tnl_cfg;
    tnl_cfg = netdev_get_tunnel_config(netdev);
    if(tnl_cfg && tnl_cfg->in_key_present) {
        return ntohll(tnl_cfg->in_key);
    }
    return -1;
}
/* For diagnostic purpose only */
static int
ops_vport_lsw_create(int hw_unit, int vni)
{
    int rc;
    bcmsdk_vxlan_opcode_t opcode = BCMSDK_VXLAN_OPCODE_CREATE;
    lsw.vnid = vni;
    VLOG_DBG("%s unit %d vni %d",__func__, hw_unit, vni);
    rc = bcmsdk_vxlan_logical_switch_operation(hw_unit, opcode, &lsw);
    if(rc) {
        VLOG_ERR("Fail creating logical switch\n");
        return rc;
    }
    VLOG_DBG("VPN_ID 0x%x", lsw.vpn_id);
    return 0;
}

/*
 * Bind l2 MAC to the a vxlan port on the logical switch
 */
int
ops_vport_bind_mac(int hw_unit, char *port, int ptype,
                   int vni, struct eth_addr *ether_mac)
{
    opennsl_mac_t host_mac;
    opennsl_l2_addr_t l2_addr;

    int rc;
    bcmsdk_vxlan_logical_switch_t logical_sw_p;

    if(!ether_mac || !port) {
        VLOG_ERR("%s Invalid ethernet address or port name\n", __func__);
        return EINVAL;
    }
    memcpy(host_mac, ether_mac->ea, ETH_ALEN);

    logical_sw_p.vnid = vni;
    rc = bcmsdk_vxlan_logical_switch_operation(hw_unit,
         BCMSDK_VXLAN_OPCODE_GET, &logical_sw_p);
    if(rc) {
        VLOG_ERR("%s Failed to get logical_switch for vni %d, rc %s",
                __func__, vni, opennsl_errmsg(rc));
        return rc;
    }

    opennsl_l2_addr_t_init(&l2_addr, host_mac, logical_sw_p.vpn_id);
    l2_addr.flags = OPENNSL_L2_STATIC;
    l2_addr.vid   = logical_sw_p.vpn_id;
    rc = get_vport_id(port, vni, ptype, &l2_addr.port);
    if(rc) {
        VLOG_ERR("%s Invalid vport id for port 0x%x, rc %d", __func__,l2_addr.port, rc);
        return rc;
    }
    opennsl_l2_addr_dump(&l2_addr);
    rc = opennsl_l2_addr_add(hw_unit, &l2_addr);
    if(rc) {
        VLOG_ERR("%s failed, rc: %s", __func__, opennsl_errmsg(rc));
        return rc;
    }
    VLOG_DBG("%s exit successfully, vport_id 0x%x, vpn_id 0x%x\n",
             __func__, l2_addr.port, l2_addr.vid);
    return 0;
}
int
ops_vport_unbind_mac(int hw_unit, int vni, struct eth_addr *ether_mac)
{
    opennsl_mac_t host_mac;
    int rc;
    bcmsdk_vxlan_logical_switch_t logical_sw_p;

    if(!ether_mac) {
        VLOG_ERR("%s Null pointer for MAC\n", __func__);
        return EINVAL;
    }
    memcpy(host_mac, ether_mac->ea, ETH_ALEN);
    logical_sw_p.vnid = vni;
    rc = bcmsdk_vxlan_logical_switch_operation(hw_unit,
                          BCMSDK_VXLAN_OPCODE_GET, &logical_sw_p);
    if(rc) {
        VLOG_ERR("%s Failed to get logical_switch for vni %d, rc %s",
                __func__, vni, opennsl_errmsg(rc));
        return rc;
    }
    rc = opennsl_l2_addr_delete(hw_unit, host_mac, logical_sw_p.vpn_id);
    if(rc) {
        VLOG_ERR("%s failed, rc: %s", __func__, opennsl_errmsg(rc));
        return rc;
    }
    VLOG_DBG("%s exit successfully, vpn_id 0x%x\n", __func__,
             logical_sw_p.vpn_id);
    return rc;
}
static void
diag_hmap_vnode_dump(struct unixctl_conn *conn, int argc,
        const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    hmap_vnode_print(&ds);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
diag_vport_lsw_create(struct unixctl_conn *conn, int argc,
        const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    int rc;
    int hw_unit = atoi(argv[1]);
    int vni = atoi(argv[2]);
    VLOG_INFO("%s unit %d vni %d",__func__, hw_unit, vni);
    rc  = ops_vport_lsw_create(hw_unit, vni);
    if (rc) {
        VLOG_ERR("%s failed rc: %s", __func__, opennsl_errmsg(rc));
        ds_put_format(&ds, "fail bcmsdk_vxlan_logical_switch");
    } else {
        ds_put_format(&ds, "Successful create lsw,"
                           " vnid %d, vpnid 0x%x\n",
                            lsw.vnid,lsw.vpn_id);
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
diag_vport_bind_mac(struct unixctl_conn *conn, int argc,
        const char *argv[], void *aux OVS_UNUSED)
{
    int vni, ptype, hw_unit = 0;
    char port[128];
    char mac[32];
    struct eth_addr ether_mac;
    snprintf(mac,32,argv[3]);
    snprintf(port,32,argv[1]);
    vni = atoi(argv[2]);
    ptype = atoi(argv[4]);

    if(eth_addr_from_string(mac, &ether_mac) &&
       !ops_vport_bind_mac(hw_unit, port, ptype, vni, &ether_mac)) {
        unixctl_command_reply(conn, "Sucess binding MAC");
    } else {
        unixctl_command_reply(conn, "Fail binding MAC");
    }
}

static void
diag_vport_unbind_mac(struct unixctl_conn *conn, int argc,
        const char *argv[], void *aux OVS_UNUSED)
{
    int vni, hw_unit = 0;
    char mac[32];
    struct eth_addr ether_mac;
    vni = atoi(argv[1]);
    snprintf(mac,32,argv[2]);
    if(eth_addr_from_string(mac, &ether_mac) &&
        !ops_vport_unbind_mac(hw_unit, vni, &ether_mac)) {
        unixctl_command_reply(conn, "Sucess unbinding MAC");
    } else {
        unixctl_command_reply(conn, "Fail binding MAC");
    }
}

int
ops_vport_init(int hw_unit)
{
    int rc = 0;
    rc = ops_vxlan_init(hw_unit);
    if (rc) {
        VLOG_ERR("%s failed rc: %s", __func__, opennsl_errmsg(rc));
        return rc;
    }

    unixctl_command_register("lsw", "hw_unit vni", 2, 2,
                   diag_vport_lsw_create, NULL);
    unixctl_command_register("bind/mac", "[port vni MAC port type]", 4, 4,
                   diag_vport_bind_mac, NULL);
    unixctl_command_register("unbind/mac", "[vni MAC]", 2, 2,
                   diag_vport_unbind_mac, NULL);
    unixctl_command_register("vport/dump", "", 0, 0,
                   diag_hmap_vnode_dump, NULL);
    return 0;
}

int
ops_vport_delete_tunnel(struct netdev *netdev)
{
    int unit = 0, rc = 0;
    bcmsdk_vxlan_tunnel_t tunnel;

    NULL_CHECK(netdev)
    VLOG_DBG("%s entered, name %s",__func__, netdev_get_name(netdev));
    netdev_bcmsdk_vport_get_hw_info(netdev, &unit, NULL, NULL);
    if(!netdev_bcmsdk_vport_get_tunnel_id(netdev, &tunnel.tunnel_id)) {
        rc = bcmsdk_vxlan_tunnel_operation(unit,
                                BCMSDK_VXLAN_OPCODE_DESTROY, &tunnel);
        if(rc) {
            VLOG_ERR("Failed to delete tunnel id %d\n", tunnel.tunnel_id);
            return rc;
        }
        netdev_bcmsdk_vport_set_tunnel_id(netdev, INVALID_VALUE, TNL_INIT);
    }
    return rc;
}

int
ops_vport_create_tunnel(struct netdev *netdev)
{
    int unit, rc = 0;
    bcmsdk_vxlan_tunnel_t tunnel;
    const struct netdev_tunnel_config *tnl_cfg;
    const carrier_t *carrier;
    ovs_be32 ipv4;

    NULL_CHECK(netdev)

    tnl_cfg = netdev_get_tunnel_config(netdev);
    carrier = netdev_bcmsdk_vport_get_carrier(netdev);

    if (!tnl_cfg || !carrier) {
        VLOG_ERR("%s Invalid tnl_cfg", __func__);
        return 1;
    }
    netdev_bcmsdk_vport_get_hw_info(netdev, &unit, NULL, NULL);
    /*
     * If source IP is not given from cli:
     * 1. Find out the IP address given the carrier net port
     *    which is found when searching for nexthop
     * 2. If fails on step 1, give it a dummy src IP (not supported)
     */
    if (!ipv6_addr_is_set(&tnl_cfg->ipv6_src)) {
        /* src ip is not configured */
        if((VALID_PORT(carrier->port))
            && ofproto_find_ipv4_from_port(carrier->port, &tunnel.local_ip)) {
            VLOG_DBG(" Found source IP4: 0x%x for port %d",
                     tunnel.local_ip, carrier->port);
        } else {
            VLOG_ERR("Can't find src IP for port %d", carrier->port);
            return 1;
        }
    } else {
        ipv4 =  in6_addr_get_mapped_ipv4(&tnl_cfg->ipv6_src);
        if(!ipv4) {
            /* TODO: support IPV6 */
            VLOG_INFO("Invalid IP\n");
            return 1;
        }
        tunnel.local_ip  = ntohl(ipv4);
        VLOG_DBG("Find given source IPP 0x%x\n", tunnel.local_ip);
    }
    ipv4 =  in6_addr_get_mapped_ipv4(&tnl_cfg->ipv6_dst);
    if(!ipv4) {
        /* TODO: support IPV6 */
        VLOG_INFO("Invalid IP\n");
        return 1;
    }
    tunnel.remote_ip = ntohl(ipv4);
    tunnel.ttl = tnl_cfg->ttl;
    tunnel.udp_dst_port  = ntohs(tnl_cfg->dst_port);
    tunnel.udp_src_port = get_src_udp();
    tunnel.vlan = -1;
    tunnel.tunnel_id = INVALID_VALUE;
    vxlan_tunnel_dump(&tunnel);

    rc = bcmsdk_vxlan_tunnel_operation(unit, BCMSDK_VXLAN_OPCODE_CREATE,
                                       &tunnel);
    if(!rc) {
         netdev_bcmsdk_vport_set_tunnel_id(netdev, tunnel.tunnel_id, TNL_CREATED);
         VLOG_INFO("\n--- Successful creating tunnel id 0x%x ---\n",
                   tunnel.tunnel_id);
    }
    return rc;
}

int
ops_vport_bind_net_port(struct netdev *netdev, int vni)
{
    int unit, rc = 0;
    bcmsdk_vxlan_port_t  vxlan_port;
    const carrier_t *carrier;
    vport_node * vnode;
    NULL_CHECK(netdev)
    vxlan_port.vnid = vni != -1? vni: get_vni(netdev);
    if(!VALID_TUNNEL_KEY(vxlan_port.vnid)) {
        VLOG_ERR("Not ready to bind: Invalid vni\n");
        return 1;
    }

    vnode = vport_lookup(netdev, vxlan_port.vnid);
    if(vnode) {
        VLOG_ERR("Already bound\n");
        return 1;
    }
    carrier = netdev_bcmsdk_vport_get_carrier(netdev);

    if (carrier) {
        if(!is_ready_to_bind(carrier)) {
            VLOG_ERR("Not ready to bind, carrier invalid\n");
            return 1;
        }
        vxlan_port.port = carrier->port;
        vxlan_port.port_type = BCMSDK_VXLAN_PORT_TYPE_NETWORK;
        netdev_bcmsdk_vport_get_tunnel_id(netdev, &vxlan_port.tunnel_id);
        vxlan_port.vrf  = carrier->vrf;
        vxlan_port.vlan = carrier->vlan;
        vxlan_port.l3_intf_id = carrier->l3_intf_id;
        memcpy(vxlan_port.next_hop_mac, carrier->next_hop_mac, ETH_ALEN);
        memcpy(vxlan_port.local_mac, carrier->local_mac, ETH_ALEN);

        netdev_bcmsdk_vport_get_hw_info(netdev, &unit, NULL, NULL);
        rc = bcmsdk_vxlan_port_operation(unit, BCMSDK_VXLAN_OPCODE_CREATE,
                                         &vxlan_port);
        if(rc) {
            VLOG_ERR("failed to bind network port:%s\n", opennsl_errmsg(rc));
            ops_vport_dump(&vxlan_port);
            return rc;
        }
        VLOG_INFO("\n--- Successfully binding net port %d"
                  " to vpn with vxlan port id 0x%x ---\n",
                  vxlan_port.port, vxlan_port.vxlan_port_id);
        netdev_bcmsdk_vport_set_tunnel_state(netdev, TNL_BOUND);
        vport_insert(netdev, vxlan_port.vnid, &vxlan_port);
        ops_vport_dump(&vxlan_port);
    }
    return rc;
}

/*
 * Binding the tunnel to a logical network
 */
int
ops_vport_unbind_net_port(struct netdev *netdev, int vni)
{
    int unit, rc = 0;
    bcmsdk_vxlan_port_t  vxlan_port;
    vport_node * vnode;
    const carrier_t *carrier;

    NULL_CHECK(netdev)
    vxlan_port.vnid = vni != -1? vni: get_vni(netdev);
    if(!VALID_TUNNEL_KEY(vxlan_port.vnid)) {
        VLOG_ERR("Unable to unbind: Invalid vni\n");
        return 1;
    }

    vnode = vport_lookup(netdev, vxlan_port.vnid);
    carrier = netdev_bcmsdk_vport_get_carrier(netdev);

    if(vnode && carrier) {
        bcm_vport_t *vport = &vnode->vport;
        vxlan_port.egr_obj_id = vport->egr_obj_id;
        vxlan_port.port_type = BCMSDK_VXLAN_PORT_TYPE_NETWORK;
        vxlan_port.station_id = vport->station_id;
        vxlan_port.vxlan_port_id = vport->vxlan_port_id;

        /* Required port because of BCM BUG of this opennsl version:
         * opennsl get port from vxlan_port.match_port return 0
         * Will remove when it's fixed */
        vxlan_port.port = carrier->port;
        netdev_bcmsdk_vport_get_hw_info(netdev, &unit, NULL, NULL);
        rc = bcmsdk_vxlan_port_operation(unit, BCMSDK_VXLAN_OPCODE_DESTROY,
                                         &vxlan_port);
        if(rc) {
            VLOG_ERR("failed to unbind network port:%s\n", opennsl_errmsg(rc));
            return rc;
        }
        netdev_bcmsdk_vport_set_tunnel_state(netdev, TNL_CREATED);
        vport_remove(netdev, vxlan_port.vnid);
        VLOG_INFO("\n--- Successfully unbinding network port ---\n");
    }
    return rc;
}

/*
 * Delete all the bcm vxlan ports using this tunnel
 */
int
ops_vport_unbind_all(struct netdev *netdev)
{
    vport_node * vnode, *next;
    int rc = 0;
    VLOG_DBG("%s entered\n", __func__);
    HMAP_FOR_EACH_SAFE(vnode, next, node, &vport_hmap) {
        if(vnode->netdev == netdev) {
            VLOG_DBG("tunnel id 0x%x - vni %d", vnode->vport.tunnel_id, vnode->vni);
            rc = ops_vport_unbind_net_port(netdev, vnode->vni);
            if(rc) {
               VLOG_ERR("%s failed to unbind tunnel id 0x%x from vni %d",
                         __func__, vnode->vport.tunnel_id, vnode->vni);
               return rc;
            }
        }
    }
    return rc;
}

int
ops_vport_bind_access_port(int hw_unit, opennsl_pbmp_t pbm, int vni, int vlan)
{
    bcmsdk_vxlan_port_t port;
    int rc, aport;

    VLOG_DBG("%s entered vlan %d, vni %d",__func__, vlan, vni);

    if(!VALID_TUNNEL_KEY(vni)) {
        VLOG_ERR("Invalid vni %d, ", vni);
        return 1;
    }
    port.port_type = BCMSDK_VXLAN_PORT_TYPE_ACCESS;
    port.vlan = vlan;
    port.vnid = vni;
    port.vrf = 0;     /* access port is in bridge_normal, vrf = 0 */

    OPENNSL_PBMP_ITER(pbm, aport) {
        port.port = aport;
        rc = bcmsdk_vxlan_port_operation(hw_unit, BCMSDK_VXLAN_OPCODE_CREATE,
                                         &port);
        if (rc) {
            VLOG_ERR("%s - rc: %s", __func__, opennsl_errmsg(rc));
            return rc;
        }
        netdev_bcmsdk_set_vport_id(hw_unit, port.port, port.vxlan_port_id);
    }
    VLOG_DBG("\n--- Successully bind access port, vxlan port id 0x%x ---\n",
              port.vxlan_port_id);
    return 0;
}

int
ops_vport_unbind_access_port(int hw_unit, opennsl_pbmp_t pbm, int vni)
{
    bcmsdk_vxlan_port_t port;
    int rc, aport;

    VLOG_DBG("%s entered vni %d",__func__, vni);
    if(!VALID_TUNNEL_KEY(vni)) {
        VLOG_ERR("%s Invalid vni %d, ", __func__, vni);
        return 1;
    }
    port.vnid = vni;
    port.port_type = BCMSDK_VXLAN_PORT_TYPE_ACCESS;

    OPENNSL_PBMP_ITER(pbm, aport) {
        port.port = aport;
        if(netdev_bcmsdk_get_vport_id(hw_unit, aport, &port.vxlan_port_id)) {
            rc = bcmsdk_vxlan_port_operation(hw_unit,
                                             BCMSDK_VXLAN_OPCODE_DESTROY,
                                             &port);
            if (rc) {
                VLOG_ERR("%s Error, %s", __func__, opennsl_errmsg(rc));
                return rc;
            }
            netdev_bcmsdk_set_vport_id(hw_unit, port.port, INVALID_VALUE);
        }
    }
    return 0;
}

static int
update_tunnel_src_ip(struct netdev *netdev, int *tunnel_id)
{
    bcmsdk_vxlan_tunnel_t  old_tnl;
    int unit, rc = 0;
    uint32_t new_src_ip;
    const carrier_t *carrier;
    const struct netdev_tunnel_config *new_tnl_cfg;

    VLOG_DBG("%s entered, name %s",__func__, netdev_get_name(netdev));
    netdev_bcmsdk_vport_get_hw_info(netdev, &unit, NULL, NULL);

    if(netdev
       && !netdev_bcmsdk_vport_get_tunnel_id(netdev, &old_tnl.tunnel_id)) {

        /* Retrieve current tunnel structure from bcm */
        rc = bcmsdk_vxlan_tunnel_operation(unit, BCMSDK_VXLAN_OPCODE_GET,
                                           &old_tnl);
        if(rc) {
            VLOG_ERR("Failed get Tunnel: %s\n", opennsl_errmsg(rc));
            return rc;
        }

        /* Get new tunnel configuration */
        new_tnl_cfg = netdev_get_tunnel_config(netdev);
        if(new_tnl_cfg) {

            /* If new tunnel config still doesn't have src_ip, find it */
            /* If src is not given */
            if(!ipv6_addr_is_set(&new_tnl_cfg->ipv6_src)) {
                carrier = netdev_bcmsdk_vport_get_carrier(netdev);
                if(carrier && (VALID_PORT(carrier->port)
                           && ofproto_find_ipv4_from_port(carrier->port,
                                                         &new_src_ip))) {
                    VLOG_DBG(" Found source IP4: 0x%x for port %d",
                             new_src_ip, carrier->port);
                } else {
                    VLOG_ERR("Expect new src IP for port 0x%x", carrier->port);
                    return 1;
                }
            } else {
                ovs_be32 src_ip = in6_addr_get_mapped_ipv4(&new_tnl_cfg->ipv6_src);
                if(!src_ip) {
                    /* TODO: support IPV6 */
                    VLOG_INFO("Invalid IP\n");
                    return 1;
                }
                new_src_ip = ntohl(src_ip);
                VLOG_DBG(" IP4 given 0x%x\n", new_src_ip);
            }
            /* Only update tunnel if new src ip is different */
            if(old_tnl.local_ip != new_src_ip ) {
                old_tnl.local_ip = new_src_ip;
                /*
                 * TODO
                 */
                return 0;
            }
        }
    }
    VLOG_DBG("%s exited",__func__);
    return rc;
}

/*
 * Tunnel Configuration changes such as dest IP, TTL, etc...
 * Unbind network port, delete old tunnel, create new one,
 * and rebind network port
 *
 */
OVS_UNUSED int
ops_vport_update_tunnel(struct netdev *netdev, int flags)
{
    int rc = 0;
    int tnl_id = -1;

    VLOG_DBG("%s entered, update flags 0x%x",
            __func__, flags);

    if(flags & UPDATE_SRC_IP) {
        rc = update_tunnel_src_ip(netdev, &tnl_id);
        if(!rc) {
            netdev_bcmsdk_vport_set_tunnel_id(netdev, tnl_id, TNL_CREATED);
            VLOG_DBG("Successful updating Src IP tunnel id 0x%x\n", tnl_id);
            return 0;
        }
    } else {
        if(!ops_vport_unbind_all(netdev)) {
            if(!ops_vport_delete_tunnel(netdev)) {
                if(!ops_vport_create_tunnel(netdev)) {
                    return ops_vport_bind_net_port(netdev, -1);
                }
            }
        }
    }
    return 1;
}


static void
vxlan_vport_print(struct ds *ds, bcmsdk_vxlan_port_t *vport)
{
    if (!vport || !ds) {
        ds_put_format(ds, "%s ERR: vport is NULL", __func__);
        return;
    }
    ds_put_format(ds, "\nVXLAN PORT:\n");
    ds_put_format(ds, "port %d          port_type %d     vlan %d\n"
                  "vnid %d       vrf %d           tunnel_id 0x%x\n"
                  "vxlan_port_id 0x%x             l3_intf_id %d\n"
                  "egr_obj_id    0x%x             station_id %d\n"
                  "port type %s\n", vport->port, vport->port_type,
                  vport->vlan, vport->vnid, vport->vrf, vport->tunnel_id,
                  vport->vxlan_port_id, vport->l3_intf_id,
                  vport->egr_obj_id, vport->station_id,
                  vport->port_type == BCMSDK_VXLAN_PORT_TYPE_NETWORK ?
                  "Network\n" : "Access\n");
    ds_put_format(ds, mac_format(vport->local_mac));
    ds_put_format(ds, mac_format(vport->next_hop_mac));
}

static void
ops_vport_dump(bcmsdk_vxlan_port_t *vport)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    vxlan_vport_print(&ds, vport);
    VLOG_DBG("%s",ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
vxlan_tunnel_print(struct ds *ds, bcmsdk_vxlan_tunnel_t *tunnel)
{
    if(!tunnel) {
        ds_put_format(ds, "%s tunnel is NULL", __func__);
        return;
    }
    ds_put_format(ds, "VXLAN TUNNEL:\n");
    ds_put_format(ds, "local_ip 0x%x     remote_ip 0x%x\n"
             "udp_src_port %d   udp_dst_port %d\n"
             "vlan %d           ttl %d\n"
             "tunnel_id 0x%x\n",
             tunnel->local_ip, tunnel->remote_ip, tunnel->udp_src_port,
             tunnel->udp_dst_port, tunnel->vlan, tunnel->ttl,
             tunnel->tunnel_id);
}

static void
vxlan_tunnel_dump(bcmsdk_vxlan_tunnel_t *tunnel)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    vxlan_tunnel_print(&ds, tunnel);
    VLOG_DBG("%s",ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
bcm_vport_print(struct ds *ds, bcm_vport_t *vport)
{
    if (!vport || !ds) {
        ds_put_format(ds, "%s ERR: vport is NULL", __func__);
        return;
    }
    ds_put_format(ds, "vxlan_port_id = 0x%x\n"
                      "egr_obj_id    = 0x%x\n"
                      "station_id    = %d\n"
                      "tunnel_id     = 0x%x\n",
                      vport->vxlan_port_id,
                      vport->egr_obj_id,
                      vport->station_id,
                      vport->tunnel_id);
}

OVS_UNUSED static void
bcm_vport_dump(bcm_vport_t *vport)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    bcm_vport_print(&ds, vport);
    VLOG_DBG("%s",ds_cstr(&ds));
    ds_destroy(&ds);
}

OVS_UNUSED static void
print_bitmap(opennsl_pbmp_t *temp_pbm)
{
    char  a_pfmt[_SHR_PBMP_FMT_LEN];
    VLOG_DBG("bitmap %s",_SHR_PBMP_FMT(*temp_pbm, a_pfmt));
}

static void
opennsl_l2_addr_print(struct ds *ds, opennsl_l2_addr_t *l2_addr)
{
    if(l2_addr && ds) {
        ds_put_format(ds, "vxlan port 0x%x vpn id %d",
                      l2_addr->port, l2_addr->vid);
        ds_put_format(ds, mac_format(l2_addr->mac));
    }
}

static void
opennsl_l2_addr_dump(opennsl_l2_addr_t *l2_addr)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    opennsl_l2_addr_print(&ds, l2_addr);
    VLOG_DBG("%s",ds_cstr(&ds));
    ds_destroy(&ds);
}

void
hmap_vnode_print(struct ds *ds)
{
    vport_node* vnode, *next;
    int count = 0;
    ds_put_format(ds, "*** VXLAN PORTS ***:\n");
    HMAP_FOR_EACH_SAFE(vnode, next, node, &vport_hmap) {
        count++;
        ds_put_format(ds, "VNI %d\n", vnode->vni);
        bcm_vport_print(ds, &vnode->vport);
        ds_put_format(ds, "\n");
    }
    ds_put_format(ds, "Total %d vxlan ports:\n",count);
}
