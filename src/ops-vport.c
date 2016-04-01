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
 * File: ops-vport.c
 *
 * Purpose: This file contains OpenSwitch VXLAN related application codes.
 * It provides APIs to ofproto-provider on top of ops-vxlan.c
 *
 */

#include "unixctl.h"
#include "util.h"
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
bcmsdk_vxlan_multicast_t multi_group;
/*******************************/

/* To avoid compiler warning... */
OVS_UNUSED static void netdev_change_seq_changed(const struct netdev *);

static  uint16_t tnl_udp_port = UDP_PORT_MIN;


#define mac_format(mac) \
        "ETHR ADDR: %02x:%02x:%02x:%02x:%02x:%02x\n", \
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] \

#define NULL_CHECK(p) \
        if(!p) {      \
            VLOG_ERR("Null Pointer %s", __func__);\
            return 1;\
        }

static void vxlan_tunnel_dump(bcmsdk_vxlan_tunnel_t *tunnel);
static void opennsl_l2_addr_dump(opennsl_l2_addr_t *l2_addr);

static int
get_src_udp(void)
{
    uint16_t next = tnl_udp_port++;
    if(tnl_udp_port == UDP_PORT_MAX)
        tnl_udp_port = UDP_PORT_MIN;
    return (int)next;
}

static inline bool
is_ready_to_bind(const bcmsdk_vport_t  *vport, const carrier_t *carrier)
{
    return (VALID_PORT(carrier->port) &&
            VALID_TUNNEL_ID(vport->tunnel_id) &&
            !MAC_IS_ZERO(carrier->next_hop_mac));
}

static int
get_vport_id_from_name(char *port)
{
    int vport_id = INVALID_VALUE;
    if(port) {
        const char *type = netdev_get_type_from_name(port);
        if(!strcmp(type, OVSREC_INTERFACE_TYPE_VXLAN)) {
            vport_id = netdev_bcmsdk_vport_get_vport_id(port);
        }
        else {
            vport_id = netdev_bcmsdk_get_vport_id(0, atoi(port));
        }
    }
    return vport_id;
}

static int
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
    if((rc = bcmsdk_vxlan_multicast_operation(hw_unit,
        opcode, &multi_group)) != 0)
        return rc;
    lsw.unknown_multicast_group = multi_group.group_id;
    lsw.unknown_unicast_group = multi_group.group_id;
    lsw.broadcast_group = multi_group.group_id;
    lsw.vnid = vni;
    VLOG_INFO("%s unit %d vni %d",__func__, hw_unit, vni);
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
ops_vport_bind_mac(int hw_unit, char *port, int vni, uint8_t *mac_str)
{
    opennsl_mac_t host_mac;
    opennsl_l2_addr_t l2_addr;
    struct ether_addr *ether_mac;
    struct ether_addr ZERO_MAC = {{0}};
    int rc;
    bcmsdk_vxlan_logical_switch_t logical_sw_p;

    if(!mac_str || !port) {
        VLOG_ERR("%s Invalid ethernet address or port name\n", __func__);
        return 1;
    }
    VLOG_DBG("Port %s, vni %d, MAC entered %s",port, vni, mac_str);

    ether_mac = ether_aton((char*)mac_str);
    if(ether_mac) {
        memcpy(host_mac, ether_mac, ETH_ALEN);
    } else {
        ether_mac = &ZERO_MAC;
    }

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
    l2_addr.port  = get_vport_id_from_name(port);
    l2_addr.vid   = logical_sw_p.vpn_id;

    if(!VALID_VPORT_ID(l2_addr.port)) {
        VLOG_ERR("%s Invalid vxlan port", __func__);
        return 1;
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
ops_vport_unbind_mac(int hw_unit, int vni, uint8_t *mac_str)
{
    opennsl_mac_t host_mac;
    struct ether_addr *ether_mac;
    struct ether_addr ZERO_MAC = {{0}};
    int rc;
    bcmsdk_vxlan_logical_switch_t logical_sw_p;

    if(!mac_str) {
        VLOG_ERR("%s Invalid ethernet address or port name\n", __func__);
        return 1;
    }
    VLOG_DBG("vni %d, MAC entered %s", vni, mac_str);
    ether_mac = ether_aton((char*)mac_str);
    if(ether_mac) {
        memcpy(host_mac, ether_mac, ETH_ALEN);
    } else {
        ether_mac = &ZERO_MAC;
    }

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
    VLOG_DBG("%s exit successfully, vpn_id 0x%x, mac %s\n", __func__,
             logical_sw_p.vpn_id, mac_str);
    return 0;
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
        ds_put_format(&ds, "Successful create lsw, multicast group %d,"
                           " vnid %d, vpnid 0x%x\n",
                            multi_group.group_id, lsw.vnid,lsw.vpn_id);
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
diag_vport_bind_mac(struct unixctl_conn *conn, int argc,
        const char *argv[], void *aux OVS_UNUSED)
{
    int hw_unit = 0;
    char port[128];
    char mac[32];
    snprintf(mac,32,argv[3]);
    snprintf(port,32,argv[1]);
    int vni = atoi(argv[2]);
    if(!ops_vport_bind_mac(hw_unit, port, vni, (uint8_t*)mac)) {
       unixctl_command_reply(conn, "sucess bining mac");
    } else {
        VLOG_ERR("%s failed ", __func__);
        unixctl_command_reply(conn, "fail bining mac");
    }
}

static void
diag_vport_unbind_mac(struct unixctl_conn *conn, int argc,
        const char *argv[], void *aux OVS_UNUSED)
{
    int hw_unit = 0;
    char mac[32];
    snprintf(mac,32,argv[2]);
    int vni = atoi(argv[1]);
    if(!ops_vport_unbind_mac(hw_unit, vni, (uint8_t*)mac)) {
       unixctl_command_reply(conn, "sucess unbining mac");
    } else {
        VLOG_ERR("%s failed ", __func__);
        unixctl_command_reply(conn, "fail bining mac");
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
    unixctl_command_register("bind/mac", "[port vni MAC]", 3, 3,
                   diag_vport_bind_mac, NULL);
    unixctl_command_register("unbind/mac", "[vni MAC]", 2, 2,
                   diag_vport_unbind_mac, NULL);

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
    if(!netdev_bcmsdk_vport_get_tunnel_id(netdev, &tunnel.tunnel_id)
        && VALID_TUNNEL_ID(tunnel.tunnel_id)) {
        rc = bcmsdk_vxlan_tunnel_operation(unit,
                                BCMSDK_VXLAN_OPCODE_DESTROY, &tunnel);
        if(rc) {
            VLOG_ERR("Failed to delete tunnel id %d\n", tunnel.tunnel_id);
            return rc;
        }
        netdev_bcmsdk_vport_set_tunnel_id(netdev, INVALID_VALUE);
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
            && ofproto_find_ip4_from_port(carrier->port, &tunnel.local_ip)) {
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
         netdev_bcmsdk_vport_set_tunnel_id(netdev, tunnel.tunnel_id);
         VLOG_INFO("\n--- Successful creating tunnel id 0x%x ---\n",
                   tunnel.tunnel_id);
    }
    return rc;
}

int
ops_vport_bind_net_port(struct netdev *netdev)
{
    int unit, rc = 0;
    bcmsdk_vxlan_port_t  vxlan_port;
    const bcmsdk_vport_t     *vport;
    const carrier_t *carrier;

    NULL_CHECK(netdev)
    vxlan_port.vnid = get_vni(netdev);
    if(!VALID_TUNNEL_KEY(vxlan_port.vnid)) {
        VLOG_ERR("Not ready to bind: Invalid vni\n");
        return 1;
    }
    vport = netdev_bcmsdk_vport_get_tunnel_vport(netdev);
    carrier = netdev_bcmsdk_vport_get_carrier(netdev);

    if (vport && carrier) {
        if(!is_ready_to_bind(vport, carrier)) {
            VLOG_ERR("Not ready to bind vxlan port, vxlan cfg invalid\n");
            return 1;
        }
        vxlan_port.port = carrier->port;
        vxlan_port.port_type = BCMSDK_VXLAN_PORT_TYPE_NETWORK;
        vxlan_port.tunnel_id = vport->tunnel_id;
        vxlan_port.vrf  = carrier->vrf;
        vxlan_port.vlan = vport->vlan;
        vxlan_port.l3_intf_id = vport->l3_intf_id;
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
        netdev_bcmsdk_vport_set_tunnel_vport(netdev, &vxlan_port);
        ops_vport_dump(&vxlan_port);
    }
    return rc;
}

int
ops_vport_unbind_net_port(struct netdev *netdev)
{
    int unit, rc = 0;
    bcmsdk_vxlan_port_t  vxlan_port;
    const bcmsdk_vport_t     *vport;
    const carrier_t *carrier;

    NULL_CHECK(netdev)
    vxlan_port.vnid = get_vni(netdev);
    if(!VALID_TUNNEL_KEY(vxlan_port.vnid)) {
        VLOG_ERR("Unable to unbind: Invalid vni\n");
        return 1;
    }
    vport = netdev_bcmsdk_vport_get_tunnel_vport(netdev);
    carrier = netdev_bcmsdk_vport_get_carrier(netdev);
    if(vport && VALID_EGRESS_ID(vport->egr_obj_id) && carrier) {
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
        netdev_bcmsdk_vport_reset_tunnel_vport(netdev);
        VLOG_INFO("\n--- Successfully unbinding network port ---\n");
    }
    return rc;
}

int
ops_vport_bind_access_port(int hw_unit, opennsl_pbmp_t pbm, int vni, int vlan)
{
    bcmsdk_vxlan_port_t port;
    int rc, aport;
    int vxlan_port_id;
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
        vxlan_port_id = netdev_bcmsdk_get_vport_id(hw_unit, aport);
        if(VALID_VPORT_ID(vxlan_port_id)) {
            VLOG_ERR("Access port already bound. Must unbind it first 0x%x\n",
                     vxlan_port_id );
            return 1;
        }
        rc = bcmsdk_vxlan_port_operation(hw_unit, BCMSDK_VXLAN_OPCODE_CREATE,
                                         &port);
        if (rc) {
            VLOG_ERR("%s - rc: %s", __func__, opennsl_errmsg(rc));
            return rc;
        }
        netdev_bcmsdk_set_vport_id(hw_unit, port.port, port.vxlan_port_id);
    }
    VLOG_INFO("\n--- Successully bind access port, vxlan port id 0x%x ---\n",
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
        port.vxlan_port_id = netdev_bcmsdk_get_vport_id(hw_unit, aport);

        if(VALID_VPORT_ID(port.vxlan_port_id)) {
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
       && !netdev_bcmsdk_vport_get_tunnel_id(netdev, &old_tnl.tunnel_id)
       && VALID_TUNNEL_ID(old_tnl.tunnel_id)) {

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
                           && ofproto_find_ip4_from_port(carrier->port,
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
            netdev_bcmsdk_vport_set_tunnel_id(netdev, tnl_id);
            VLOG_DBG("Successful updating Src IP tunnel id 0x%x\n", tnl_id);
            return 0;
        }
    } else {
        if(!ops_vport_unbind_net_port(netdev)) {
            if(!ops_vport_delete_tunnel(netdev)) {
                if(!ops_vport_create_tunnel(netdev)) {
                    return ops_vport_bind_net_port(netdev);
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

void
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
/*
static inline void
ethr_addr_print(struct ds *ds, uint8_t *ethr_addr)
{
    if(ethr_addr && ds) {
        ds_put_format(ds,"ETHR ADDR: %02x:%02x:%02x:%02x:%02x:%02x\n",
                 ethr_addr[0],ethr_addr[1],ethr_addr[2],
                 ethr_addr[3],ethr_addr[4],ethr_addr[5]);
    }
}
*/
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
        //ethr_addr_print(ds, l2_addr->mac);
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
