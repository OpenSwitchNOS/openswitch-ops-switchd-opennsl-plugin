/*
 * Copyright (C) 2015-2016 Hewlett-Packard Enterprise Development Company, L.P.
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
 * File: netdev-bcmsdk-vport.c
 */

#include <config.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "byte-order.h"
#include "daemon.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "hash.h"
#include "hmap.h"
#include "list.h"
#include <netdev-provider.h>
#include <openvswitch/vlog.h>
#include <openswitch-idl.h>
#include <ofproto/ofproto.h>
#include "ops-stats.h"
#include "platform-defines.h"
#include "netdev-bcmsdk.h"
#include "ops-routing.h"
#include "shash.h"
#include "socket-util.h"
#include "unixctl.h"
#include "util.h"
#include "ops-vxlan.h"
#include "ops-vport.h"
#include "netdev-bcmsdk-vport.h"


VLOG_DEFINE_THIS_MODULE(netdev_bcmsdk_vport);


#define GENEVE_DST_PORT 6081
#define VXLAN_DST_PORT 4789
#define LISP_DST_PORT 4341
#define STT_DST_PORT 7471

#define DEFAULT_TTL 64


#define mac_format(mac) \
        "ETHR ADDR: %02x:%02x:%02x:%02x:%02x:%02x\n", \
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] \

#define TUNNEL_UNBIND(event, state) \
        ((event == HOST_DELETE || event == ROUTE_DELETE) && state == TNL_BOUND)

#define TUNNEL_BIND(event, state) \
        ((event == HOST_ADD || event == ROUTE_ADD)  && state < TNL_BOUND)

#define TUNNEL_ACTION(event, state) \
        (TUNNEL_UNBIND(event, state) || TUNNEL_BIND(event, state))

struct netdev_vport {
    struct netdev up;
    /* Protects all members below. */
    struct ovs_mutex mutex;

    struct eth_addr etheraddr;
    struct netdev_stats stats;
    /* Tunnels. */
    struct netdev_tunnel_config tnl_cfg;

    int hw_unit;            /* 0 */
    int tnl_state;          /* state of tunnel, created, bound etc...*/
    carrier_t carrier;      /* physical carrier */
    bcmsdk_vport_t vport;   /* bcm related info */
};

static char *events_str[] = {
    "HOST_ADD",
    "HOST_DELETE",
    "ROUTE_ADD",
    "ROUTE_DELETE"
};

static char *tnl_state_str[] = {
    "UNDEFINED",
    "INIT",
    "CREATED",
    "BOUND"
};
struct vport_class {
    const char *dpif_port;
    struct netdev_class netdev_class;
};

static const struct vport_class vport_classes;
static uint16_t tnl_udp_port_min = UDP_PORT_MIN;
static uint16_t tnl_udp_port_max = UDP_PORT_MAX;


static void do_ping(uint32_t *ip_dst);
static void check_route(struct netdev_vport *netdev);
static int  netdev_vport_construct(struct netdev *);
static int  get_tunnel_config(const struct netdev *, struct smap *args);
static bool set_tunnel_nexthop(struct netdev_vport *netdev, int egr_id);
static void init_vport(bcmsdk_vport_t *vport);
static void init_carrier(carrier_t *port);
static bool tunnel_check_status_change__(struct netdev_vport *netdev);



static bool
is_vport_class(const struct netdev_class *class) {
    return class->construct == netdev_vport_construct;
}

static struct netdev_vport *
netdev_vport_cast(const struct netdev *netdev)
{
    ovs_assert(is_vport_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_vport, up);
}

static const struct netdev_tunnel_config *
get_netdev_tunnel_config(const struct netdev *netdev)
{
    return &netdev_vport_cast(netdev)->tnl_cfg;
}

static bool
netdev_vport_needs_dst_port(const struct netdev *dev)
{
    const struct netdev_class *class = netdev_get_class(dev);
    const char *type = netdev_get_type(dev);

    return (class->get_config == get_tunnel_config &&
            (!strcmp("geneve", type) || !strcmp("vxlan", type) ||
             !strcmp("lisp", type) || !strcmp("stt", type)) );
}

static struct netdev *
netdev_vport_alloc(void)
{
    struct netdev_vport *netdev = xzalloc(sizeof *netdev);
    return &netdev->up;
}

static int
netdev_vport_construct(struct netdev *netdev_)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev_);
    const char *type = netdev_get_type(netdev_);
    ovs_mutex_init(&dev->mutex);
    eth_addr_random(&dev->etheraddr);

    /* Add a default destination port for tunnel ports if none specified. */
    if (!strcmp(type, "geneve")) {
        dev->tnl_cfg.dst_port = htons(GENEVE_DST_PORT);
    } else if (!strcmp(type, "vxlan")) {
        dev->tnl_cfg.dst_port = htons(VXLAN_DST_PORT);
    } else if (!strcmp(type, "lisp")) {
        dev->tnl_cfg.dst_port = htons(LISP_DST_PORT);
    } else if (!strcmp(type, "stt")) {
        dev->tnl_cfg.dst_port = htons(STT_DST_PORT);
    }
    dev->tnl_cfg.dont_fragment = true;
    dev->tnl_cfg.ttl = DEFAULT_TTL;

    dev->carrier.status = false;
    dev->hw_unit = 0;
    dev->tnl_state = TNL_UNDEFINED;
    init_vport(&dev->vport);
    init_carrier(&dev->carrier);
    return 0;
}

static void
netdev_vport_destruct(struct netdev *netdev_)
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);
    ovs_mutex_destroy(&netdev->mutex);
}

static void
netdev_vport_dealloc(struct netdev *netdev_)
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);
    free(netdev);
}

static int
netdev_vport_set_etheraddr(struct netdev *netdev_, const struct eth_addr mac)
{
    return 0;
}

static int
netdev_vport_get_etheraddr(const struct netdev *netdev_, struct eth_addr *mac)
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    *mac = netdev->etheraddr;
    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static int
netdev_vport_get_status(const struct netdev *netdev_, struct smap *smap) {
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);
    char buf[20];
    /* TODO, Get the status of the carrier port */
    VLOG_DBG("%s carrier is %d", __func__, netdev->carrier.port);
    if (VALID_PORT(netdev->carrier.port)) {
        sprintf(buf, "%d", netdev->carrier.port);
        smap_add(smap, "tunnel_egress_iface", buf);

        smap_add(smap, "tunnel_egress_iface_carrier",
        netdev->carrier.status ? "up" : "down");
    }
    return 0;
}

static int
netdev_vport_update_flags(struct netdev *netdev OVS_UNUSED,
                          enum netdev_flags off,
                          enum netdev_flags on OVS_UNUSED,
                          enum netdev_flags *old_flagsp)
{
    if (off & (NETDEV_UP | NETDEV_PROMISC)) {
        return EOPNOTSUPP;
    }

    *old_flagsp = NETDEV_UP | NETDEV_PROMISC;
    return 0;
}

/* Code specific to tunnel types. */

static ovs_be64
parse_key(const struct smap *args, const char *name,
                         bool *present, bool *flow)
{
    const char *s;

    *present = false;
    *flow = false;

    s = smap_get(args, name);
    if (!s) {
        s = smap_get(args, "key");
        if (!s) {
            return 0;
        }
    }

    *present = true;
    if (!strcmp(s, "flow")) {
        *flow = true;
        return 0;
    } else {
        return htonll(strtoull(s, NULL, 0));
    }
}

static int
parse_tunnel_ip(const char *value, bool accept_mcast, bool *flow,
                struct in6_addr *ipv6, uint16_t *protocol)
{
    if (!strcmp(value, "flow")) {
        *flow = true;
        *protocol = 0;
        return 0;
    }
    if (addr_is_ipv6(value)) {
        if (lookup_ipv6(value, ipv6)) {
            return ENOENT;
        }
        if (!accept_mcast && ipv6_addr_is_multicast(ipv6)) {
            return EINVAL;
        }
        *protocol = ETH_TYPE_IPV6;
    } else {
        struct in_addr ip;
        if (lookup_ip(value, &ip)) {
            return ENOENT;
        }
        if (!accept_mcast && ip_is_multicast(ip.s_addr)) {
            return EINVAL;
        }
        in6_addr_set_mapped_ipv4(ipv6, ip.s_addr);
        *protocol = ETH_TYPE_IP;
    }
    return 0;
}

static int
set_local_mac(struct netdev_vport *netdev)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_intf_t intf;
    if(!netdev) {
        VLOG_ERR("%s Invalid carrier\n", __func__);
        return 1;
    }
    opennsl_l3_intf_t_init(&intf);
    intf.l3a_intf_id = netdev->vport.l3_intf_id;
    rc = opennsl_l3_intf_get(netdev->hw_unit, &intf);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error, opennsl_l3_intf_get rc:%s l3_intf_id:0x%x\n",
                 opennsl_errmsg(rc), intf.l3a_intf_id);
        return rc;
    }
    ovs_mutex_lock(&netdev->mutex);
    memcpy(netdev->carrier.local_mac, intf.l3a_mac_addr,
           sizeof(netdev->carrier.local_mac));
    ovs_mutex_unlock(&netdev->mutex);
    return rc;
}

static int
get_egr_obj(int hw_unit, int egr_id, opennsl_l3_egress_t *egress_object)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    if(egress_object) {
        opennsl_l3_egress_t_init(egress_object);
        rc = opennsl_l3_egress_get(hw_unit, egr_id, egress_object);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Egress object not found in ASIC for given id rc=%s "
                     " egr-id: %d", opennsl_errmsg(rc), egr_id);
        }
        return rc;
    }
    VLOG_DBG("%s invalid egr object\n",__func__);
    return 1;
}
/*
 * set_tunnel_nexthop
 * Retrieve next hop mac, net port, vlan, l3 intf id and save it
 * in the netdev->vport structure
 */
static bool
set_tunnel_nexthop( struct netdev_vport *netdev, int egr_id)
{
    opennsl_l3_egress_t egress_object;
    if(!get_egr_obj(netdev->hw_unit, egr_id, &egress_object)
                    && VALID_PORT(egress_object.port)) {

        VLOG_DBG("%s L3 EGRESS NH Object port %d, intf %d, flag %x, vlan %d",
                 __func__, egress_object.port, egress_object.intf,
                 egress_object.flags, egress_object.vlan);

        ovs_mutex_lock(&netdev->mutex);
        netdev->carrier.port = egress_object.port;
        netdev->vport.l3_intf_id = egress_object.intf;
        /* Use the default vlan 1024, 1025, ...etc  */
        netdev->vport.vlan = egress_object.vlan;
        memcpy(netdev->carrier.next_hop_mac, egress_object.mac_addr, ETH_ALEN);
        ovs_mutex_unlock(&netdev->mutex);
        /* API needs local mac even though l3 intf id is provided
         * To be discussed and fixed
         */
        set_local_mac(netdev);
        return true;
    }
    return false;
}

/* Called upon tunnel configuration
 * Find out route, next hop and update the carrier config
 */
static void
check_route(struct netdev_vport *netdev)
{
    ovs_be32 route;
    int l3_egress_id;
    /* TODO with ipv6 */
    route = in6_addr_get_mapped_ipv4(&netdev->tnl_cfg.ipv6_dst);
    if (route && ops_egress_lookup_from_dst_ip(netdev->carrier.vrf,
        route, &l3_egress_id)) {
        if(set_tunnel_nexthop(netdev, l3_egress_id)) {
            tunnel_check_status_change__(netdev);
        }
        else {
            VLOG_DBG("Route unresolved. To be resolved by arpmgr "
                     " intd id %d", l3_egress_id);
            /* do_ping(&route); */
        }
    }
}

static int
set_tunnel_config(struct netdev *dev_, const struct smap *args)
{
    struct netdev_vport *dev = netdev_vport_cast(dev_);
    const char *name = netdev_get_name(dev_);
    const char *type = netdev_get_type(dev_);
    bool ipsec_mech_set, needs_dst_port, has_csum;
    uint16_t dst_proto = 0, src_proto = 0;
    struct netdev_tunnel_config tnl_cfg;
    struct smap_node *node;

    if (dev->tnl_state >= TNL_INIT) {
        return 0;
    }
    VLOG_DBG("%s type %s name %s", __func__, type, name);
    has_csum = strstr(type, "gre") || strstr(type, "geneve") ||
               strstr(type, "stt") || strstr(type, "vxlan");
    ipsec_mech_set = false;
    memset(&tnl_cfg, 0, sizeof tnl_cfg);

    /* Add a default destination port for tunnel ports if none specified. */
    if (!strcmp(type, "geneve")) {
        tnl_cfg.dst_port = htons(GENEVE_DST_PORT);
    }

    if (!strcmp(type, "vxlan")) {
        tnl_cfg.dst_port = htons(VXLAN_DST_PORT);
    }

    if (!strcmp(type, "lisp")) {
        tnl_cfg.dst_port = htons(LISP_DST_PORT);
    }

    if (!strcmp(type, "stt")) {
        tnl_cfg.dst_port = htons(STT_DST_PORT);
    }

    needs_dst_port = netdev_vport_needs_dst_port(dev_);
    tnl_cfg.ipsec = strstr(type, "ipsec");
    tnl_cfg.dont_fragment = true;

    SMAP_FOR_EACH (node, args) {
        if (!strcmp(node->key, "remote_ip")) {
            VLOG_INFO("Set_tunnel_config remote_IP %s",node->value);
            int err;
            err = parse_tunnel_ip(node->value, false, &tnl_cfg.ip_dst_flow,
                                  &tnl_cfg.ipv6_dst, &dst_proto);
            switch (err) {
            case ENOENT:
                VLOG_WARN("%s: bad %s 'remote_ip'", name, type);
                break;
            case EINVAL:
                VLOG_WARN("%s: multicast remote_ip=%s not allowed",
                          name, node->value);
                return EINVAL;
            }
        } else if (!strcmp(node->key, "local_ip")) {
            int err;
            VLOG_INFO("Set_tunnel_config local_ip %s",node->value);
            err = parse_tunnel_ip(node->value, true, &tnl_cfg.ip_src_flow,
                                  &tnl_cfg.ipv6_src, &src_proto);
            switch (err) {
            case ENOENT:
                VLOG_WARN("%s: bad %s 'local_ip'", name, type);
                break;
            }
        } else if (!strcmp(node->key, "tos")) {
            if (!strcmp(node->value, "inherit")) {
                tnl_cfg.tos_inherit = true;
            } else {
                char *endptr;
                int tos;
                tos = strtol(node->value, &endptr, 0);
                if (*endptr == '\0' && tos == (tos & IP_DSCP_MASK)) {
                    tnl_cfg.tos = tos;
                } else {
                    VLOG_WARN("%s: invalid TOS %s", name, node->value);
                }
            }
        } else if (!strcmp(node->key, "ttl")) {
            if (!strcmp(node->value, "inherit")) {
                tnl_cfg.ttl_inherit = true;
            } else {
                tnl_cfg.ttl = atoi(node->value);
            }
        } else if (!strcmp(node->key, "dst_port") && needs_dst_port) {
            tnl_cfg.dst_port = htons(atoi(node->value));
        } else if (!strcmp(node->key, "csum") && has_csum) {
            if (!strcmp(node->value, "true")) {
                tnl_cfg.csum = true;
            }
        } else if (!strcmp(node->key, "df_default")) {
            if (!strcmp(node->value, "false")) {
                tnl_cfg.dont_fragment = false;
            }
        } else if (!strcmp(node->key, "peer_cert") && tnl_cfg.ipsec) {
            if (smap_get(args, "certificate")) {
                ipsec_mech_set = true;
            } else {
                const char *use_ssl_cert;

            /* If the "use_ssl_cert" is true, then "certificate" and
             * "private_key" will be pulled from the SSL table.  The
             * use of this option is strongly discouraged, since it
             * will like be removed when multiple SSL configurations
             * are supported by OVS.
             */
            use_ssl_cert = smap_get(args, "use_ssl_cert");
            if (!use_ssl_cert || strcmp(use_ssl_cert, "true")) {
                VLOG_ERR("%s: 'peer_cert' requires 'certificate' argument",
                         name);
                return EINVAL;
            }
                ipsec_mech_set = true;
            }
        } else if (!strcmp(node->key, "psk") && tnl_cfg.ipsec) {
            ipsec_mech_set = true;
        } else if (tnl_cfg.ipsec
                && (!strcmp(node->key, "certificate")
                        || !strcmp(node->key, "private_key")
                        || !strcmp(node->key, "use_ssl_cert"))) {
            /* Ignore options not used by the netdev. */
        } else if (!strcmp(node->key, "key") ||
                   !strcmp(node->key, "in_key") ||
                   !strcmp(node->key, "out_key")) {
            /* Handled separately below. */
        } else if (!strcmp(node->key, "exts")) {
            char *str = xstrdup(node->value);
            char *ext, *save_ptr = NULL;

            tnl_cfg.exts = 0;

            ext = strtok_r(str, ",", &save_ptr);
            while (ext) {
                if (!strcmp(type, "vxlan") && !strcmp(ext, "gbp")) {
                    tnl_cfg.exts |= (1 << OVS_VXLAN_EXT_GBP);
                } else {
                    VLOG_WARN("%s: unknown extension '%s'", name, ext);
                }

                ext = strtok_r(NULL, ",", &save_ptr);
            }

            free(str);
        } else {
            VLOG_WARN("%s: unknown %s argument '%s'", name, type, node->key);
        }
    }

    if (tnl_cfg.ipsec) {
        static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
        static pid_t pid = 0;

        ovs_mutex_lock(&mutex);
        if (pid <= 0) {
        char *file_name = xasprintf("%s/%s", ovs_rundir(),
                                    "ovs-monitor-ipsec.pid");
            pid = read_pidfile(file_name);
            free(file_name);
        }
        ovs_mutex_unlock(&mutex);

        if (pid < 0) {
            VLOG_ERR("%s: IPsec requires the ovs-monitor-ipsec daemon",
                     name);
            return EINVAL;
        }

        if (smap_get(args, "peer_cert") && smap_get(args, "psk")) {
            VLOG_ERR("%s: cannot define both 'peer_cert' and 'psk'", name);
            return EINVAL;
        }

        if (!ipsec_mech_set) {
            VLOG_ERR("%s: IPsec requires an 'peer_cert' or psk' argument",
                     name);
            return EINVAL;
        }
    }

    if (!ipv6_addr_is_set(&tnl_cfg.ipv6_dst) && !tnl_cfg.ip_dst_flow) {
        VLOG_ERR("%s: %s type requires valid 'remote_ip' argument",
                 name, type);
        return EINVAL;
    }
    if (tnl_cfg.ip_src_flow && !tnl_cfg.ip_dst_flow) {
        VLOG_ERR("%s: %s type requires 'remote_ip=flow' with 'local_ip=flow'",
                 name, type);
        return EINVAL;
    }
    if (src_proto && dst_proto && src_proto != dst_proto) {
        VLOG_ERR("%s: 'remote_ip' and 'local_ip' has to be of"
                 " the same address family", name);
        return EINVAL;
    }
    if (!tnl_cfg.ttl) {
        tnl_cfg.ttl = DEFAULT_TTL;
    }

    tnl_cfg.in_key = parse_key(args, "in_key",
                               &tnl_cfg.in_key_present,
                               &tnl_cfg.in_key_flow);

    tnl_cfg.out_key = parse_key(args, "out_key",
                               &tnl_cfg.out_key_present,
                               &tnl_cfg.out_key_flow);
    if(tnl_cfg.in_key_present)
        VLOG_DBG("set_tunnel_config key %lx",
                (unsigned long int)ntohll(tnl_cfg.in_key));

    ovs_mutex_lock(&dev->mutex);
    dev->tnl_cfg = tnl_cfg;
    dev->tnl_state = TNL_INIT;
    netdev_change_seq_changed(dev_);
    ovs_mutex_unlock(&dev->mutex);
    check_route(dev);
    return 0;
}

static int
get_tunnel_config(const struct netdev *dev, struct smap *args)
{
    struct netdev_vport *netdev = netdev_vport_cast(dev);
    struct netdev_tunnel_config tnl_cfg;

    ovs_mutex_lock(&netdev->mutex);
    tnl_cfg = netdev->tnl_cfg;
    ovs_mutex_unlock(&netdev->mutex);

    if (ipv6_addr_is_set(&tnl_cfg.ipv6_dst)) {
        smap_add_ipv6(args, "remote_ip", &tnl_cfg.ipv6_dst);
    } else if (tnl_cfg.ip_dst_flow) {
        smap_add(args, "remote_ip", "flow");
    }

    if (ipv6_addr_is_set(&tnl_cfg.ipv6_src)) {
        smap_add_ipv6(args, "local_ip", &tnl_cfg.ipv6_src);
    } else if (tnl_cfg.ip_src_flow) {
        smap_add(args, "local_ip", "flow");
    }
    if (tnl_cfg.in_key_flow && tnl_cfg.out_key_flow) {
        smap_add(args, "key", "flow");
    } else if (tnl_cfg.in_key_present && tnl_cfg.out_key_present
               && tnl_cfg.in_key == tnl_cfg.out_key) {
        smap_add_format(args, "key", "%"PRIu64, ntohll(tnl_cfg.in_key));
    } else {
        if (tnl_cfg.in_key_flow) {
            smap_add(args, "in_key", "flow");
        } else if (tnl_cfg.in_key_present) {
            smap_add_format(args, "in_key", "%"PRIu64,
                            ntohll(tnl_cfg.in_key));
        }

        if (tnl_cfg.out_key_flow) {
            smap_add(args, "out_key", "flow");
        } else if (tnl_cfg.out_key_present) {
            smap_add_format(args, "out_key", "%"PRIu64,
                            ntohll(tnl_cfg.out_key));
        }
    }

    if (tnl_cfg.ttl_inherit) {
        smap_add(args, "ttl", "inherit");
    } else if (tnl_cfg.ttl != DEFAULT_TTL) {
        smap_add_format(args, "ttl", "%"PRIu8, tnl_cfg.ttl);
    }

    if (tnl_cfg.tos_inherit) {
        smap_add(args, "tos", "inherit");
    } else if (tnl_cfg.tos) {
        smap_add_format(args, "tos", "0x%x", tnl_cfg.tos);
    }

    if (tnl_cfg.dst_port) {
        uint16_t dst_port = ntohs(tnl_cfg.dst_port);
        const char *type = netdev_get_type(dev);

        if ((!strcmp("geneve", type) && dst_port != GENEVE_DST_PORT) ||
            (!strcmp("vxlan", type) && dst_port != VXLAN_DST_PORT) ||
            (!strcmp("lisp", type) && dst_port != LISP_DST_PORT) ||
            (!strcmp("stt", type) && dst_port != STT_DST_PORT)) {
            smap_add_format(args, "dst_port", "%d", dst_port);
        }
    }

    if (tnl_cfg.csum) {
        smap_add(args, "csum", "true");
    }

    if (!tnl_cfg.dont_fragment) {
        smap_add(args, "df_default", "false");
    }

    return 0;
}

static void
init_vport(bcmsdk_vport_t *vport)
{
    if (vport) {
        vport->egr_obj_id = INVALID_VALUE;
        vport->l3_intf_id = INVALID_VALUE;
        vport->tunnel_id = INVALID_VALUE;
        vport->vlan = INVALID_VALUE;
        vport->vxlan_port_id = INVALID_VALUE;
    }
}

static void
init_carrier(carrier_t *port)
{
    if (port) {
        port->port = INVALID_VALUE;
        port->status = false;
        port->vrf = 0;
    }
}

void
netdev_bcmsdk_vport_get_hw_info(struct netdev *netdev,
                 int *hw_unit, int *hw_id, uint8_t *hwaddr)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    ovs_assert(is_vport_class(netdev_get_class(netdev)));
    *hw_unit = dev->hw_unit;
    if (hw_id) {
        *hw_id = -1;
    }
    if (hwaddr) {
        *((struct eth_addr *)hwaddr) = dev->etheraddr;
    }
}

int
netdev_bcmsdk_vport_get_tunnel_id(struct netdev *netdev, int *tunnel_id) {
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    if (tunnel_id) {
        ovs_mutex_lock(&dev->mutex);
        *tunnel_id = dev->vport.tunnel_id;
        ovs_mutex_unlock(&dev->mutex);
    }
    return 0;
}

void
netdev_bcmsdk_vport_set_tunnel_id(struct netdev *netdev, int tunnel_id, int state)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    ovs_mutex_lock(&dev->mutex);
    dev->vport.tunnel_id = tunnel_id;
    dev->tnl_state = state;
    ovs_mutex_unlock(&dev->mutex);
}

const bcmsdk_vport_t *
netdev_bcmsdk_vport_get_tunnel_vport(struct netdev *netdev)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    return &dev->vport;
}
const carrier_t *
netdev_bcmsdk_vport_get_carrier(struct netdev *netdev)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    return &dev->carrier;
}
/* Return vxlan_port id given port name */
bool
netdev_bcmsdk_vport_get_vport_id(char *port, int* vxlan_port_id)
{
    struct netdev *netdev_;
    int ret = false;
    if(port && vxlan_port_id) {
        netdev_ = netdev_from_name(port);
        if(netdev_ && is_vport_class(netdev_get_class(netdev_))) {
            struct netdev_vport *dev = netdev_vport_cast(netdev_);
            if(dev->tnl_state == TNL_BOUND) {
                ovs_mutex_lock(&dev->mutex);
                *vxlan_port_id = dev->vport.vxlan_port_id;
                ovs_mutex_unlock(&dev->mutex);
                ret = true;
            }
            netdev_close(netdev_);
        }
    }
    return ret;
}
void
netdev_bcmsdk_vport_set_tunnel_vport(struct netdev *netdev,
                                     bcmsdk_vxlan_port_t * vport)
{
    struct netdev_vport *dev  = netdev_vport_cast(netdev);
    if(vport) {
        dev = netdev_vport_cast(netdev);
        ovs_mutex_lock(&dev->mutex);
        dev->vport.egr_obj_id = vport->egr_obj_id;
        dev->vport.station_id = vport->station_id;
        dev->vport.vxlan_port_id = vport->vxlan_port_id;
        dev->tnl_state = TNL_BOUND;
        ovs_mutex_unlock(&dev->mutex);
    }
}
void
netdev_bcmsdk_vport_reset_tunnel_vport(struct netdev *netdev)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
        ovs_mutex_lock(&dev->mutex);
        dev->tnl_state = TNL_CREATED;
        dev->vport.egr_obj_id = INVALID_VALUE;
        dev->vport.station_id = INVALID_VALUE;
        dev->vport.vxlan_port_id = INVALID_VALUE;
        dev->carrier.port = INVALID_VALUE;
        ovs_mutex_unlock(&dev->mutex);
}

static bool
tunnel_check_status_change__(struct netdev_vport *dev)
{
    bool status = false;
    int change = false;
    ovs_mutex_lock(&dev->mutex);
    if(!VALID_PORT(dev->carrier.port)) {
        if(dev->carrier.status) {
            dev->carrier.status = false;
            change = true;
        }
    } else {
        status = netdevv_bcmsdk_get_link_status(dev->hw_unit,
                                                dev->carrier.port);
        if(dev->carrier.status != status) {
            dev->carrier.status = status;
            VLOG_DBG("%s port %d status %s", __func__,dev->carrier.port,
                      status? "up":"down");
            change = true;
        }
    }
    ovs_mutex_unlock(&dev->mutex);
    return change;
}

static void
create_tunnel(struct netdev_vport *netdev, int l3_egress_id)
{
    switch (netdev->tnl_state) {
        case TNL_INIT:
            /*Tunnel doesn't exist.  Route up, create tunnel and bind port*/
            if(!ops_vport_create_tunnel(&netdev->up)) {
                ops_vport_bind_net_port(&netdev->up);
            }
            break;
        case TNL_CREATED:
            /*Tunnel exists and not bound.  Bind it to this net port*/
            ops_vport_bind_net_port(&netdev->up);
            break;
        default:
            break;
    }
}

/*
 * When destination host is deleted, unbind tunnel
 * When destination host is added, create tunnel and bind it
 */
static void
upon_host_chg(int event, struct netdev_vport *netdev, int l3_egr_id)
{
    if(TUNNEL_UNBIND(event, netdev->tnl_state)) {
        ops_vport_unbind_net_port(&netdev->up);
        return;
    }
    if(set_tunnel_nexthop(netdev, l3_egr_id)) {
        create_tunnel(netdev, l3_egr_id);
    }
}
/*
 * In case there is no Gateway, there is no egress object saved
 * in provider's cache (Why? To find out if it's a bug). Therefore
 * Searching for next hop mac will fail when route is up.
 * This function catches when host is added and thus having
 * the neighbor mac if its dest IP matches host IP.
 * However, if link down and up again or route down or up again
 * Asic doesn't receive any trigger to add host again (bug?)
 *
 */
void
netdev_vport_update_host_chg(int event, int port, char *ip_addr,
        int l3_egress_id)
{
    struct shash device_shash;
    struct shash_node *node;
    ovs_be32 ipv4;
    struct netdev_vport *dev;
    char ip[INET_ADDRSTRLEN];
    int count = 0;
    if(!ip_addr) {
        VLOG_ERR("%s Null pointer\n", __func__);
        return;
    }
    shash_init(&device_shash);
    netdev_get_devices(&vport_classes.netdev_class, &device_shash);
    SHASH_FOR_EACH (node, &device_shash) {
        struct netdev *netdev = node->data;
        if(netdev) {
            dev = netdev_vport_cast(netdev);
            if(dev && (TUNNEL_ACTION(event, dev->tnl_state))) {
                count++;
                ipv4 =  in6_addr_get_mapped_ipv4(&dev->tnl_cfg.ipv6_dst);
                if(!ipv4) {
                    /* IPV6 To be supported */
                    netdev_close(netdev);
                    continue;
                }
                VLOG_DBG("%s event %d, tnl state %s\n", dev->up.name,
                         event, tnl_state_str[dev->tnl_state]);
                inet_ntop(AF_INET, &ipv4, ip, INET_ADDRSTRLEN);

                /* If destination IP matches host,it's neighbor */
                if(strcmp(ip, ip_addr) == 0) {
                    upon_host_chg(event, dev, l3_egress_id);
                }
            }
            netdev_close(netdev);
        }
    }
    shash_destroy(&device_shash);
    VLOG_DBG("%s Number of tunnels %d", __func__, count);
}

uint32_t
get_prefix_len(const char * route_prefix)
{
    char *p = strchr(route_prefix, '/');
    if(p) {
        return atoi(++p);
    }
    return 0;
}

/*
 * Input: net byte order ipv4
 * Out put: route_prefix string
 * X.X.X.X/Y
 */
static void
ip_to_prefix(uint32_t ip, uint32_t prefix_len, char *ip_prefix)
{
    uint32_t prefix, len;
    if(ip_prefix) {
        prefix = ip & be32_prefix_mask(prefix_len);
        inet_ntop(AF_INET, &prefix, ip_prefix, INET_ADDRSTRLEN);
        len = strlen(ip_prefix);
        snprintf(&ip_prefix[len],INET_ADDRSTRLEN - len, "/%d", prefix_len);
    }
}
/*
 * When route is deleted and tunnel is bound to this route,
 * unbind tunnel
 * When route is added and tunnel is not created or not bound,
 * create tunnel and bind it
 */
static void
upon_route_chg(struct netdev_vport *dev, int event, char *route_prefix)
{
    int l3_egr_id;
    VLOG_DBG("%s Event %s Tunnel state %s\n", __func__, events_str[event],
             tnl_state_str[dev->tnl_state]);

    if(TUNNEL_BIND(event, dev->tnl_state)) {

        if(ops_egress_lookup_from_route(dev->carrier.vrf, route_prefix, &l3_egr_id)) {
            if(set_tunnel_nexthop(dev, l3_egr_id)) {
                create_tunnel(dev, l3_egr_id);
            } else {
                /* Arpmgrd will take care of this
                ovs_be32 ipv4;
                ipv4 =  in6_addr_get_mapped_ipv4(&dev->tnl_cfg.ipv6_dst);
                if(ipv4) {
                    do_ping(&ipv4);
                }
                */
            }
        }

    } else if(TUNNEL_UNBIND(event, dev->tnl_state)) {
        VLOG_DBG("Event %s - State BOUND\n", events_str[event]);
        ops_vport_unbind_net_port(&dev->up);
    }

}
/*
 * When ASIC receives Route Action (Add, Delete),
 * This function will traverse the netdev hashmap, pick out
 * the tunnel device and compare its destination ip with
 * the route prefix. If there is a match, it will
 * creat/bind/unbind tunnels depending on the
 * tunnel state and route action
 */
void
netdev_vport_update_route_chg(int event, char* route_prefix)
{
    struct shash device_shash;
    struct shash_node *node;
    struct netdev_vport *dev;
    ovs_be32 ipv4;
    int count = 0;
    int plen = get_prefix_len(route_prefix);
    char ip_prefix[INET_ADDRSTRLEN];
    if(!route_prefix) {
        VLOG_DBG("%s Null pointer \n", __func__);
        return;
    }
    VLOG_DBG("%s entered route prefix %s", __func__,route_prefix);
    shash_init(&device_shash);
    netdev_get_devices(&vport_classes.netdev_class, &device_shash);
    SHASH_FOR_EACH (node, &device_shash) {
        struct netdev *netdev = node->data;
        if(netdev) {
            dev = netdev_vport_cast(netdev);
            if(dev) {
                count++;
                VLOG_DBG("%s", dev->up.name);
                ipv4 =  in6_addr_get_mapped_ipv4(&dev->tnl_cfg.ipv6_dst);
                if(!ipv4) {
                    /* IPV6 To be supported */
                    netdev_close(netdev);
                    continue;
                }
                ip_to_prefix(ipv4, plen, ip_prefix);
                if(strcmp(ip_prefix, route_prefix)== 0){
                    upon_route_chg(dev, event, route_prefix);
                }
            }
            netdev_close(netdev);
        }
    }
    shash_destroy(&device_shash);
    VLOG_DBG("%s Number of tunnels %d", __func__, count);
}

/* ip_dst is in host byte order */
OVS_UNUSED static void
do_ping(uint32_t *ip_dst)
{
    char ip[INET_ADDRSTRLEN];
    char cmd[128];
    if(ip_dst) {
        inet_ntop(AF_INET, ip_dst, ip, INET_ADDRSTRLEN);
        snprintf(cmd, sizeof(cmd), "ping -c 3 %s", ip);
        VLOG_INFO("%s %s\n", __func__, cmd);
        system(cmd);
    }
}

static void
tunnel_print(struct ds *ds, const struct netdev_tunnel_config *tnl_cfg)
{
    char remote_ip[INET_ADDRSTRLEN];
    char local_ip[INET_ADDRSTRLEN];
    ovs_be32 ipv4_dst;
    ovs_be32 ipv4_src;
    if (!tnl_cfg) {
        ds_put_format(ds, "%s ERR: tnl_cfg is NULL", __func__);
        return;
    }
    ipv4_dst = in6_addr_get_mapped_ipv4(&tnl_cfg->ipv6_dst);
    inet_ntop(AF_INET, &ipv4_dst, remote_ip, INET_ADDRSTRLEN);
    ipv4_src = in6_addr_get_mapped_ipv4(&tnl_cfg->ipv6_src);
    inet_ntop(AF_INET, &ipv4_src, local_ip, INET_ADDRSTRLEN);
    if (tnl_cfg->in_key_present) {
        if (tnl_cfg->in_key_flow)
            ds_put_format(ds, "key = flow");
        else {
            ds_put_format(ds, "key = 0x%lx",
                    (unsigned long int )htonll(tnl_cfg->in_key));
        }
    }
    ds_put_format(ds, "TUNNEL CONFIG:\n"
             "remote_ip = %s     <%lx>\n"
             "local_ip  = %s     <%lx>\n"
             "ttl       = %d\n"
             "destination UDP port %d\n", remote_ip,
             (long unsigned int )ntohl(ipv4_dst), local_ip,
             (long unsigned int )ntohl(ipv4_src), tnl_cfg->ttl,
             tnl_cfg->dst_port);
}

OVS_UNUSED static void
tunnel_dump(const struct netdev_tunnel_config *tnl_cfg)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    tunnel_print(&ds, tnl_cfg);
    VLOG_DBG("%s",ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
carrier_print(struct ds *ds, carrier_t *carrier)
{
    if (!carrier || !ds) {
        ds_put_format(ds, "%s ERR: carrier is NULL", __func__);
        return;
    }
    ds_put_format(ds, "\nCARRIER PORT:\n");
    ds_put_format(ds, "port %5d  vrf  %5d status %s\n",\
                  carrier->port, carrier->vrf, carrier->status? "up":"down");
    ds_put_format(ds, mac_format(carrier->local_mac));
    ds_put_format(ds, mac_format(carrier->next_hop_mac));
}

static void
vport_print(struct ds *ds, bcmsdk_vport_t *vport)
{
    if (!vport || !ds) {
        ds_put_format(ds, "%s ERR: vport is NULL", __func__);
        return;
    }
    ds_put_format(ds, "\nVXLAN PORT:\n");
    ds_put_format(ds, "tunnel_id     = 0x%x\n"
                      "vxlan_port_id = 0x%x\n"
                      "l3_intf_id    = %d\n"
                      "egr_obj_id    = 0x%x\n"
                      "station_id    = %d\n"
                      ,vport->tunnel_id, vport->vxlan_port_id
                      ,vport->l3_intf_id,vport->egr_obj_id
                      ,vport->station_id);
}

OVS_UNUSED static void
vport_dump(bcmsdk_vport_t *vport)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    vport_print(&ds, vport);
    VLOG_DBG("%s",ds_cstr(&ds));
    ds_destroy(&ds);
}


static void
netdev_vport_dump(struct ds *ds)
{
    struct shash device_shash;
    struct shash_node *node;
    int count = 0;
    shash_init(&device_shash);
    netdev_get_devices(&vport_classes.netdev_class, &device_shash);
    SHASH_FOR_EACH (node, &device_shash) {
        struct netdev *netdev = node->data;
        if(netdev) {
            struct netdev_vport *dev = netdev_vport_cast(netdev);
            if(dev) {
                VLOG_DBG("\nTUNNEL %s state %s\n",
                         dev->up.name,tnl_state_str[dev->tnl_state]);
                tunnel_print(ds, &dev->tnl_cfg);
                carrier_print(ds, &dev->carrier);
                vport_print(ds, &dev->vport);
                VLOG_DBG("%s",ds_cstr(ds));
                count++;
            }
            netdev_close(netdev);
        }
    }
    shash_destroy(&device_shash);
    VLOG_DBG("%s COUNT OF VPORT %d", __func__, count);
}

/* convert const ascii mac string to 48 bit ethernet addr */
static void
converting_mac(const char * mac, uint8_t *ether_addr)
{
    char mac_[32];
    struct ether_addr *ether_mac;
    /* change from const char to none const char */
    snprintf(mac_,sizeof(mac_), mac);
    ether_mac = ether_aton(mac_);
    if(ether_mac && ether_addr) {
        memcpy(ether_addr, ether_mac, ETH_ALEN);
    } else {
        VLOG_ERR("Failed converting_mac\n");
    }
}

/*
 * Setting up next hop information from terminal,
 * For testing tunnel using l2 port as carrier
 */
static void
vport_bind_from_term(struct ds *ds, int argc, const char *argv[])
{
    char tnl_name[32];
    struct netdev *netdev_;
    snprintf(tnl_name,sizeof(tnl_name),argv[1]);
    netdev_ = netdev_from_name(tnl_name);
    VLOG_DBG("%s, tnl_name %s", __func__, tnl_name);
    if(netdev_ && is_vport_class(netdev_get_class(netdev_)))
    {
        struct netdev_vport *dev = netdev_vport_cast(netdev_);
        ds_put_format(ds, "Nexthop Data for Tunnel %s:\n", tnl_name);
        if(dev) {
            dev->carrier.port = atoi(argv[2]);
            dev->vport.l3_intf_id = atoi(argv[5]);
            converting_mac(argv[3], dev->carrier.local_mac);
            converting_mac(argv[4], dev->carrier.next_hop_mac);
            if(argc > 6) {
                dev->vport.vlan = atoi(argv[6]);
                ds_put_format(ds, "vlan %d\n", dev->vport.vlan);
            }
            ds_put_format(ds, "port %d, intf id %d vlan %d\n",
                          dev->carrier.port, dev->vport.l3_intf_id,
                          dev->vport.l3_intf_id);
            ds_put_format(ds, mac_format(dev->carrier.local_mac));

            ds_put_format(ds, mac_format(dev->carrier.next_hop_mac));
            if(!ops_vport_create_tunnel(&dev->up)) {
                 ops_vport_bind_net_port(&dev->up);
            }
        }
        netdev_close(netdev_);
    }
}

static void
diag_netdev_vport_dump(struct unixctl_conn *conn, int argc,
                               const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    netdev_vport_dump(&ds);
    unixctl_command_reply(conn,ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
diag_set_nexthop(struct unixctl_conn *conn, int argc,
                               const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    vport_bind_from_term(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
netdev_vport_range(struct unixctl_conn *conn, int argc,
    const char *argv[], void *aux OVS_UNUSED) {
    int val1, val2;

    if (argc < 3) {
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds,
            "Tunnel UDP source port range: %"PRIu16"-%"PRIu16"\n",
            tnl_udp_port_min, tnl_udp_port_max);

        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);
        return;
    }

    if (argc != 3) {
        return;
    }

    val1 = atoi(argv[1]);
    if (val1 <= 0 || val1 > UINT16_MAX) {
        unixctl_command_reply(conn, "Invalid min.");
        return;
    }
    val2 = atoi(argv[2]);
    if (val2 <= 0 || val2 > UINT16_MAX) {
        unixctl_command_reply(conn, "Invalid max.");
        return;
    }

    if (val1 > val2) {
        tnl_udp_port_min = val2;
        tnl_udp_port_max = val1;
    } else {
        tnl_udp_port_min = val1;
        tnl_udp_port_max = val2;
    }
    seq_change(tnl_conf_seq);

    unixctl_command_reply(conn, "OK");
}


#define VPORT_FUNCTIONS(GET_CONFIG, SET_CONFIG,             \
                        GET_TUNNEL_CONFIG, GET_STATUS,      \
                        BUILD_HEADER,                       \
                        PUSH_HEADER, POP_HEADER)            \
    NULL,                                                   \
    NULL,                                                   \
    NULL,                                                   \
                                                            \
    netdev_vport_alloc,                                     \
    netdev_vport_construct,                                 \
    netdev_vport_destruct,                                  \
    netdev_vport_dealloc,                                   \
    GET_CONFIG,                                             \
    SET_CONFIG,                                             \
    NULL,                       /* set_hw_intf_info  */     \
    NULL,                       /* set_hw_intf_config */    \
    GET_TUNNEL_CONFIG,                                      \
    BUILD_HEADER,                                           \
    PUSH_HEADER,                                            \
    POP_HEADER,                                             \
    NULL,                       /* get_numa_id */           \
    NULL,                       /* set_multiq */            \
                                                            \
    NULL,                       /* send */                  \
    NULL,                       /* send_wait */             \
    netdev_vport_set_etheraddr,                             \
    netdev_vport_get_etheraddr,                             \
    NULL,                       /* get_mtu */               \
    NULL,                       /* set_mtu */               \
    NULL,                       /* get_ifindex */           \
    NULL,                       /* get_carrier */           \
    NULL,                       /* get_carrier_resets */    \
    NULL,                       /* get_miimon */            \
    NULL,                                                   \
                                                            \
    NULL,                       /* get_features */          \
    NULL,                       /* set_advertisements */    \
                                                            \
    NULL,                       /* set_policing */          \
    NULL,                       /* get_qos_types */         \
    NULL,                       /* get_qos_capabilities */  \
    NULL,                       /* get_qos */               \
    NULL,                       /* set_qos */               \
    NULL,                       /* get_queue */             \
    NULL,                       /* set_queue */             \
    NULL,                       /* delete_queue */          \
    NULL,                       /* get_queue_stats */       \
    NULL,                       /* queue_dump_start */      \
    NULL,                       /* queue_dump_next */       \
    NULL,                       /* queue_dump_done */       \
    NULL,                       /* dump_queue_stats */      \
                                                            \
    NULL,                       /* get_in4 */               \
    NULL,                       /* set_in4 */               \
    NULL,                       /* get_in6 */               \
    NULL,                       /* add_router */            \
    NULL,                       /* get_next_hop */          \
    GET_STATUS,                                             \
    NULL,                       /* arp_lookup */            \
                                                            \
    netdev_vport_update_flags,                              \
                                                            \
    NULL,                   /* rx_alloc */                  \
    NULL,                   /* rx_construct */              \
    NULL,                   /* rx_destruct */               \
    NULL,                   /* rx_dealloc */                \
    NULL,                   /* rx_recv */                   \
    NULL,                   /* rx_wait */                   \
    NULL,                   /* rx_drain */

#define TUNNEL_CLASS(NAME, DPIF_PORT, BUILD_HEADER, PUSH_HEADER, POP_HEADER) \
    { DPIF_PORT,                                                             \
        { NAME, VPORT_FUNCTIONS(get_tunnel_config,                           \
                                set_tunnel_config,                           \
                                get_netdev_tunnel_config,                    \
                                netdev_vport_get_status,                     \
                                BUILD_HEADER, PUSH_HEADER, POP_HEADER) }}

static const struct vport_class vport_classes =
    TUNNEL_CLASS("vxlan", "vxlan_sys", NULL,NULL,NULL);


void netdev_bcmsdk_vport_register(void) {
    /* The name of the dpif_port should be short enough to accomodate adding
     * a port number to the end if one is necessary. */

    netdev_register_provider(&vport_classes.netdev_class);
    unixctl_command_register("tnl/egress_port_range", "min max", 0, 2,
                             netdev_vport_range, NULL);
    unixctl_command_register("tnl/dump", "", 0, 0,
                             diag_netdev_vport_dump, NULL);
    /* Setting next hop from terminal for debug */
    unixctl_command_register("tnl/nexthop", "[tunnel netport localmac"
                             " remotemac, l3intf_id vlan (optional)]", 5, 6,
                             diag_set_nexthop, NULL);

}
