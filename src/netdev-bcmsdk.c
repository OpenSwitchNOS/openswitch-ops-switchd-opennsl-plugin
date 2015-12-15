/*
 * Copyright (C) 2015 Hewlett-Packard Development Company, L.P.
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
 * File: netdev-bcmsdk.c
 */

#include <config.h>
#include <errno.h>
#include <linux/ethtool.h>
#include <netinet/ether.h>

#include <netdev-provider.h>
#include <openvswitch/vlog.h>
#include <openflow/openflow.h>
#include <openswitch-idl.h>
#include <openswitch-dflt.h>

#include <opennsl/port.h>

#include "ops-port.h"
#include "ops-knet.h"
#include "ops-stats.h"
#include "platform-defines.h"
#include "netdev-bcmsdk.h"
#include "ops-routing.h"

VLOG_DEFINE_THIS_MODULE(netdev_bcmsdk);

#define MAX_KEY_LENGTH 12

/* Protects 'bcmsdk_list'. */
static struct ovs_mutex bcmsdk_list_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct bcmsdk_dev's. */
static struct ovs_list bcmsdk_list OVS_GUARDED_BY(bcmsdk_list_mutex)
    = OVS_LIST_INITIALIZER(&bcmsdk_list);

struct deleted_stats {
    uint32_t packets;
    uint32_t bytes;
};

struct netdev_bcmsdk {
    struct netdev up;

    /* In bcmsdk_list. */
    struct ovs_list list_node OVS_GUARDED_BY(bcmsdk_list_mutex);

    /* Protects all members below. */
    struct ovs_mutex mutex OVS_ACQ_AFTER(bcmsdk_list_mutex);

    uint8_t hwaddr[ETH_ADDR_LEN] OVS_GUARDED;
    int mtu OVS_GUARDED;
    struct netdev_stats stats OVS_GUARDED;
    enum netdev_flags flags OVS_GUARDED;
    long long int link_resets OVS_GUARDED;

    int hw_unit;
    int hw_id;
    int l3_intf_id;
    int knet_if_id;             /* BCM KNET interface ID. */
    int knet_filter_id;         /* BCM KNET filter ID. */

    bool intf_initialized;

    /* Port Configuration. */
    struct port_cfg pcfg;

    /* Port info structure. */
    struct ops_port_info *port_info;

    /* ----- Subport/lane split config (e.g. QSFP+) ----- */

     /* Boolean indicating if this is a split parent or subport:
     *  - Parent port refers to the base port that is not split.
     *  - Subports refers to all individual ports after the
     *    parent port is split.
     * Note that these two booleans can never both be true at the
     * same time, and the parent port and the first subport are
     * mutually exclusive since they map to the same h/w port.
     */
    bool is_split_parent;
    bool is_split_subport;

    /* Pointer to parent port port_info data.
     * Valid for split children ports only. */
    struct ops_port_info *split_parent_portp;

    /* hashmap of the egress object id, num and stat id
     * associated with the l3 interface */
    struct hmap egress_id_map;

    /* ingress stats object struct */
    struct ops_l3_stats_ingress ingress_stats_object;

    /* Running counter of total egress object level
     * stats deleted for the l3 interface */
    struct ops_deleted_stats deleted_stats_counter;
};

static int netdev_bcmsdk_construct(struct netdev *);

static bool
is_bcmsdk_class(const struct netdev_class *class)
{
    return class->construct == netdev_bcmsdk_construct;
}

static struct netdev_bcmsdk *
netdev_bcmsdk_cast(const struct netdev *netdev)
{
    ovs_assert(is_bcmsdk_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_bcmsdk, up);
}

void
netdev_bcmsdk_get_hw_info(struct netdev *netdev, int *hw_unit, int *hw_id,
                          uint8_t *hwaddr)
{
    struct netdev_bcmsdk *nb = netdev_bcmsdk_cast(netdev);
    ovs_assert(is_bcmsdk_class(netdev_get_class(netdev)));

    *hw_unit = nb->hw_unit;
    *hw_id = nb->hw_id;
    if (hwaddr) {
        memcpy(hwaddr, nb->hwaddr, ETH_ADDR_LEN);
    }
}

static struct netdev_bcmsdk *
netdev_from_hw_id(int hw_unit, int hw_id)
{
    struct netdev_bcmsdk *netdev = NULL;
    bool found = false;

    ovs_mutex_lock(&bcmsdk_list_mutex);
    LIST_FOR_EACH(netdev, list_node, &bcmsdk_list) {
        if ((netdev->hw_unit == hw_unit) &&
            (netdev->hw_id == hw_id)) {

            /* If the port is splittable, and it is
             * split into child ports, then skip it. */
            if (netdev->is_split_parent &&
                netdev->port_info->lanes_split_status == true) {
                continue;
            }
            found = true;
            break;
        }
    }
    ovs_mutex_unlock(&bcmsdk_list_mutex);
    return (found == true) ? netdev : NULL;
}

static struct netdev *
netdev_bcmsdk_alloc(void)
{
    struct netdev_bcmsdk *netdev = xzalloc(sizeof *netdev);
    VLOG_DBG("Netdev alloc called");
    return &netdev->up;
}

static int
netdev_bcmsdk_construct(struct netdev *netdev_)
{
    static atomic_count next_n = ATOMIC_COUNT_INIT(0xaa550000);
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    unsigned int n;

    VLOG_DBG("Netdev construct called");
    n = atomic_count_inc(&next_n);

    ovs_mutex_init(&netdev->mutex);
    ovs_mutex_lock(&netdev->mutex);

    /* XXX: We should use MAC address defined in the
     * INTERFACE table instead of a randomly generated one. */
    netdev->hwaddr[0] = 0xaa;
    netdev->hwaddr[1] = 0x55;
    netdev->hwaddr[2] = n >> 24;
    netdev->hwaddr[3] = n >> 16;
    netdev->hwaddr[4] = n >> 8;
    netdev->hwaddr[5] = n;
    netdev->mtu = 1500;
    netdev->flags = 0;

    netdev->hw_unit = -1;
    netdev->hw_id = -1;
    netdev->knet_if_id = 0;
    netdev->knet_filter_id = 0;
    netdev->port_info = NULL;
    netdev->intf_initialized = false;

    netdev->is_split_parent = false;
    netdev->is_split_subport = false;
    netdev->split_parent_portp = NULL;

    hmap_init(&netdev->egress_id_map);

    ovs_mutex_unlock(&netdev->mutex);

    ovs_mutex_lock(&bcmsdk_list_mutex);
    list_push_back(&bcmsdk_list, &netdev->list_node);
    ovs_mutex_unlock(&bcmsdk_list_mutex);

    return 0;
}

static void
netdev_bcmsdk_destruct(struct netdev *netdev_)
{
    int rc = 0;
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    VLOG_DBG("Calling Netdev destruct. name=%s unit=%d port=%d",
             netdev->up.name, netdev->hw_unit, netdev->hw_id);
    ovs_mutex_lock(&bcmsdk_list_mutex);

    if(netdev->knet_if_id) {
        rc = bcmsdk_knet_if_delete(netdev->up.name, netdev->hw_unit, netdev->knet_if_id);
    }

    if (rc) {
        VLOG_ERR("Failed to delete kernel KNET interface %s", netdev->up.name);
    }

    list_remove(&netdev->list_node);
    ovs_mutex_unlock(&bcmsdk_list_mutex);
}

static void
netdev_bcmsdk_dealloc(struct netdev *netdev_)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    struct ops_stats_egress_id    *egress_id_node;
    int rc = 0;

    /* Iterate through egress object hashmap and get all stats object
     * to be removed. */
    HMAP_FOR_EACH(egress_id_node, egress_node, &(netdev->egress_id_map)) {
        VLOG_DBG("Iterating through hmap for id: %d",
                  egress_id_node->egress_object_id);
        /* Make sure we detach the egress stats objects and destroy them before
         * removing it from our local cache.
         */
        rc = opennsl_l3_egress_stat_detach(netdev->hw_unit, egress_id_node->egress_object_id);
        if (rc) {
            VLOG_ERR("Failed to detach stats from egress object id : %d",
                      egress_id_node->egress_object_id);
        }

        rc = opennsl_stat_group_destroy(netdev->hw_unit, egress_id_node->egress_stat_id);
        if (rc) {
            VLOG_ERR("Failed to destroy stats group for egress object id : %d",
                      egress_id_node->egress_object_id);
        }

        hmap_remove(&(netdev->egress_id_map), &(egress_id_node->egress_node));
        free(egress_id_node);
    }

    /* Destroy the hashmap once all of the entries are removed  and freed. */
    hmap_destroy(&netdev->egress_id_map);

    /* Now detach the ingress stats object and destroy it before freeing
     * netdev.
     */
    rc = opennsl_l3_ingress_stat_detach(netdev->hw_unit,
                                 netdev->ingress_stats_object.ingress_vlan_id);
    if (rc) {
        VLOG_ERR("Failed to detach stats from ingress vlan id : %d",
                  netdev->ingress_stats_object.ingress_vlan_id);
    }

    rc = opennsl_stat_group_destroy(netdev->hw_unit,
                  netdev->ingress_stats_object.ingress_stat_id);
    if (rc) {
        VLOG_ERR("Failed to destroy stats group for ingress vlan id : %d",
                  netdev->ingress_stats_object.ingress_vlan_id);
    }

    free(netdev);

}

static int
netdev_bcmsdk_set_hw_intf_info(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    struct netdev *p_netdev_ = NULL;
    struct netdev_bcmsdk *p_netdev = NULL;
    struct ops_port_info *p_info = NULL;
    struct ether_addr ZERO_MAC = {{0}};
    struct ether_addr *ether_mac = NULL;
    int rc = 0;

    const char *hw_unit = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_SWITCH_UNIT);
    const char *hw_id = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_SWITCH_INTF_ID);
    const char *mac_addr = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_MAC_ADDR);
    const char *is_splittable = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_SPLIT_4);
    const char *split_parent = smap_get(args, INTERFACE_HW_INTF_INFO_SPLIT_PARENT);

    VLOG_DBG("netdev set_hw_intf_info for interace %s", netdev->up.name);

    ovs_mutex_lock(&netdev->mutex);

    if (netdev->intf_initialized == false) {

        netdev->hw_unit = (hw_unit) ? atoi(hw_unit) : -1;
        if (!VALID_HW_UNIT(netdev->hw_unit)) {
            VLOG_ERR("Invalid switch unit id %s", hw_unit);
            goto error;
        }

        netdev->hw_id = (hw_id) ? atoi(hw_id) : -1;
        if (netdev->hw_id <= 0) {
            VLOG_ERR("Invalid switch port id %s", hw_id);
            goto error;
        }

        if (mac_addr) {
            ether_mac = ether_aton(mac_addr);
            if (ether_mac != NULL) {
                memcpy(netdev->hwaddr, ether_mac, ETH_ALEN);
            } else {
                ether_mac = &ZERO_MAC;
            }
        }

        /* Get the port_info struct for a given hardware unit & port number. */
        p_info = PORT_INFO(netdev->hw_unit, netdev->hw_id);
        if (NULL == p_info) {
            VLOG_ERR("Unable to get port info struct for "
                     "Interface=%s, hw_unit=%d, hw_id=%d",
                     netdev->up.name, netdev->hw_unit, netdev->hw_id);
            goto error;
        }

        /* Save the port_info porinter in netdev struct. */
        netdev->port_info = p_info;

        /* Save the hardware unit & port number in port_info struct. */
        p_info->hw_unit = netdev->hw_unit;
        p_info->hw_port = netdev->hw_id;
        p_info->name = xstrdup(netdev->up.name);

        /* For all the ports that can be split into multiple
         * subports, 'split_4' property is set to true.
         * This is set only on the parent ports. */
        if (STR_EQ(is_splittable, "true")) {

            netdev->is_split_parent = true;
            p_info->split_port_count = MAX_QSFP_SPLIT_PORT_COUNT;
            p_info->lanes_split_status = false;

        } else {

            /* For all the split children ports 'split_parent'
             * property is set to the name of the parent port.
             * This is done in subsystem.c file. */
            if (split_parent != NULL) {

                netdev->is_split_subport = true;

                /* Get parent ports netdev struct. */
                p_netdev_ = netdev_from_name(split_parent);
                if (p_netdev_ != NULL) {
                    p_netdev = netdev_bcmsdk_cast(p_netdev_);

                    /* Save pointer to parent port's port_info struct. */
                    netdev->split_parent_portp = p_netdev->port_info;

                    /* netdev_from_name() opens a reference, so we need to close it here. */
                    netdev_close(p_netdev_);

                } else {
                    VLOG_ERR("Unable to find the netdev for the parent port. "
                             "intf_name=%s parent_name=%s",
                             netdev->up.name, split_parent);
                    goto error;
                }
            }
        }

        rc = bcmsdk_knet_if_create(netdev->up.name, netdev->hw_unit,
                                   netdev->hw_id, ether_mac,
                                   &(netdev->knet_if_id));
        if (rc) {
            VLOG_ERR("Failed to initialize interface %s", netdev->up.name);
        } else {
            netdev->intf_initialized = true;
        }
    }
    ovs_mutex_unlock(&netdev->mutex);
    return 0;

error:
    ovs_mutex_unlock(&netdev->mutex);

    rc = -EINVAL;
    return rc;
}

static void
get_interface_autoneg_config(const char *autoneg_cfg, int *autoneg)
{
        /* Auto negotiation configuration. */
        if (STR_EQ(autoneg_cfg, INTERFACE_HW_INTF_CONFIG_MAP_AUTONEG_ON)) {
            *autoneg = true;
        } else {
            *autoneg = false;
        }
}

static void
get_interface_duplex_config(const char *duplex_cfg, int *duplex)
{
        /* Duplex configuration. */
        if (STR_EQ(duplex_cfg, INTERFACE_HW_INTF_CONFIG_MAP_DUPLEX_FULL)) {
            *duplex = OPENNSL_PORT_DUPLEX_FULL;
        } else {
            *duplex = OPENNSL_PORT_DUPLEX_HALF;
        }
}

static void
get_interface_pause_config(const char *pause_cfg, int *pause_rx, int *pause_tx)
{
    *pause_rx = false;
    *pause_tx = false;

        /* Pause configuration. */
    if (STR_EQ(pause_cfg, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE_RX)) {
        *pause_rx = true;
    } else if (STR_EQ(pause_cfg, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE_TX)) {
        *pause_tx = true;
    } else if (STR_EQ(pause_cfg, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE_RXTX)) {
        *pause_rx = true;
        *pause_tx = true;
    }
}

static void
get_interface_connector_type(const char *interface_type, opennsl_port_if_t *iface_port_if)
{
    opennsl_port_if_t port_if;

    if (interface_type) {
        if (!strcmp(interface_type,
                    INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_BACKPLANE)) {
            port_if = OPENNSL_PORT_IF_NULL;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_1GBASE_SX)) {
            port_if = OPENNSL_PORT_IF_GMII;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_1GBASE_T)) {
            port_if = OPENNSL_PORT_IF_GMII;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_10GBASE_CR)) {
            port_if = OPENNSL_PORT_IF_CR;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_10GBASE_SR)) {
            port_if = OPENNSL_PORT_IF_SR;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_10GBASE_LR)) {
            port_if = OPENNSL_PORT_IF_LR;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_10GBASE_LRM)) {
            port_if = OPENNSL_PORT_IF_LR;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_40GBASE_CR4)) {
            port_if = OPENNSL_PORT_IF_CR4;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_40GBASE_SR4)) {
            port_if = OPENNSL_PORT_IF_SR4;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_40GBASE_LR4)) {
            port_if = OPENNSL_PORT_IF_LR4;
        } else {
            port_if = OPENNSL_PORT_IF_NULL;
        }
    } else {
        port_if = OPENNSL_PORT_IF_NULL;
    }

    *iface_port_if = port_if;
}

static void
handle_bcmsdk_knet_filters(struct netdev_bcmsdk *netdev, int enable)
{
    if ((enable == true) && (netdev->knet_filter_id == 0)) {

        bcmsdk_knet_port_filter_create(netdev->up.name, netdev->hw_unit, netdev->hw_id,
                                       netdev->knet_if_id, &(netdev->knet_filter_id));

    } else if ((enable == false) && (netdev->knet_filter_id != 0)) {

        bcmsdk_knet_filter_delete(netdev->up.name, netdev->hw_unit, netdev->knet_filter_id);
        netdev->knet_filter_id = 0;
    }
}

/* Compare the existing port configuration,
 * and check if anything changed. */
static int
is_port_config_changed(const struct port_cfg *cur_pcfg, const struct port_cfg *pcfg)
{
    if ((cur_pcfg->enable != pcfg->enable) ||
        (cur_pcfg->autoneg != pcfg->autoneg) ||
        (cur_pcfg->cfg_speed != pcfg->cfg_speed) ||
        (cur_pcfg->duplex != pcfg->duplex) ||
        (cur_pcfg->pause_rx != pcfg->pause_rx) ||
        (cur_pcfg->pause_tx != pcfg->pause_tx) ||
        (cur_pcfg->max_frame_sz != pcfg->max_frame_sz) ||
        (cur_pcfg->intf_type != pcfg->intf_type)) {

        return 1;
    }
    return 0;

} // is_port_config_changed

static void
update_port_config(struct port_cfg *netdev_pcfg, const struct port_cfg *new_pcfg)
{
    netdev_pcfg->enable = new_pcfg->enable;
    netdev_pcfg->autoneg = new_pcfg->autoneg;
    netdev_pcfg->cfg_speed = new_pcfg->cfg_speed;
    netdev_pcfg->duplex = new_pcfg->duplex;
    netdev_pcfg->pause_rx = new_pcfg->pause_rx;
    netdev_pcfg->pause_tx = new_pcfg->pause_tx;
    netdev_pcfg->max_frame_sz = new_pcfg->max_frame_sz;
    netdev_pcfg->intf_type = new_pcfg->intf_type;

} // update_port_config

static int
netdev_bcmsdk_set_hw_intf_config(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    int rc = 0;
    struct port_cfg *pcfg = NULL;

    const char *hw_enable = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_ENABLE);
    const char *autoneg = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_AUTONEG);
    const char *duplex = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_DUPLEX);
    const char *pause = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE);
    const char *interface_type = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE);
    const int mtu = smap_get_int(args, INTERFACE_HW_INTF_CONFIG_MAP_MTU, 0);

    VLOG_DBG("netdev set_hw_intf_config called for interface %s", netdev->up.name);

    if (netdev->intf_initialized == false) {
        VLOG_WARN("netdev interface %s is not initialized.", netdev->up.name);
        return 1;
    }

    pcfg = xcalloc(1, sizeof *pcfg);


    /* If interface is enabled */
    if (STR_EQ(hw_enable, INTERFACE_HW_INTF_CONFIG_MAP_ENABLE_TRUE)) {

        pcfg->enable = true;

        get_interface_autoneg_config(autoneg, &(pcfg->autoneg));
        get_interface_duplex_config(duplex, &(pcfg->duplex));
        get_interface_pause_config(pause, &(pcfg->pause_rx), &(pcfg->pause_tx));
        get_interface_connector_type(interface_type, &(pcfg->intf_type));
        pcfg->max_frame_sz = (mtu == 0) ? 0 : mtu + BCMSDK_MTU_TO_MAXFRAMESIZE_PAD;

    } else {
        /* Treat the absence of hw_enable info as a "disable" action. */
        pcfg->enable = false;
    }

    if (!is_port_config_changed(&(netdev->pcfg), pcfg)) {
        VLOG_DBG("port config is not changed. Intf=%s, unit=%d port=%d",
                 netdev->up.name, netdev->hw_unit, netdev->hw_id);
        return 0;
    }

    // Update the netdev struct with new config.
    update_port_config(&(netdev->pcfg), pcfg);

    ovs_mutex_lock(&netdev->mutex);

     /* Splittable port lane configuration. */
    if (pcfg->enable == true) {
        if (netdev->is_split_parent) {
            split_port_lane_config(netdev->port_info, false);
        } else if (netdev->is_split_subport) {
            split_port_lane_config(netdev->split_parent_portp, true);
        }
    }

    /* If interface is being enabled, add a KNET filter rule
     * to send the incoming frames on the corresponding
     * KNET virtual interface, otherwise delete the rule. */
    handle_bcmsdk_knet_filters(netdev, pcfg->enable);

    rc = bcmsdk_set_port_config(netdev->hw_unit, netdev->hw_id, pcfg);
    if (rc) {
        VLOG_WARN("Failed to configure netdev interface %s.", netdev->up.name);
    }

    netdev_change_seq_changed(netdev_);

    ovs_mutex_unlock(&netdev->mutex);

    free(pcfg);

    return rc;
}

static int
netdev_bcmsdk_set_etheraddr(struct netdev *netdev,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_bcmsdk *dev = netdev_bcmsdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (!eth_addr_equals(dev->hwaddr, mac)) {
        memcpy(dev->hwaddr, mac, ETH_ADDR_LEN);
        netdev_change_seq_changed(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_bcmsdk_get_etheraddr(const struct netdev *netdev,
                           uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_bcmsdk *dev = netdev_bcmsdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    memcpy(mac, dev->hwaddr, ETH_ADDR_LEN);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_bcmsdk_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    int status;

    ovs_mutex_lock(&netdev->mutex);
    bcmsdk_get_link_status(netdev->hw_unit, netdev->hw_id, &status);
    *carrier = status;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static long long int
netdev_bcmsdk_get_carrier_resets(const struct netdev *netdev_)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    long long int link_resets = 0;

    ovs_mutex_lock(&netdev->mutex);
    link_resets = netdev->link_resets;
    ovs_mutex_unlock(&netdev->mutex);

    return link_resets;
}

int netdev_bcmsdk_set_l3_ingress_stat_obj(const struct netdev *netdev_,
                                          const int vlan_id,
                                          const uint32_t ing_stat_id,
                                          const uint32_t ing_num_id)
{
    VLOG_DBG("Entering netdev_bcmsdk_set_l3_ingress_id");
    int rc = 0;
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    netdev->ingress_stats_object.ingress_vlan_id = vlan_id;
    netdev->ingress_stats_object.ingress_num_id = ing_num_id;
    netdev->ingress_stats_object.ingress_stat_id = ing_stat_id;

    return rc;
}

int netdev_bcmsdk_set_l3_egress_id(const struct netdev *netdev_,
                                   const int l3_egress_id)
{
    char    egress_object_id_key[MAX_KEY_LENGTH];

    VLOG_DBG("Entering netdev_bcmsdk_set_l3_egress_id");
    int rc = 0;
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    struct ops_stats_egress_id   *egress_id_node = NULL;
    uint32_t egr_stat_id = 0;
    uint32_t egr_num_id = 0;

    memset(egress_object_id_key, 0, sizeof(egress_object_id_key));
    snprintf(egress_object_id_key, MAX_KEY_LENGTH, "%d", l3_egress_id);

    /* add the egress id to hashmap */
    egress_id_node = (struct ops_stats_egress_id *) xmalloc(sizeof(struct
                                                       ops_stats_egress_id));
    if (egress_id_node == NULL) {
        VLOG_ERR("Failed allocating memory to ops_stats_egress_id structure "
                 "for l3_egress_id%d", l3_egress_id);
        return 1; /* Return error */
    }

    rc = opennsl_stat_group_create(netdev->hw_unit, opennslStatObjectEgrL3Intf,
                                   opennslStatGroupModeSingle,
                                   &egr_stat_id, &egr_num_id);
    if (rc) {
        VLOG_ERR("Failed to create bcm stat group for egress object %d",
                  l3_egress_id);
        return 1; /* Return error */
    }
    VLOG_DBG("opennsl_stat_group_create SUCCESS for egr id %d"
             ", egr_stat_id is %d, egr_num_id is  %d", l3_egress_id,
             egr_stat_id, egr_num_id);

    rc = opennsl_l3_egress_stat_attach(netdev->hw_unit, l3_egress_id,
                                       egr_stat_id);
    if (rc) {
        VLOG_ERR("Failed to attach bcm stat object, for egress object %d",
                  l3_egress_id);
        return 1; /* Return error */
    }
    VLOG_DBG("opennsl_l3_egress_stat_attach SUCCESS for egr id %d",
              l3_egress_id);

    egress_id_node->egress_object_id = l3_egress_id;
    egress_id_node->egress_num_id = egr_num_id;
    egress_id_node->egress_stat_id = egr_stat_id;

    VLOG_DBG(" egress_node for l3_egress_id %d", l3_egress_id);

    ovs_mutex_lock(&netdev->mutex);
    hmap_insert(&(netdev->egress_id_map), &(egress_id_node->egress_node),
                hash_string(egress_object_id_key, 0));
    VLOG_DBG(" hash insert success for l3_egress_id%d", l3_egress_id);
    ovs_mutex_unlock(&netdev->mutex);

    return rc;
}

static struct ops_stats_egress_id *
netdev_bcmsdk_egress_id_lookup(char*egress_id_key_l, struct netdev_bcmsdk *netdev)
{
    struct ops_stats_egress_id    *egress_id_node;

    HMAP_FOR_EACH_WITH_HASH(egress_id_node, egress_node, hash_string(egress_id_key_l, 0),
                            &netdev->egress_id_map) {
        return egress_id_node;
    }

    return NULL;
}

int netdev_bcmsdk_remove_l3_egress_id(const struct netdev *netdev_,
                                      const int l3_egress_id)
{
    int rc = 0;
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    struct ops_stats_egress_id   *egress_id_node = NULL;
    uint32_t counter_index[10];
    opennsl_stat_value_t count_arr[10];
    char    egress_object_id_key[MAX_KEY_LENGTH];

    memset(egress_object_id_key, 0, sizeof(egress_object_id_key));
    snprintf(egress_object_id_key, MAX_KEY_LENGTH, "%d", l3_egress_id);

    ovs_mutex_lock(&netdev->mutex);
    egress_id_node = netdev_bcmsdk_egress_id_lookup(egress_object_id_key,
                                                 netdev);
    ovs_mutex_unlock(&netdev->mutex);

    if (egress_id_node == NULL) {
        VLOG_ERR("Failed to retrieve hashmap node for l3 egress id: %d",
                 l3_egress_id);
        return 1; /* Return error */
    }
    VLOG_DBG("netdev_bcmsdk_egress_id_lookup SUCCESS for l3 egress id: %d",
              l3_egress_id);

    memset(counter_index, 0 , 10);
    opennsl_stat_value_t_init(&(count_arr[0]));
    VLOG_DBG("netdev opennsl_stat_init SUCCES for l3 egress id: %d",
              egress_id_node->egress_object_id);

    rc = opennsl_l3_egress_stat_counter_get(netdev->hw_unit,
                                            egress_id_node->egress_object_id,
                                            opennslL3StatOutPackets,
                                            egress_id_node->egress_num_id,
                                            &(counter_index[0]),
                                            &(count_arr[0]));
    if (rc) {
        VLOG_ERR("During delete Failed to get stat pkts for l3 egress id: %d",
                 l3_egress_id);
        return 1; /* Return error */
    }
    VLOG_DBG(" deleted packets obtained for l3 egress id: %d",
              l3_egress_id);

    ovs_mutex_lock(&netdev->mutex);
    netdev->deleted_stats_counter.del_packets += count_arr[0].packets;
    ovs_mutex_unlock(&netdev->mutex);

    memset(counter_index, 0 , 10);
    opennsl_stat_value_t_init(&(count_arr[0]));
    VLOG_DBG("netdev opennsl_stat_init SUCCES for l3 egress id: %d",
              egress_id_node->egress_object_id);

    rc = opennsl_l3_egress_stat_counter_get(netdev->hw_unit,
                                            egress_id_node->egress_object_id,
                                            opennslL3StatOutBytes,
                                            egress_id_node->egress_num_id,
                                            &(counter_index[0]),
                                            &(count_arr[0]));
    if (rc) {
        VLOG_ERR("During delete Failed to get stat bytes for l3 egress id: %d",
                 l3_egress_id);
        return 1; /* Return error */
    }
    VLOG_DBG(" deleted bytes obtained for l3 egress id: %d",
              l3_egress_id);

    /* Make sure the stats object associated with this egress object is
     * detached and destroyed.
     */
    rc = opennsl_l3_egress_stat_detach(netdev->hw_unit,
                                       egress_id_node->egress_object_id);
    if (rc) {
        VLOG_ERR("Failed to detach stats from egress object id : %d",
                  egress_id_node->egress_object_id);
        return 1; /* Return error */
    }

     rc = opennsl_stat_group_destroy(netdev->hw_unit,
                                     egress_id_node->egress_stat_id);
    if (rc) {
        VLOG_ERR("Failed to destroy stats group for egress object id : %d",
                  egress_id_node->egress_object_id);
        return 1; /* Return error */
    }

    ovs_mutex_lock(&netdev->mutex);
    netdev->deleted_stats_counter.del_bytes += count_arr[0].bytes;

    /* remove the entry from the egress_id hash map */
    hmap_remove(&(netdev->egress_id_map), &(egress_id_node->egress_node));
    free(egress_id_node);
    ovs_mutex_unlock(&netdev->mutex);

    return rc;
}

static int
netdev_bcmsdk_get_mtu(const struct netdev *netdev_, int *mtup)
{
    int rc = 0;
    struct port_cfg pcfg;
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    memset(&pcfg, 0, sizeof(struct port_cfg));

    rc = bcmsdk_get_port_config(netdev->hw_unit, netdev->hw_id, &pcfg);
    if (rc) {
        VLOG_WARN("Unable to get the interface %s config", netdev->up.name);
        return rc;
    }

    if (pcfg.max_frame_sz) {
        *mtup = (pcfg.max_frame_sz - BCMSDK_MTU_TO_MAXFRAMESIZE_PAD);
    }

    return rc;
}

static int
netdev_bcmsdk_get_stats(const struct netdev *netdev_, struct netdev_stats *stats)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    return bcmsdk_get_port_stats(netdev->hw_unit, netdev->hw_id, stats);
}

static int
netdev_bcmsdk_get_l3_stats(const struct netdev *netdev_,
                           struct netdev_stats *stats)
{
    int rc = 0;
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    struct ops_stats_egress_id    *egress_id_node;
    struct ops_deleted_stats      *del_stats;

    del_stats = (struct ops_deleted_stats*) xmalloc(sizeof(struct
                                                  ops_deleted_stats));

    /* populate the del stats from bcmsdk netdev struct */
    del_stats->del_packets = netdev->deleted_stats_counter.del_packets;
    del_stats->del_drop_packets = netdev->deleted_stats_counter.del_drop_packets;
    del_stats->del_bytes = netdev->deleted_stats_counter.del_bytes;

    /* Initially set all the stat fields to zero */
    memset(stats, 0, sizeof(struct netdev_stats));

    /* Iterate through egress object hashmap and get every object stats */
    HMAP_FOR_EACH(egress_id_node, egress_node, &(netdev->egress_id_map)) {
        VLOG_DBG("Iterating through hmap for id: %d",
                  egress_id_node->egress_object_id);
        rc = bcmsdk_get_l3_egress_stats(netdev->hw_unit, stats,
                                        egress_id_node->egress_object_id,
                                        egress_id_node->egress_num_id);
        if (rc) {
            VLOG_ERR("Failed to get l3 stats for egress id : %d",
                      egress_id_node->egress_object_id);
            return 1; /* Return error */
        }
    }

    stats->tx_packets += del_stats->del_packets;
    stats->tx_bytes += del_stats->del_bytes;

    /* Now get the ingress stats for the l3 interface */
    rc = bcmsdk_get_l3_ingress_stats(netdev->hw_unit, stats,
                                   netdev->ingress_stats_object.ingress_vlan_id,
                                   netdev->ingress_stats_object.ingress_num_id);
    if (rc) {
        VLOG_ERR("Failed to get l3 stats for ingress vlan id : %d",
                  netdev->ingress_stats_object.ingress_vlan_id);
        return 1; /* Return error */
    }

    return rc;
}

static int
netdev_bcmsdk_get_features(const struct netdev *netdev_,
                           enum netdev_features *current,
                           enum netdev_features *advertised,
                           enum netdev_features *supported,
                           enum netdev_features *peer)
{
    int rc = 0;
    uint32_t speed;
    struct port_cfg pcfg;
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    *current = *advertised = *supported = *peer = (enum netdev_features) 0;

    memset(&pcfg, 0, sizeof(struct port_cfg));
    rc = bcmsdk_get_port_config(netdev->hw_unit, netdev->hw_id, &pcfg);
    if (rc) {
        VLOG_WARN("Unable to get the interface %s config", netdev->up.name);
        return rc;
    }

    /* Current settings. */
    speed = pcfg.link_speed;
    if (speed == SPEED_10) {
        *current |= pcfg.duplex ? NETDEV_F_10MB_FD : NETDEV_F_10MB_HD;
    } else if (speed == SPEED_100) {
        *current |= pcfg.duplex ? NETDEV_F_100MB_FD : NETDEV_F_100MB_HD;
    } else if (speed == SPEED_1000) {
        *current |= pcfg.duplex ? NETDEV_F_1GB_FD : NETDEV_F_1GB_HD;
    } else if (speed == SPEED_10000) {
        *current |= NETDEV_F_10GB_FD;
    } else if (speed == 40000) {
        *current |= NETDEV_F_40GB_FD;
    } else if (speed == 100000) {
        *current |= NETDEV_F_100GB_FD;
    }

    if (pcfg.autoneg) {
        *current |= NETDEV_F_AUTONEG;
    }

    if (pcfg.pause_tx && pcfg.pause_rx) {
        *current |= NETDEV_F_PAUSE;
    } else if (pcfg.pause_rx) {
        *current |= NETDEV_F_PAUSE;
        *current |= NETDEV_F_PAUSE_ASYM;
    } else if (pcfg.pause_tx) {
        *current |= NETDEV_F_PAUSE_ASYM;
    }

    return rc;
}

static int
netdev_bcmsdk_update_flags(struct netdev *netdev_,
                           enum netdev_flags off,
                           enum netdev_flags on,
                           enum netdev_flags *old_flagsp)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    int rc = 0;
    int state = 0;

    if ((off | on) & ~NETDEV_UP) {
        return EOPNOTSUPP;
    }

    ovs_mutex_lock(&netdev->mutex);

    /* Get the current state to update the old flags. */
    rc = bcmsdk_get_enable_state(netdev->hw_unit, netdev->hw_id, &state);
    if (!rc) {
        if (state) {
            *old_flagsp |= NETDEV_UP;
        } else {
            *old_flagsp &= ~NETDEV_UP;
        }

        /* Set the new state to that which is desired. */
        if (on & NETDEV_UP) {
            rc = bcmsdk_set_enable_state(netdev->hw_unit, netdev->hw_id, true);
        } else if (off & NETDEV_UP) {
            rc = bcmsdk_set_enable_state(netdev->hw_unit, netdev->hw_id, false);
        }
    }

    ovs_mutex_unlock(&netdev->mutex);

    return rc;
}

void
netdev_bcmsdk_link_state_callback(int hw_unit, int hw_id, int link_status)
{
    struct netdev_bcmsdk *netdev = netdev_from_hw_id(hw_unit, hw_id);

    if (link_status) {
        netdev->link_resets++;
    }

    if (netdev != NULL) {
        netdev_change_seq_changed((struct netdev *)&(netdev->up));
    }

    // Wakeup poll_block() function.
    seq_change(connectivity_seq_get());
}

/* Helper functions. */

static const struct netdev_class bcmsdk_class = {
    "system",
    NULL,                       /* init */
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_bcmsdk_alloc,
    netdev_bcmsdk_construct,
    netdev_bcmsdk_destruct,
    netdev_bcmsdk_dealloc,
    NULL,                       /* get_config */
    NULL,                       /* set_config */
    netdev_bcmsdk_set_hw_intf_info,
    netdev_bcmsdk_set_hw_intf_config,
    NULL,                       /* get_tunnel_config */
    NULL,                       /* build header */
    NULL,                       /* push header */
    NULL,                       /* pop header */
    NULL,                       /* get_numa_id */
    NULL,                       /* set_multiq */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_bcmsdk_set_etheraddr,
    netdev_bcmsdk_get_etheraddr,
    netdev_bcmsdk_get_mtu,
    NULL,                       /* set_mtu */
    NULL,                       /* get_ifindex */
    netdev_bcmsdk_get_carrier,
    netdev_bcmsdk_get_carrier_resets,
    NULL,                       /* get_miimon */
    netdev_bcmsdk_get_stats,

    netdev_bcmsdk_get_features,
    NULL,                       /* set_advertisements */

    NULL,                       /* set_policing */
    NULL,                       /* get_qos_types */
    NULL,                       /* get_qos_capabilities */
    NULL,                       /* get_qos */
    NULL,                       /* set_qos */
    NULL,                       /* get_queue */
    NULL,                       /* set_queue */
    NULL,                       /* delete_queue */
    NULL,                       /* get_queue_stats */
    NULL,                       /* queue_dump_start */
    NULL,                       /* queue_dump_next */
    NULL,                       /* queue_dump_done */
    NULL,                       /* dump_queue_stats */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* get_status */
    NULL,                       /* arp_lookup */

    netdev_bcmsdk_update_flags,

    NULL,                       /* rxq_alloc */
    NULL,                       /* rxq_construct */
    NULL,                       /* rxq_destruct */
    NULL,                       /* rxq_dealloc */
    NULL,                       /* rxq_recv */
    NULL,                       /* rxq_wait */
    NULL,                       /* rxq_drain */
};

static int
netdev_internal_bcmsdk_set_hw_intf_info(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    int rc = 0;
    struct ether_addr *ether_mac = NULL;
    bool is_bridge_interface = smap_get_bool(args, INTERFACE_HW_INTF_INFO_MAP_BRIDGE, DFLT_INTERFACE_HW_INTF_INFO_MAP_BRIDGE);

    VLOG_DBG("netdev set_hw_intf_info for interace %s", netdev->up.name);

    ovs_mutex_lock(&netdev->mutex);

    if (netdev->intf_initialized == false) {
        netdev->hw_unit = 0;
        netdev->hw_id = -1;
        if(is_bridge_interface) {
            ether_mac = (struct ether_addr *) netdev->hwaddr;
            rc = bcmsdk_knet_if_create(netdev->up.name, netdev->hw_unit, netdev->hw_id, ether_mac,
                    &(netdev->knet_if_id));
            if (rc) {
                VLOG_ERR("Failed to initialize interface %s", netdev->up.name);
                goto error;
            } else {
                netdev->intf_initialized = true;
            }
        } else {
            netdev->intf_initialized = true;
        }
    }

    ovs_mutex_unlock(&netdev->mutex);
    return 0;

error:
    ovs_mutex_unlock(&netdev->mutex);
    rc = -EINVAL;
    return rc;
}


static int
netdev_internal_bcmsdk_update_flags(struct netdev *netdev_,
                                    enum netdev_flags off,
                                    enum netdev_flags on,
                                    enum netdev_flags *old_flagsp)
{
    /* XXX: Not yet supported for internal interfaces */
    return EOPNOTSUPP;
}

static const struct netdev_class bcmsdk_internal_class = {
    "internal",
    NULL,                       /* init */
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_bcmsdk_alloc,
    netdev_bcmsdk_construct,
    netdev_bcmsdk_destruct,
    netdev_bcmsdk_dealloc,
    NULL,                       /* get_config */
    NULL,                       /* set_config */
    netdev_internal_bcmsdk_set_hw_intf_info,
    NULL,
    NULL,                       /* get_tunnel_config */
    NULL,                       /* build header */
    NULL,                       /* push header */
    NULL,                       /* pop header */
    NULL,                       /* get_numa_id */
    NULL,                       /* set_multiq */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_bcmsdk_set_etheraddr,
    netdev_bcmsdk_get_etheraddr,
    NULL,                       /* get_mtu */
    NULL,                       /* set_mtu */
    NULL,                       /* get_ifindex */
    NULL,                       /* get_carrier */
    NULL,                       /* get_carrier_resets */
    NULL,                       /* get_miimon */
    netdev_bcmsdk_get_l3_stats, /* get_stats */

    NULL,                       /* get_features */
    NULL,                       /* set_advertisements */

    NULL,                       /* set_policing */
    NULL,                       /* get_qos_types */
    NULL,                       /* get_qos_capabilities */
    NULL,                       /* get_qos */
    NULL,                       /* set_qos */
    NULL,                       /* get_queue */
    NULL,                       /* set_queue */
    NULL,                       /* delete_queue */
    NULL,                       /* get_queue_stats */
    NULL,                       /* queue_dump_start */
    NULL,                       /* queue_dump_next */
    NULL,                       /* queue_dump_done */
    NULL,                       /* dump_queue_stats */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* get_status */
    NULL,                       /* arp_lookup */

    netdev_internal_bcmsdk_update_flags,

    NULL,                       /* rxq_alloc */
    NULL,                       /* rxq_construct */
    NULL,                       /* rxq_destruct */
    NULL,                       /* rxq_dealloc */
    NULL,                       /* rxq_recv */
    NULL,                       /* rxq_wait */
    NULL,                       /* rxq_drain */
};

void
netdev_bcmsdk_register(void)
{
    netdev_register_provider(&bcmsdk_class);
    netdev_register_provider(&bcmsdk_internal_class);
}
