/*
 * Copyright (C) 2016 Hewlett-Packard Enterprise Company, L.P.
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
 * File: ops-vxlan.c
 *
 * Purpose: This file contains OpenSwitch VxLAN related application code in the Broadcom SDK.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openvswitch/vlog.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/port.h>
#include <opennsl/vxlan.h>
#include <opennsl/switch.h>
#include <opennsl/tunnel.h>
#include <opennsl/l2.h>
#include <opennsl/multicast.h>

#include "platform-defines.h"
#include "hash.h"
#include "hmap.h"
#include "ops-debug.h"
#include "ops-pbmp.h"
#include "ops-port.h"
#include "ops-vxlan.h"
#include "bcm-common.h"

/*
 * BCM issues are commented out using
 * #ifdef PORT_GET
 * #ifdef L2_STATION
 * When the issues are resoved, remove those #ifdef
 */

/**************************************************************************/
/*                              DECLARATIONS                              */
/**************************************************************************/
VLOG_DEFINE_THIS_MODULE(ops_vxlan);

/*
 * struct vxlan_setting_t
 *      Structure for configuring VxLAN
 *
 * l3_egress_endis:
 *      L3 egress enable/disable.
 *
 * dst_udp_port:
 *      which destination UDP port to use for encapsulation.
 *
 * vxlan_entropy:
 *      VxLAN entropy enable/disable.
 *
 * vxlan_tunnel_lookup_failure:
 *      VxLAN tunnel lookup failure send to CPU enable/disable.
 *
 * vxlan_vni_loopup_failure:
 *      VxLAN VNI lookup failures send to CPU enable/disable.
 */
typedef struct vxlan_setting_t_ {
    bool l3_egress_endis;
    int dst_udp_port;
    bool entropy;
    bool tunnel_miss_to_cpu_endis;
    bool vnid_miss_to_cpu_endis;
} vxlan_setting_t;


/*
 * struct vxlan_egr_obj_t
 *      Structure for egress object operations
 *
 * gport:
 *      gport
 *
 * egr_obj_id:
 *      egress object ID.
 */
typedef struct bcmsdk_vxlan_egr_obj_ {
    int gport;
    int egr_obj_id;
} bcmsdk_vxlan_egr_obj_t;


typedef struct vxlan_logical_sw_element_t_ {
    int vnid;                       /* key */
    int vpn_id;                     /* value */
    int broadcast_group;            /* value */
    int unknown_multicast_group;    /* value */
    int unknown_unicast_group;      /* value */
    struct hmap_node node;
} vxlan_logical_sw_element_t;

/*
 * struct vxlan_egr_obj_element_t
 *      Structure for egress object hash element
 *
 * unit:
 *      ASIC unit number
 *
 * gport:
 *      gport
 *
 * egr_obj_id:
 *      egress object ID.
 *
 * node:
 *      hash node
 */
typedef struct vxlan_egr_obj_element_t_ {
    int unit;                       /* key */
    int gport;                      /* key */
    int egr_obj_id;                 /* value */
    struct hmap_node node;
} vxlan_egr_obj_element_t;

typedef struct vxlan_global_t_ {
    /* Hash vni to vpn_id for logical switch. It contains
       vxlan_logical_sw_element_t as element. */
    struct hmap logical_sw_hmap;

    /* Hash gport to L3 egress object. It contains
       vxlan_egr_obj_element_t as element */
    struct hmap egr_obj_hmap;
} vxlan_global_t;


#define VXLAN_DUMMY_MAC         "00:00:01:00:00:01"

/* Private Variables */
static vxlan_global_t vxlan_global;


/* Private API declarations */
static int vxlan_configure_global(int unit, vxlan_setting_t *vxlan_set_p);

static int vxlan_insert_logical_switch_hash_element(int unit, bcmsdk_vxlan_logical_switch_t *logical_sw_p);
static vxlan_logical_sw_element_t *vxlan_find_logical_switch_hash_element(int unit, int vnid);

static int vxlan_insert_egr_obj_hash_element(int unit,
                                             bcmsdk_vxlan_egr_obj_t *egr_obj_p);
static vxlan_egr_obj_element_t *vxlan_find_egr_obj_hash_element(int unit, int gport);

static int vxlan_create_logical_switch(int unit, bcmsdk_vxlan_logical_switch_t *logical_sw_p);
static int vxlan_destroy_logical_switch(int unit, bcmsdk_vxlan_logical_switch_t *logical_sw_p);
static int vxlan_get_logical_switch(int unit, bcmsdk_vxlan_logical_switch_t *logical_sw_p);
static int vxlan_update_logical_switch(int unit, bcmsdk_vxlan_logical_switch_t *logical_sw_p);

static int vxlan_create_tunnel_initiator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p);
static int vxlan_destroy_tunnel_initiator(int unit, int tunnel_id);
static int vxlan_get_tunnel_initiator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p);
int vxlan_update_tunnel_initiator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p);
static int vxlan_create_tunnel_terminator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p);
static int vxlan_destroy_tunnel_terminator(int unit, int tunnel_id);
static int vxlan_get_tunnel_terminator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p);
int vxlan_update_tunnel_terminator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p);
static int vxlan_create_tunnel(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p);
static int vxlan_destroy_tunnel(int unit, int tunnel_id);
static int vxlan_get_tunnel(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p);
static int vxlan_update_tunnel(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p);

static int vxlan_bind_port(int unit, bcmsdk_vxlan_port_t *port_p);
static int vxlan_unbind_port(int unit, bcmsdk_vxlan_port_t *port_p);
static int vxlan_get_port(int unit, bcmsdk_vxlan_port_t *port_p);
static int vxlan_update_port(int unit, bcmsdk_vxlan_port_t *port_p);
static int vxlan_access_port_configure(int unit, int port);
//static int vxlan_access_port_unconfigure(int unit, int port);
static int vxlan_bind_access_port(int unit, bcmsdk_vxlan_port_t *acc_port_p);
static int vxlan_unbind_access_port(int unit, bcmsdk_vxlan_port_t *acc_port_p);
static int vxlan_get_access_port(int unit, bcmsdk_vxlan_port_t *acc_port_p);
static int vxlan_network_port_configure(int unit, int port);
static int vxlan_network_port_unconfigure(int unit, int port);
static int vxlan_bind_network_port(int unit, bcmsdk_vxlan_port_t *net_port_p);
static int vxlan_unbind_network_port(int unit, bcmsdk_vxlan_port_t *net_port_p);
static int vxlan_get_network_port(int unit, bcmsdk_vxlan_port_t *net_port_p);

static int vxlan_create_multicast(int unit, bcmsdk_vxlan_multicast_t *multicast_p);
static int vxlan_destroy_multicast(int unit, bcmsdk_vxlan_multicast_t *multicast_p);
static int vxlan_hmap_cleanup(int unit);

/**************************************************************************/
/*                              PUBLIC API                                */
/**************************************************************************/

int
bcmsdk_vxlan_endis_global(int unit, int endis)
{
    int rc;
    vxlan_setting_t vxlan_set;

    /* The default for opennslSwitchL3EgressMode = TRUE,
       for Vxlan, it also need to be set to TRUE. So in theory,
       we don't need to do anything.
       It is explicit set here in case it get changed by other
       configurations */
    vxlan_set.l3_egress_endis = opennslSwitchL3EgressMode;

    if (endis) {
        vxlan_set.dst_udp_port = VXLAN_DEFAULT_DST_UDP_PORT;
        vxlan_set.entropy = TRUE;
        vxlan_set.tunnel_miss_to_cpu_endis = TRUE;
        vxlan_set.vnid_miss_to_cpu_endis = TRUE;
    } else {
        /* change to default values */
        vxlan_set.dst_udp_port = 0;
        vxlan_set.entropy = FALSE;
        vxlan_set.tunnel_miss_to_cpu_endis = FALSE;
        vxlan_set.vnid_miss_to_cpu_endis = FALSE;
    }

    rc = vxlan_configure_global(unit, &vxlan_set);

    if (rc) {
        VLOG_ERR("Error [%s, %d], exit rc:%d unit:%d endis:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, endis);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d endis:%d\n",
             __FUNCTION__, __LINE__, rc, unit, endis);

    return BCMSDK_E_NONE;
}


int
bcmsdk_vxlan_logical_switch_operation(int unit, bcmsdk_vxlan_opcode_t opcode,
                                      bcmsdk_vxlan_logical_switch_t *logical_sw_p)
{
    int rc;
    bcmsdk_vxlan_multicast_t mc;

    if (logical_sw_p == NULL) {
        VLOG_ERR("Error [%s, %d], logical_sw_p NULL unit:%d opcode:%d\n",
                 __FUNCTION__, __LINE__, unit, opcode);
        return BCMSDK_E_PARAM;
    }

    switch (opcode) {
    case BCMSDK_VXLAN_OPCODE_CREATE:
        /* temporary create multicast group here. Eventually
           need to be created by multicast feature API */
        rc = bcmsdk_vxlan_multicast_operation(unit,
                                              BCMSDK_VXLAN_OPCODE_CREATE,
                                              &mc);
        if (rc)
            break;

        logical_sw_p->broadcast_group = mc.group_id;
        logical_sw_p->unknown_multicast_group = mc.group_id;
        logical_sw_p->unknown_unicast_group = mc.group_id;

        rc = vxlan_create_logical_switch(unit, logical_sw_p);
        break;
    case BCMSDK_VXLAN_OPCODE_DESTROY:
        rc = vxlan_destroy_logical_switch(unit, logical_sw_p);
        if (rc)
            break;

        /* Current design assigns broadcast_group, unknown_multicast_group,
           unknown_unicast_group to same value */
        mc.group_id = logical_sw_p->unknown_unicast_group;

        /* temporary delete multicast group here. Eventually need
           to be deleted by multicast feature API */
        rc = bcmsdk_vxlan_multicast_operation(unit,
                                              BCMSDK_VXLAN_OPCODE_DESTROY,
                                              &mc);
        break;
    case BCMSDK_VXLAN_OPCODE_GET:
        rc = vxlan_get_logical_switch(unit, logical_sw_p);
        break;
    case BCMSDK_VXLAN_OPCODE_UPDATE:
        rc = vxlan_update_logical_switch(unit, logical_sw_p);
        break;
    default:
        rc = BCMSDK_E_PARAM;
        break;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d opcode:%d\n",
             __FUNCTION__, __LINE__, rc, unit, opcode);

    if (rc)
        return rc;

    return BCMSDK_E_NONE;
}


int
bcmsdk_vxlan_tunnel_operation(int unit, bcmsdk_vxlan_opcode_t opcode,
                              bcmsdk_vxlan_tunnel_t *tunnel_p)
{
    int rc;

    if (tunnel_p == NULL) {
        VLOG_ERR("Error [%s, %d], tunnel_p is NULL unit:%d opcode:%d\n",
                 __FUNCTION__, __LINE__, unit, opcode);
        return BCMSDK_E_PARAM;
    }

    switch (opcode) {
    case BCMSDK_VXLAN_OPCODE_CREATE:
        rc = vxlan_create_tunnel(unit, tunnel_p);
        break;
    case BCMSDK_VXLAN_OPCODE_DESTROY:
        rc = vxlan_destroy_tunnel(unit, tunnel_p->tunnel_id);
        break;
    case BCMSDK_VXLAN_OPCODE_GET:
        rc = vxlan_get_tunnel(unit, tunnel_p);
        break;
    case BCMSDK_VXLAN_OPCODE_UPDATE:
        rc = vxlan_update_tunnel(unit, tunnel_p);
        break;
    default:
        rc = BCMSDK_E_PARAM;
        break;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d opcode:%d\n",
             __FUNCTION__, __LINE__, rc, unit, opcode);

    if (rc)
        return rc;

    return BCMSDK_E_NONE;
}


int
bcmsdk_vxlan_port_operation(int unit, bcmsdk_vxlan_opcode_t opcode,
                            bcmsdk_vxlan_port_t *port_p)
{
    int rc;

    if (port_p == NULL) {
        VLOG_ERR("Error [%s, %d], port_p is NULL unit:%d opcode:%d\n",
                 __FUNCTION__, __LINE__, unit, opcode);
        return BCMSDK_E_PARAM;
    }

    switch (opcode) {
    case BCMSDK_VXLAN_OPCODE_CREATE:
        rc = vxlan_bind_port(unit, port_p);
        break;
    case BCMSDK_VXLAN_OPCODE_DESTROY:
        rc = vxlan_unbind_port(unit, port_p);
        break;
    case BCMSDK_VXLAN_OPCODE_GET:
        rc = vxlan_get_port(unit, port_p);
        break;
    case BCMSDK_VXLAN_OPCODE_UPDATE:
        rc = vxlan_update_port(unit, port_p);
        break;
    default:
        rc = BCMSDK_E_PARAM;
        break;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d opcode:%d\n",
             __FUNCTION__, __LINE__, rc, unit, opcode);

    if (rc)
        return rc;

    return BCMSDK_E_NONE;
}


int
bcmsdk_vxlan_multicast_operation(int unit, bcmsdk_vxlan_opcode_t opcode,
                                 bcmsdk_vxlan_multicast_t *multicast_p)
{
    int rc;

    if (multicast_p == NULL) {
        VLOG_ERR("Error [%s, %d], multicast_p is NULL unit:%d opcode:%d\n",
                 __FUNCTION__, __LINE__, unit, opcode);
        return BCMSDK_E_PARAM;
    }

    switch (opcode) {
    case BCMSDK_VXLAN_OPCODE_CREATE:
        rc = vxlan_create_multicast(unit, multicast_p);
        break;
    case BCMSDK_VXLAN_OPCODE_DESTROY:
        rc = vxlan_destroy_multicast(unit, multicast_p);
        break;
    case BCMSDK_VXLAN_OPCODE_GET:
    case BCMSDK_VXLAN_OPCODE_UPDATE:
        /* Not surpported */
    default:
        rc = BCMSDK_E_PARAM;
        break;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d opcode:%d\n",
             __FUNCTION__, __LINE__, rc, unit, opcode);

    if (rc)
        return rc;

    return BCMSDK_E_NONE;
}

/**************************************************************************/
/*                              PRIVATE API                              */
/**************************************************************************/
/*
 * Function: vxlan_configure_global
 *      Configure VXLAN global parameters.
 *
 * [In] unit
 *      BCM HW unit
 *
 * [In] vxlan_set_p
 *      vxlan_set_p->l3_egress_endis
 *      vxlan_set_p->dst_udp_port
 *      vxlan_set_p->entropy
 *      vxlan_set_p->tunnel_miss_to_cpu_endis
 *      vxlan_set_p->vnid_miss_to_cpu_endis
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_configure_global(int unit, vxlan_setting_t *vxlan_set_p)
{
    int rc;

    if (!vxlan_set_p) {
        VLOG_ERR("Error [%s, %d], vxlan_set_p is NULL\n",
                 __FUNCTION__, __LINE__);
        return BCMSDK_E_PARAM;
    }

    rc = opennsl_switch_control_set(unit, opennslSwitchL3EgressMode,
                                    vxlan_set_p->l3_egress_endis);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_switch_control_set rc:%d unit:%d opennslSwitchL3EgressMode:%d\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 vxlan_set_p->l3_egress_endis);
        return rc;
    }

    /* Set UDP port for VXLAN */
    rc = opennsl_switch_control_set(unit, opennslSwitchVxlanUdpDestPortSet,
                                    vxlan_set_p->dst_udp_port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_switch_control_set rc:%d unit:%d opennslSwitchVxlanUdpDestPortSet:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, vxlan_set_p->dst_udp_port);
        return rc;
    }

    /* Enable/Disable VXLAN Entropy */
    rc = opennsl_switch_control_set(unit, opennslSwitchVxlanEntropyEnable,
                                    vxlan_set_p->entropy);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_switch_control_set rc:%d unit:%d opennslSwitchVxlanEntropyEnable:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, vxlan_set_p->entropy);
        return rc;
    }

    /* Enable/Disable VXLAN Tunnel lookup failure settings */
    rc = opennsl_switch_control_set(unit, opennslSwitchVxlanTunnelMissToCpu,
                                    vxlan_set_p->tunnel_miss_to_cpu_endis);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_switch_control_set rc:%d unit:%d opennslSwitchVxlanTunnelToCpu:%d\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 vxlan_set_p->tunnel_miss_to_cpu_endis);
        return rc;
    }

    /* Enable/Disable VXLAN VN_ID lookup failure settings */
    rc = opennsl_switch_control_set(unit, opennslSwitchVxlanVnIdMissToCpu,
                                    vxlan_set_p->vnid_miss_to_cpu_endis);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_switch_control_set rc:%d unit:%d opennslSwitchVxlanVnIdMissToCpu:%d\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 vxlan_set_p->vnid_miss_to_cpu_endis);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d opennslSwitchL3EgressMode:%d opennslSwitchVxlanUdpDestPortSet:%d opennslSwitchVxlanEntropyEnable:%d opennslSwitchVxlanTunnelToCpu:%d VxlanVnIdMissToCpu:%d\n",
             __FUNCTION__, __LINE__, rc, unit,
             vxlan_set_p->l3_egress_endis, vxlan_set_p->dst_udp_port,
             vxlan_set_p->entropy, vxlan_set_p->tunnel_miss_to_cpu_endis,
             vxlan_set_p->vnid_miss_to_cpu_endis);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_insert_logical_switch_hash_element
 *      Insert vnid key and vpn_id value pair to hash map.
 *      User must check if the vnid key and vpn_id pair does not
 *      exist first using vxlan_find_logical_switch_hash_element().
 *
 * [In] unit
 *      HW unit
 *
 * [In] logical_sw_p
 *      logical_sw_p->vnid
 *      logical_sw_p->vpn_id
 *      logical_sw_p->broadcast_group
 *      logical_sw_p->unknown_multicast_group
 *      logical_sw_p->unknown_unicast_group
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_insert_logical_switch_hash_element(int unit,
                                         bcmsdk_vxlan_logical_switch_t *logical_sw_p)
{
    vxlan_logical_sw_element_t *logical_sw_element_p;
    uint32_t hash;

    logical_sw_element_p = (vxlan_logical_sw_element_t *)calloc(1, sizeof(vxlan_logical_sw_element_t));

    if (logical_sw_element_p == NULL) {
        VLOG_ERR("Error [%s, %d], logical_sw_element_p calloc failed for unit:%d vnid:%d vpn_id:%d\n",
                 __FUNCTION__, __LINE__, unit, logical_sw_p->vnid,
                 logical_sw_p->vpn_id);
        return BCMSDK_E_RESOURCE;
    }

    /* Update hash element key and value */
    logical_sw_element_p->vnid = logical_sw_p->vnid;
    logical_sw_element_p->vpn_id = logical_sw_p->vpn_id;
    logical_sw_element_p->broadcast_group = logical_sw_p->broadcast_group;
    logical_sw_element_p->unknown_multicast_group =
        logical_sw_p->unknown_multicast_group;
    logical_sw_element_p->unknown_unicast_group =
        logical_sw_p->unknown_unicast_group;

    /* insert this element to logical_sw_hmap hash table */
    hash = hash_2words((uint32_t)logical_sw_element_p->vnid, unit);
    hmap_insert(&vxlan_global.logical_sw_hmap,
                &logical_sw_element_p->node, hash);

    return BCMSDK_E_NONE;
}

/*
 * Function: vxlan_find_logical_switch_hash_element
 *      Find logical switch vpn_id from vni from hash map
 *
 * [In] unit
 *      HW unit
 *
 * [In] vnid
 *      Vxlan VNI ID
 *
 * [Out] return vxlan_logical_sw_element_t *
 *       Not found - NULL
 *       Found - (vxlan_logical_sw_element_t *)->vpn_id
 */
static
vxlan_logical_sw_element_t *
vxlan_find_logical_switch_hash_element(int unit, int vnid)
{
    uint32_t hash;
    vxlan_logical_sw_element_t *logical_sw_element_p;
    vxlan_logical_sw_element_t *logical_sw_element_found_p;

    hash = hash_2words((uint32_t)vnid, unit);

    logical_sw_element_found_p = NULL;
    HMAP_FOR_EACH_WITH_HASH (logical_sw_element_p, node, hash,
                             &vxlan_global.logical_sw_hmap) {
        if (logical_sw_element_p->vnid == vnid) {
            logical_sw_element_found_p = logical_sw_element_p;
            break;
        }
    }

    return  logical_sw_element_found_p;
}


/*
 * Function: vxlan_insert_egr_obj_hash_element
 *      Insert gport and egr_obj value pair to hash map.
 *      User must check if the gport and egr_obj pair does not
 *      exist first using vxlan_find_egr_obj_hash_element().
 *
 * [In] unit
 *      HW unit
 *
 * [In] egr_obj_p
 *      egr_obj_p->gport
 *      egr_obj_p->egr_obj
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_insert_egr_obj_hash_element(int unit,
                                  bcmsdk_vxlan_egr_obj_t *egr_obj_p)
{
    vxlan_egr_obj_element_t *egr_obj_element_p;
    uint32_t hash;

    egr_obj_element_p = (vxlan_egr_obj_element_t *)
        calloc(1, sizeof(vxlan_egr_obj_element_t));

    if (egr_obj_element_p == NULL) {
        VLOG_ERR("Error [%s, %d], egr_obj_element_p calloc failed for unit:%d gport:0x%x egr_obj:0x%x\n",
                 __FUNCTION__, __LINE__, unit, egr_obj_p->gport,
                 egr_obj_p->egr_obj_id);
        return BCMSDK_E_RESOURCE;
    }

    /* Update hash element key and value */
    egr_obj_element_p->gport = egr_obj_p->gport;
    egr_obj_element_p->egr_obj_id = egr_obj_p->egr_obj_id;

    /* insert this element to egr_obj_hmap hash table */
    hash = hash_2words((uint32_t)egr_obj_element_p->gport, unit);
    hmap_insert(&vxlan_global.egr_obj_hmap,
                &egr_obj_element_p->node, hash);

    return BCMSDK_E_NONE;
}



/*
 * Function: vxlan_find_egr_obj_hash_element
 *      Find egr_obj from gport from hash map
 *
 * [In] unit
 *      HW unit
 *
 * [In] gport
 *      gport
 *
 * [Out] return vxlan_egr_obj_element_t *
 *       Not found - NULL
 *       Found - (vxlan_egr_obj_element_t *)->egr_obj
 */
static
vxlan_egr_obj_element_t *
vxlan_find_egr_obj_hash_element(int unit, int gport)
{
    uint32_t hash;
    vxlan_egr_obj_element_t *egr_obj_element_p;
    vxlan_egr_obj_element_t *egr_obj_element_found_p;

    hash = hash_2words((uint32_t)gport, unit);

    egr_obj_element_found_p = NULL;
    HMAP_FOR_EACH_WITH_HASH (egr_obj_element_p, node, hash,
                             &vxlan_global.egr_obj_hmap) {
        if ((egr_obj_element_p->unit == unit) &&
            (egr_obj_element_p->gport == gport)) {
            egr_obj_element_found_p = egr_obj_element_p;
            break;
        }
    }

    return  egr_obj_element_found_p;
}

/*
 * Function: vxlan_create_logical_switch
 *      Create Vxlan logical switch.
 *
 * [In] unit
 *      HW unit
 *
 * [In] logical_sw_p
 *      logical_sw_p->vnid
 *      logical_sw_p->broadcast_group
 *      logical_sw_p->unknown_multicast_group
 *      logical_sw_p->unknown_unicast_group
 *
 * [Out] logical_sw_p
 *       logical_sw_p->vpn_id
 *
 * [Out] return
 *       see BCMSDK_E_XXX
 */
static
int
vxlan_create_logical_switch(int unit, bcmsdk_vxlan_logical_switch_t *logical_sw_p)
{
    opennsl_vxlan_vpn_config_t vpn_info;
    int rc;
    int rc1;

    if (!logical_sw_p) {
        VLOG_ERR("Error [%s, %d], logical_sw_p is NULL\n",
                 __FUNCTION__, __LINE__);
        return BCMSDK_E_PARAM;
    }

    opennsl_vxlan_vpn_config_t_init(&vpn_info);
    vpn_info.flags = OPENNSL_VXLAN_VPN_ELAN | OPENNSL_VXLAN_VPN_WITH_VPNID;
    vpn_info.vnid = (uint32)logical_sw_p->vnid;
    vpn_info.broadcast_group         = logical_sw_p->broadcast_group;
    vpn_info.unknown_multicast_group = logical_sw_p->unknown_multicast_group;
    vpn_info.unknown_unicast_group   = logical_sw_p->unknown_unicast_group;
    rc = opennsl_vxlan_vpn_create(unit, &vpn_info);

    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_vpn_create rc:%d unit:%d vnid:%d broadcast_group:%d unknown_multicast_group:%d unknown_unicast_group:%d\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 vpn_info.vnid, vpn_info.broadcast_group,
                 vpn_info.unknown_multicast_group,
                 vpn_info.unknown_unicast_group);
        return rc;
    }

    logical_sw_p->vpn_id = vpn_info.vpn;

    /* Add vnid key and vpn_id value to hash map */
    if (!vxlan_find_logical_switch_hash_element(unit,
                                                logical_sw_p->vnid)) {

        rc = vxlan_insert_logical_switch_hash_element(unit, logical_sw_p);
        if (rc) {
            /* Fail to allocate element, clean up everything */
            rc1 = opennsl_vxlan_vpn_destroy(unit, vpn_info.vpn);

            if (rc1) {
                VLOG_ERR("Error [%s, %d], opennsl_vxlan_vpn_destroy rc:%d unit:%d vpn_id:0x%x\n",
                         __FUNCTION__, __LINE__, rc1, unit, vpn_info.vpn);
                return rc1;
            }
            return rc;
        }
    }

    VLOG_DBG("[%s, %d] exit rc:%d unit:%d vnid:%d broadcast_group:%d unknown_multicast_group:%d unknown_unicast_group:%d vpn:0x%x\n",
             __FUNCTION__, __LINE__, rc, unit,
             vpn_info.vnid, vpn_info.broadcast_group,
             vpn_info.unknown_multicast_group,
             vpn_info.unknown_unicast_group,
             logical_sw_p->vpn_id);

    return rc;
}


/*
 * Function: vxlan_destroy_logical_switch
 *      Destroy Vxlan logical switch.
 *      User needs to make sure all Vxlan access and network vports
 *      get deleted first.
 *
 * [In] unit
 *      HW unit
 *
 * [In] logical_sw_p
 *      logical_sw_p->vnid
 *
 * [Out] logical_sw_p
 *       logical_sw_p->vpn_id
 *       logical_sw_p->broadcast_group
 *       logical_sw_p->unknown_multicast_group
 *       logical_sw_p->unknown_unicast_group
 *
 * [Out] return
 *       see BCMSDK_E_XXX
 */
static
int
vxlan_destroy_logical_switch(int unit, bcmsdk_vxlan_logical_switch_t *logical_sw_p)
{
    int rc;
    vxlan_logical_sw_element_t *logical_sw_element_p;

    logical_sw_element_p = vxlan_find_logical_switch_hash_element(unit,
                                           logical_sw_p->vnid);
    if (logical_sw_element_p == NULL) {
        VLOG_ERR("Error [%s, %d], invalid vnid unit:%d vnid:%d\n",
                 __FUNCTION__, __LINE__, unit, logical_sw_p->vnid);
        return BCMSDK_E_PARAM;
    }

    logical_sw_p->vpn_id = logical_sw_element_p->vpn_id;
    logical_sw_p->broadcast_group = logical_sw_element_p->broadcast_group;
    logical_sw_p->unknown_multicast_group =
        logical_sw_element_p->unknown_multicast_group;
    logical_sw_p->unknown_unicast_group =
        logical_sw_element_p->unknown_unicast_group;

    hmap_remove(&vxlan_global.logical_sw_hmap,
                &logical_sw_element_p->node);

    rc = opennsl_vxlan_vpn_destroy(unit, logical_sw_p->vpn_id);

    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_vpn_destroy rc:%d unit:%d vpn_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, logical_sw_p->vpn_id);
        return rc;
    }

    VLOG_DBG("[%s, %d] exit rc:%d unit:%d vnid:%d vpn_id:0x%x\n",
             __FUNCTION__, __LINE__, rc, unit, logical_sw_p->vnid,
             logical_sw_p->vpn_id);

    return rc;
}


/*
 * Function: vxlan_get_logical_switch
 *      Get Vxlan logical switch.
 *
 * [In] unit
 *      HW unit
 *
 * [In] logical_sw_p
 *      logical_sw_p->vnid
 *
 * [Out] logical_sw_p
 *       logical_sw_p->vpn_id
 *       logical-sw_p->broadcast_group
 *       logical-sw_p->unknown_multicast_group
 *       logical-sw_p->unknown_unicast_group
 *
 * [Out] return
 *       see BCMSDK_E_XXX
 */
static
int
vxlan_get_logical_switch(int unit, bcmsdk_vxlan_logical_switch_t *logical_sw_p)
{
    opennsl_vxlan_vpn_config_t vpn_info;
    int rc;
    vxlan_logical_sw_element_t *logical_sw_element_p;

    if (!logical_sw_p) {
        VLOG_ERR("Error [%s, %d], logical_sw_p is NULL\n",
                 __FUNCTION__, __LINE__);
        return BCMSDK_E_PARAM;
    }

    logical_sw_element_p = vxlan_find_logical_switch_hash_element(unit, logical_sw_p->vnid);
    if (logical_sw_element_p == NULL) {
        VLOG_ERR("Error [%s, %d], vxlan_find_logical_switch_hash_element unit:%d vnid:%d\n",
                 __FUNCTION__, __LINE__, unit, logical_sw_p->vnid);
        return BCMSDK_E_PARAM;
    }
    logical_sw_p->vpn_id = logical_sw_element_p->vpn_id;

    rc = opennsl_vxlan_vpn_get(unit, logical_sw_p->vpn_id, &vpn_info);

    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_vpn_get rc:%d unit:%d vpn_id:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, logical_sw_p->vpn_id);
        return rc;
    }

    logical_sw_p->vnid = vpn_info.vpn;
    logical_sw_p->broadcast_group = vpn_info.broadcast_group;
    logical_sw_p->unknown_multicast_group = vpn_info.unknown_multicast_group;
    logical_sw_p->unknown_unicast_group = vpn_info.unknown_unicast_group;
    logical_sw_p->vpn_id = vpn_info.vpn;

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d vnid:%d broadcast_group:0x%x unknown_multicast_group:0x%x unknown_unicast_group:0x%x vpn:0x%x\n",
             __FUNCTION__, __LINE__, rc, unit,
             logical_sw_p->vnid, logical_sw_p->broadcast_group,
             logical_sw_p->unknown_multicast_group,
             logical_sw_p->unknown_unicast_group,
             logical_sw_p->vpn_id);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_update_logical_switch
 *      Update Vxlan logical switch.
 */
static
int
vxlan_update_logical_switch(int unit, bcmsdk_vxlan_logical_switch_t *logical_sw_p)
{
    /* Not supported by hardware */

    return BCMSDK_E_PARAM;
}

/*
 * Function: vxlan_create_tunnel_initiator
 *      Create tunnel initiator.
 *
 * [In] unit
 *      HW unit
 *
 * [In] tunnel_p
 *      tunnel_p->ttl
 *      tunnel_p->local_ip
 *      tunnel_p->remote_ip
 *      tunnel_p->udp_dst_port
 *      tunnel_p->udp_src_port
 *
 * [Out] tunnel_p
 *       tunnel_p->tunnel_id
 *
 * [Out] return
 *       see BCMSDK_E_XXX
 */
static
int
vxlan_create_tunnel_initiator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p)
{
    opennsl_tunnel_initiator_t tnl_init;
    int rc;

    if (!tunnel_p) {
        VLOG_ERR("Error [%s, %d], tunnel_p is NULL\n",
                 __FUNCTION__, __LINE__);
        return BCMSDK_E_PARAM;
    }

    opennsl_tunnel_initiator_t_init(&tnl_init);
    tnl_init.type  = opennslTunnelTypeVxlan;
    tnl_init.ttl = tunnel_p->ttl;
    tnl_init.sip = tunnel_p->local_ip;
    tnl_init.dip = tunnel_p->remote_ip;
    tnl_init.udp_dst_port = tunnel_p->udp_dst_port;
    tnl_init.udp_src_port = tunnel_p->udp_src_port;
    rc = opennsl_vxlan_tunnel_initiator_create(unit, &tnl_init);

    if (rc) {
        VLOG_ERR("Error [%s, %d], exit rc:%d unit:%d sip:0x%08x dip:0x%08x udp_dst_port:%d udp_src_port:%x ttl:%d\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 tunnel_p->local_ip, tunnel_p->remote_ip,
                 tunnel_p->udp_dst_port, tunnel_p->udp_src_port,
                 tunnel_p->ttl);
        return rc;
    }

    tunnel_p->tunnel_id = tnl_init.tunnel_id;

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d sip:0x%08x dip:0x%08x udp_dst_port:%d udp_src_port:%x ttl:%d tunnel_id:0x%x\n",
             __FUNCTION__, __LINE__, rc, unit,
             tunnel_p->local_ip, tunnel_p->remote_ip,
             tunnel_p->udp_dst_port, tunnel_p->udp_src_port, tunnel_p->ttl,
             tunnel_p->tunnel_id);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_destroy_tunnel_initiator
 *      Destroy tunnel initiator.
 *
 * [In] unit
 *      HW unit
 *
 * [In] tunnel_id
 *      tunnel ID
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_destroy_tunnel_initiator(int unit, int tunnel_id)
{
    int rc;

    rc = opennsl_vxlan_tunnel_initiator_destroy(unit, tunnel_id);

    if (rc) {
        VLOG_ERR("Error [%s, %d], exit rc:%d unit:%d tunnel_id:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, tunnel_id);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d tunnel_id:%d\n",
             __FUNCTION__, __LINE__, rc, unit, tunnel_id);

    return BCMSDK_E_NONE;
}

/*
 * Function: vxlan_get_tunnel_initiator
 *      Get tunnel initiator information.
 *
 * [In] unit
 *      HW unit
 *
 * [In] tunnel_p
 *       tunnel_p->tunnel_id
 *
 * [Out] tunnel_p
 *       tunnel_p->ttl
 *       tunnel_p->local_ip
 *       tunnel_p->remote_ip
 *       tunnel_p->udp_dst_port
 *       tunnel_p->udp_src_port
 *
 * [Out] return
 *       see BCMSDK_E_XXX
 */
static
int
vxlan_get_tunnel_initiator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p)
{
    opennsl_tunnel_initiator_t tnl_init;
    int rc;

    if (!tunnel_p) {
        VLOG_ERR("Error [%s, %d], tunnel_p is NULL\n",
                 __FUNCTION__, __LINE__);
        return BCMSDK_E_PARAM;
    }

    tnl_init.tunnel_id = tunnel_p->tunnel_id;
    rc = opennsl_vxlan_tunnel_initiator_get(unit, &tnl_init);

    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_tunnel_initiator_get rc:%d unit:%d tunnel_id:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, tunnel_p->tunnel_id);
        return rc;
    }

    tunnel_p->ttl = tnl_init.ttl;
    tunnel_p->local_ip = tnl_init.sip;
    tunnel_p->remote_ip = tnl_init.dip;
    tunnel_p->udp_dst_port = tnl_init.udp_dst_port;
    tunnel_p->udp_src_port = tnl_init.udp_src_port;

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d sip:0x%08x dip:0x%08x udp_dst_port:%d udp_src_port:%x ttl:%d tunnel_id:0x%x\n",
             __FUNCTION__, __LINE__, rc, unit,
             tunnel_p->local_ip, tunnel_p->remote_ip,
             tunnel_p->udp_dst_port, tunnel_p->udp_src_port, tunnel_p->ttl,
             tunnel_p->tunnel_id);

    return BCMSDK_E_NONE;
}

/*
 * Function: vxlan_update_tunnel_initiator
 *      Update Vxlan tunnel.
 *
 * [In] unit
 *      HW unit
 *
 * [In] tunnel_p
 *      tunnel_p->local_ip
 *
 * [Out] return
 *       see BCMSDK_E_XXX
 *
 * Note: Hardware only support update of local_ip.
         Hardware does not support update of remote_ip, udp_dst_port,
         udp_src_port.
 *       Attempt to update those fields will return error.
 *
 */
int
vxlan_update_tunnel_initiator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p)
{
    opennsl_tunnel_initiator_t tnl_init;
    int rc;

    if (!tunnel_p) {
        VLOG_ERR("Error [%s, %d], tunnel_p is NULL\n",
                 __FUNCTION__, __LINE__);
        return BCMSDK_E_PARAM;
    }

    opennsl_tunnel_initiator_t_init(&tnl_init);
    tnl_init.type  = opennslTunnelTypeVxlan;
    tnl_init.tunnel_id = tunnel_p->tunnel_id;
    tnl_init.flags = OPENNSL_TUNNEL_REPLACE;
    tnl_init.ttl = tunnel_p->ttl;
    tnl_init.sip = tunnel_p->local_ip;
    tnl_init.dip = tunnel_p->remote_ip;
    tnl_init.udp_dst_port = tunnel_p->udp_dst_port;
    tnl_init.udp_src_port = tunnel_p->udp_src_port;
    rc = opennsl_vxlan_tunnel_initiator_create(unit, &tnl_init);

    if (rc) {
        VLOG_ERR("Error [%s, %d], exit rc:%d unit:%d sip:0x%08x dip:0x%08x udp_dst_port:%d udp_src_port:%x ttl:%d\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 tunnel_p->local_ip, tunnel_p->remote_ip,
                 tunnel_p->udp_dst_port, tunnel_p->udp_src_port,
                 tunnel_p->ttl);
        return rc;
    }

    tunnel_p->tunnel_id = tnl_init.tunnel_id;

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d sip:0x%08x dip:0x%08x udp_dst_port:%d udp_src_port:%x ttl:%d tunnel_id:0x%x\n",
             __FUNCTION__, __LINE__, rc, unit,
             tunnel_p->local_ip, tunnel_p->remote_ip,
             tunnel_p->udp_dst_port, tunnel_p->udp_src_port, tunnel_p->ttl,
             tunnel_p->tunnel_id);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_create_tunnel_terminator
 *      Create tunnel terminator.
 *
 * [In] unit
 *      HW unit
 *
 * [In] tunnel_p
 *      tunnel_p->ttl
 *      tunnel_p->local_ip
 *      tunnel_p->remote_ip
 *      tunnel_p->udp_dst_port
 *      tunnel_p->udp_src_port
 *      tunnel_p->vlan
 *      tunnel_p->tunnel_id (returned from vxlan_create_tunnel_initiator)
 *
 * [Out] return
 *       see BCMSDK_E_XXX
 */
static
int
vxlan_create_tunnel_terminator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p)
{
    opennsl_tunnel_terminator_t tnl_term;
    int rc;

    if (!tunnel_p) {
        VLOG_ERR("Error [%s, %d], tunnel_p is NULL\n",
                 __FUNCTION__, __LINE__);
        return BCMSDK_E_PARAM;
    }

    opennsl_tunnel_terminator_t_init(&tnl_term);
    tnl_term.type  = opennslTunnelTypeVxlan;
    tnl_term.sip = tunnel_p->remote_ip;  /* For MC tunnel, Don't care */
    tnl_term.dip = tunnel_p->local_ip;
    tnl_term.tunnel_id = tunnel_p->tunnel_id;
    tnl_term.flags = OPENNSL_TUNNEL_TERM_TUNNEL_WITH_ID;
    tnl_term.vlan = tunnel_p->vlan;     /* MC tunnel only - for Bud check */
    rc = opennsl_vxlan_tunnel_terminator_create(unit, &tnl_term);

    if (rc) {
        VLOG_ERR("Error [%s, %d], exit rc:%d unit:%d sip:0x%08x dip:0x%08x tunnel_id:%d flags:0x%x vlan:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, tnl_term.sip, tnl_term.dip,
                 tnl_term.tunnel_id, tnl_term.flags, tnl_term.vlan);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d sip:0x%08x dip:0x%08x tunnel_id:%d flags:0x%x vlan:%d\n",
             __FUNCTION__, __LINE__, rc, unit,  tnl_term.sip, tnl_term.dip,
             tnl_term.tunnel_id, tnl_term.flags, tnl_term.vlan);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_destroy_tunnel_terminator
 *      Destroy tunnel terminator.
 *
 * [In] unit
 *      HW unit
 *
 * [In] tunnel_id
 *      tunnel ID
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_destroy_tunnel_terminator(int unit, int tunnel_id)
{
    int rc;

    rc = opennsl_vxlan_tunnel_terminator_destroy(unit, tunnel_id);

    if (rc) {
        VLOG_ERR("Error [%s, %d], exit rc:%d unit:%d tunnel_id:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, tunnel_id);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d tunnel_id:%d\n",
             __FUNCTION__, __LINE__, rc, unit, tunnel_id);

    return BCMSDK_E_NONE;
}

/*
 * Function: vxlan_get_tunnel_terminator
 *      Get tunnel terminator information.
 *
 * [In] unit
 *      HW unit
 *
 * [In] tunnel_p
 *       tunnel_p->tunnel_id
 *
 * [Out] tunnel_p
 *       tunnel_p->ttl
 *       tunnel_p->local_ip
 *       tunnel_p->remote_ip
 *       tunnel_p->udp_dst_port
 *       tunnel_p->udp_src_port
 *       tunnel_p->vlan
 *
 * [Out] return
 *       see BCMSDK_E_XXX
 */
static
int
vxlan_get_tunnel_terminator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p)
{
    opennsl_tunnel_terminator_t tnl_term;
    int rc;

    if (!tunnel_p) {
        VLOG_ERR("Error [%s, %d], tunnel_p is NULL\n",
                 __FUNCTION__, __LINE__);
        return BCMSDK_E_PARAM;
    }

    tnl_term.tunnel_id = tunnel_p->tunnel_id;
    rc = opennsl_vxlan_tunnel_terminator_get(unit, &tnl_term);

    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_tunnel_initiator_get rc:%d unit:%d tunnel_id:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, tunnel_p->tunnel_id);
        return rc;
    }

    tunnel_p->local_ip = tnl_term.sip;
    tunnel_p->remote_ip = tnl_term.dip;
    tunnel_p->udp_dst_port = tnl_term.udp_dst_port;
    tunnel_p->udp_src_port = tnl_term.udp_src_port;
    tunnel_p->vlan = tnl_term.vlan;

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d sip:0x%08x dip:0x%08x udp_dst_port:%d udp_src_port:%x ttl:%d vlan:%d tunnel_id:0x%x\n",
             __FUNCTION__, __LINE__, rc, unit,
             tunnel_p->local_ip, tunnel_p->remote_ip,
             tunnel_p->udp_dst_port, tunnel_p->udp_src_port, tunnel_p->ttl,
             tunnel_p->vlan, tunnel_p->tunnel_id);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_update_tunnel_terminator
 *      Update Vxlan tunnel.
 *
 * [In] unit
 *      HW unit
 *
 * [In] tunnel_p
 *       tunnel_p->ttl
 *       tunnel_p->local_ip
 *       tunnel_p->remote_ip
 *       tunnel_p->udp_dst_port
 *       tunnel_p->udp_src_port
 *
 * [Out] return
 *       see BCMSDK_E_XXX
 *
 * Note: All tunnel information for terminator can be updated.
 *       There is no limitation as in initiator where only
 *       local_ip can be updated.
 */
//static
int
vxlan_update_tunnel_terminator(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p)
{
    opennsl_tunnel_terminator_t tnl_term;
    int rc;

    if (!tunnel_p) {
        VLOG_ERR("Error [%s, %d], tunnel_p is NULL\n",
                 __FUNCTION__, __LINE__);
        return BCMSDK_E_PARAM;
    }

    opennsl_tunnel_terminator_t_init(&tnl_term);
    tnl_term.type  = opennslTunnelTypeVxlan;
    tnl_term.sip = tunnel_p->remote_ip;  /* For MC tunnel, Don't care */
    tnl_term.dip = tunnel_p->local_ip;
    tnl_term.tunnel_id = tunnel_p->tunnel_id;
    tnl_term.flags = OPENNSL_TUNNEL_TERM_TUNNEL_WITH_ID;
    tnl_term.vlan = tunnel_p->vlan;     /* MC tunnel only - for Bud check */
    rc = opennsl_vxlan_tunnel_terminator_create(unit, &tnl_term);

    if (rc) {
        VLOG_ERR("Error [%s, %d], exit rc:%d unit:%d sip:0x%08x dip:0x%08x tunnel_id:%d flags:0x%x vlan:%d\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 tnl_term.sip, tnl_term.dip,
                 tnl_term.tunnel_id, tnl_term.flags, tnl_term.vlan);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d sip:0x%08x dip:0x%08x tunnel_id:%d flags:0x%x vlan:%d\n",
             __FUNCTION__, __LINE__, rc, unit,  tnl_term.sip, tnl_term.dip,
             tnl_term.tunnel_id, tnl_term.flags, tnl_term.vlan);

    return BCMSDK_E_NONE;
}

/*
 * Function: vxlan_create_tunnel
 *      Create tunnel initiator and terminator.
 *
 * [In] unit
 *      HW unit
 *
 * [In] tunnel_p
 *      tunnel_p->ttl
 *      tunnel_p->local_ip
 *      tunnel_p->remote_ip
 *      tunnel_p->udp_dst_port
 *      tunnel_p->udp_src_port
 *
 * [Out] tunnel_p
 *       tunnel_p->tunnel_id
 *
 * [Out] return
 *       see BCMSDK_E_XXX
 */
static
int
vxlan_create_tunnel(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p)
{
    int rc;

    if (!tunnel_p) {
        VLOG_ERR("Error [%s, %d], tunnel_p is NULL\n",
                 __FUNCTION__, __LINE__);
        return BCMSDK_E_PARAM;
    }

    rc = vxlan_create_tunnel_initiator(unit, tunnel_p);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_create_tunnel_initiator rc:%d unit:%d tunnel_p:%p\n",
                 __FUNCTION__, __LINE__, rc, unit, tunnel_p);
        return rc;
    }

    rc = vxlan_create_tunnel_terminator(unit, tunnel_p);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_create_tunnel_terminator rc:%d unit:%d tunnel_p:%p\n",
                 __FUNCTION__, __LINE__, rc, unit, tunnel_p);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d tunnel_p:%p\n",
             __FUNCTION__, __LINE__, rc, unit, tunnel_p);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_destroy_tunnel
 *      Destroy tunnel initiator and terminator.
 *
 * [In] unit
 *      HW unit
 *
 * [In] tunnel_id
 *      tunnel ID
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_destroy_tunnel(int unit, int tunnel_id)
{
    int rc;

    rc = vxlan_destroy_tunnel_terminator(unit, tunnel_id);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_destroy_tunnel_terminator rc:%d unit:%d tunnel_id:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, tunnel_id);
        return rc;
    }

    rc = vxlan_destroy_tunnel_initiator(unit, tunnel_id);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_destroy_tunnel_initiator rc:%d unit:%d tunnel_id:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, tunnel_id);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d tunnel_id:%d\n",
             __FUNCTION__, __LINE__, rc, unit, tunnel_id);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_get_tunnel
 *      Get tunnel initiator and terminator.
 *
 * [In] unit
 *      HW unit
 *
 * [In] tunnel_p
 *       tunnel_p->tunnel_id
 *
 * [Out] tunnel_p
 *       tunnel_p->ttl
 *       tunnel_p->local_ip
 *       tunnel_p->remote_ip
 *       tunnel_p->udp_dst_port
 *       tunnel_p->udp_src_port
 *       tunnel_p->vlan
 *
 * [Out] return
 *       see BCMSDK_E_XXX
 */
static
int
vxlan_get_tunnel(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p)
{
    int rc;
    bcmsdk_vxlan_tunnel_t tnl_init;
    bcmsdk_vxlan_tunnel_t tnl_term;

    if (tunnel_p == NULL) {
        VLOG_ERR("Error [%s, %d], tunnel_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    memset(&tnl_init, 0, sizeof(tnl_init));
    tnl_init.tunnel_id = tunnel_p->tunnel_id;
    rc = vxlan_get_tunnel_initiator(unit, &tnl_init);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_get_tunnel_initiator rc:%d unit:%d\n",
                 __FUNCTION__, __LINE__, rc, unit);
        return rc;
    }

    memset(&tnl_term, 0, sizeof(tnl_term));
    tnl_term.tunnel_id = tunnel_p->tunnel_id;
    rc = vxlan_get_tunnel_terminator(unit, &tnl_term);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_get_tunnel_terminator rc:%d unit:%d\n",
                 __FUNCTION__, __LINE__, rc, unit);
        return rc;
    }

    if (tnl_init.local_ip != tnl_term.remote_ip) {
        VLOG_ERR("Error [%s, %d], unit:%d tunnel_id:%d tunnel initiator local_ip:0x%08x not match tunnel terminator remote_ip:0x%08x\n",
                 __FUNCTION__, __LINE__, unit,
                 tunnel_p->tunnel_id, tnl_init.local_ip,
                 tnl_term.remote_ip);
        return BCMSDK_E_FAIL;
    }

    if (tnl_init.remote_ip != tnl_term.local_ip) {
        VLOG_ERR("Error [%s, %d], unit:%d tunnel_id:%d tunnel initiator remote_ip:0x%08x not match tunnel terminator local_ip:0x%08x\n",
                 __FUNCTION__, __LINE__,
                 unit, tunnel_p->tunnel_id, tnl_init.remote_ip,
                 tnl_term.local_ip);
        return BCMSDK_E_FAIL;
    }

    tunnel_p->ttl = tnl_init.ttl;
    tunnel_p->local_ip = tnl_init.local_ip;
    tunnel_p->remote_ip = tnl_init.remote_ip;
    tunnel_p->udp_dst_port = tnl_init.udp_dst_port;
    tunnel_p->udp_src_port = tnl_init.udp_src_port;
    tunnel_p->vlan = tnl_term.vlan;

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_update_tunnel
 *      Update Vxlan tunnel.
 */
static
int
vxlan_update_tunnel(int unit, bcmsdk_vxlan_tunnel_t *tunnel_p)
{
    /* Not supported by hardware */

    return BCMSDK_E_PARAM;
}


/*
 * Function: vxlan_access_port_configure
 *      Configure a port to be vxlan access port.
 *
 * [In] unit
 *      HW unit
 *
 * [In] port
 *       Physical access port
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_access_port_configure(int unit, int port)
{
    int rc;
    bool flag;

    /* Default is FALSE.
       Explicitly disable Vxlan processing on access port in case
       it has been changed. */
    flag = FALSE;
    rc = opennsl_port_control_set(unit, port, opennslPortControlVxlanEnable,
                                  flag);

    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_control_set rc:%d unit:%d port:0x%x opennslPortControlVxlanEnable:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, port, flag);
        return rc;
    }

    /* Default is FALSE.
       Explicitly disable tunnel based vxlan VnId lookup in case it
       has been changed. */
    rc = opennsl_port_control_set(unit, port,
                                  opennslPortControlVxlanTunnelbasedVnId,
                                  flag);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_control_set rc:%d unit:%d port:0x%x opennslPortControlVxlanTunnelbasedVnId:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, port, flag);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit unit:%d port:0x%x\n",
             __FUNCTION__, __LINE__, unit, port);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_access_port_unconfigure
 *      UnConfigure a port from vxlan access port.
 *
 * [In] unit
 *      HW unit
 *
 * [In] port
 *       Physical access port
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
//static
int
vxlan_access_port_unconfigure(int unit, int port)
{
    int rc;
    bool flag;

    /* Changed back default which is FALSE */
    flag = FALSE;
    rc = opennsl_port_control_set(unit, port, opennslPortControlVxlanEnable,
                                  flag);

    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_control_set rc:%d unit:%d port:0x%x opennslPortControlVxlanEnable:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, port, flag);
        return rc;
    }

    /* Changed back default which is FALSE */
    rc = opennsl_port_control_set(unit, port,
                                  opennslPortControlVxlanTunnelbasedVnId,
                                  flag);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_control_set rc:%d unit:%d port:0x%x opennslPortControlVxlanTunnelbasedVnId:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, port, flag);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit unit:%d port:0x%x\n",
             __FUNCTION__, __LINE__, unit, port);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_bind_access_port
 *      Bind an access port to a logical switch
 *
 * [In] unit
 *      HW unit
 *
 * [In] acc_port_p
 *      acc_port_p->port
 *      acc_port_p->vlan
 *      acc_port_p->vrf
 *      acc_port_p->vnid
 *
 * [Out] acc_port_p
 *       acc_port_p->l3_intf_id
 *       acc_port_p->egr_obj_id
 *       acc_port_p->station_id
 *       acc_port_p->vxlan_port_id (Vxlan virtual port ID)
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_bind_access_port(int unit, bcmsdk_vxlan_port_t *acc_port_p)
{
    int rc;
    int rc1;
    opennsl_vxlan_port_t vxlan_port;
    opennsl_gport_t gport;
    opennsl_l3_intf_t l3_intf;
    opennsl_l3_egress_t l3_egr;
    vxlan_logical_sw_element_t *logical_sw_element_p;

    if (acc_port_p == NULL) {
        VLOG_ERR("Error [%s, %d], acc_port_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    rc = opennsl_port_gport_get(unit, acc_port_p->port, &gport);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_gport_get rc:%d unit:%d port:0x%x gport:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, acc_port_p->port, gport);
        return rc;
    }

    rc = vxlan_access_port_configure(unit, acc_port_p->port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_access_port_configure rc:%d unit:%d port:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, acc_port_p->port);
        return rc;
    }

    opennsl_l3_intf_t_init(&l3_intf);
    l3_intf.l3a_flags = OPENNSL_L3_ADD_TO_ARL;
    memcpy(l3_intf.l3a_mac_addr, VXLAN_DUMMY_MAC,
           ETH_ALEN);
    l3_intf.l3a_vid = acc_port_p->vlan;
    l3_intf.l3a_vrf = acc_port_p->vrf;
    rc = opennsl_l3_intf_create(unit, &l3_intf);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_intf_create rc:%d unit:%d local_mac:%s vlan:%d vrf:%d\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 VXLAN_DUMMY_MAC, acc_port_p->vlan,
                 acc_port_p->vrf);
        goto CLEANUP_ACCESS_PORT_CFG;
    }
    acc_port_p->l3_intf_id = l3_intf.l3a_intf_id;

    opennsl_l3_egress_t_init(&l3_egr);
    l3_egr.flags = OPENNSL_L3_VXLAN_ONLY;
    l3_egr.intf = acc_port_p->l3_intf_id;
    memcpy(l3_egr.mac_addr, VXLAN_DUMMY_MAC,
           ETH_ALEN);
    l3_egr.vlan = acc_port_p->vlan;
    l3_egr.port = gport;
    rc = opennsl_l3_egress_create(unit, 0, &l3_egr,
                                  &(acc_port_p->egr_obj_id));
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_egress_create rc:%d unit:%d next_hop_mac:%s vlan:%d vrf:%d\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 VXLAN_DUMMY_MAC, acc_port_p->vlan,
                 acc_port_p->vrf);
        goto CLEANUP_L3_INTF;
    }

    logical_sw_element_p = vxlan_find_logical_switch_hash_element(unit, acc_port_p->vnid);
    if (logical_sw_element_p == NULL) {
        VLOG_ERR("Error [%s, %d], invalid vnid unit:%d vnid:%d\n",
                 __FUNCTION__, __LINE__, unit, acc_port_p->vnid);
        rc = BCMSDK_E_PARAM;
        goto CLEANUP_EGRESS_OBJ;
    }

    opennsl_vxlan_port_t_init(&vxlan_port);
    vxlan_port.flags = OPENNSL_VXLAN_PORT_SERVICE_TAGGED;
    vxlan_port.match_port = gport;
    vxlan_port.criteria = OPENNSL_VXLAN_PORT_MATCH_PORT;
    vxlan_port.egress_if = acc_port_p->egr_obj_id;
    vxlan_port.match_vlan = acc_port_p->vlan;

    rc = opennsl_vxlan_port_add(unit, logical_sw_element_p->vpn_id,
                                &vxlan_port);

    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_port_add rc:%d unit:%d port:0x%x l3_intf_id:0x%x egr_obj_id:0x%x vlan:%d vnid:%d local_mac:%s next_hop_mac:%s\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 acc_port_p->port, acc_port_p->l3_intf_id,
                 acc_port_p->egr_obj_id, acc_port_p->vlan,
                 acc_port_p->vnid, VXLAN_DUMMY_MAC, VXLAN_DUMMY_MAC);
        goto CLEANUP_EGRESS_OBJ;
    }

    acc_port_p->vxlan_port_id = vxlan_port.vxlan_port_id;

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d port:0x%x l3_intf_id:0x%x egr_obj_id:0x%x vlan:%d vnid:%d local_mac:%s next_hop_mac:%s vxlan_port_id:0x%x\n",
             __FUNCTION__, __LINE__, rc, unit,
             acc_port_p->port, acc_port_p->l3_intf_id,
             acc_port_p->egr_obj_id, acc_port_p->vlan,
             acc_port_p->vnid, VXLAN_DUMMY_MAC,
             VXLAN_DUMMY_MAC, acc_port_p->vxlan_port_id);

    return BCMSDK_E_NONE;


    /* Error return */

 CLEANUP_EGRESS_OBJ:
    rc1 = opennsl_l3_egress_destroy(unit, acc_port_p->egr_obj_id);
    if (rc1) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_egress_destroy rc:%d unit:%d egr_obj_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, acc_port_p->egr_obj_id);
        return rc1;
    }

 CLEANUP_L3_INTF:
    rc1 = opennsl_l3_intf_delete(unit, &l3_intf);
    if (rc1) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_intf_delete rc:%d unit:%d l3_intf_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc1, unit, acc_port_p->l3_intf_id);
        return rc;
    }

 CLEANUP_ACCESS_PORT_CFG:
    rc1 = vxlan_access_port_unconfigure(unit, acc_port_p->port);
    if (rc1) {
        VLOG_ERR("Error [%s, %d], vxlan_access_port_unconfigure rc:%d unit:%d port:0x%x\n",
                 __FUNCTION__, __LINE__, rc1, unit, acc_port_p->port);
        return rc1;
    }

    return  rc;
}


/*
 * Function: vxlan_unbind_access_port
 *      Unbind an access port from a logical switch.
 *      Please make sure the forwarding path that corresonding
 *      to this path is no longer in used. If the forwarding
 *      is still in used. This function will return BCMSDK_E_BUSY.
 *
 * [In] unit
 *      HW unit
 *
 * [In] acc_port_p
 *      acc_port_p->vxlan_port_id (Vxlan virtual port ID)
 *      acc_port_p->vnid
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_unbind_access_port(int unit, bcmsdk_vxlan_port_t *acc_port_p)
{
    int rc;
    opennsl_l3_intf_t l3_intf;
    opennsl_l3_egress_t l3_egr;
    opennsl_vxlan_port_t vxlan_port;
    vxlan_logical_sw_element_t *logical_sw_element_p;

    if (acc_port_p == NULL) {
        VLOG_ERR("Error [%s, %d], acc_port_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    logical_sw_element_p = vxlan_find_logical_switch_hash_element(unit, acc_port_p->vnid);
    if (logical_sw_element_p == NULL) {
        VLOG_ERR("Error [%s, %d], invalid vnid unit:%d vnid:%d\n",
                 __FUNCTION__, __LINE__, unit, acc_port_p->vnid);
        return BCMSDK_E_PARAM;
    }

    vxlan_port.vxlan_port_id = acc_port_p->vxlan_port_id;
    rc = opennsl_vxlan_port_get(unit, logical_sw_element_p->vpn_id,
                                &vxlan_port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_port_get rc:%d unit:%d vxlan_port_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 acc_port_p->vxlan_port_id);
        return rc;
    }

    acc_port_p->egr_obj_id = vxlan_port.egress_if;
    rc = opennsl_port_local_get(unit, vxlan_port.match_port,
                                &acc_port_p->port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_local_get rc:%d unit:%d gport:0x%x vxlan_port_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 vxlan_port.match_port,
                 acc_port_p->vxlan_port_id);
        return rc;
    }

    rc = vxlan_access_port_unconfigure(unit, acc_port_p->port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_access_port_unconfigure rc:%d unit:%d port:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, acc_port_p->port);
        return rc;
    }

    /* Delete the access port from Vxlan */
    rc = opennsl_vxlan_port_delete(unit, logical_sw_element_p->vpn_id,
                                   acc_port_p->vxlan_port_id);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_port_delete rc:%d unit:%d vpn_id:0x%x vnid:%d vxlan_port_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 logical_sw_element_p->vpn_id,
                 acc_port_p->vnid, acc_port_p->vxlan_port_id);
        return rc;
    }

    rc = opennsl_l3_egress_get(unit, acc_port_p->egr_obj_id, &l3_egr);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_egress_get rc:%d unit:%d egr_obj_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, acc_port_p->egr_obj_id);
        return rc;
    }

    acc_port_p->l3_intf_id = l3_egr.intf;

    /* Destroy the egress object.
       Note: Only unused egress object can be destroyed.
       Attempt to destroy an egress object that is being used by
       forwarding path will result in BCMSDK_E_BUSY error. */
    rc = opennsl_l3_egress_destroy(unit, acc_port_p->egr_obj_id);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_egress_destroy rc:%d unit:%d egr_obj_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, acc_port_p->egr_obj_id);
        return rc;
    }

    /* Delete the L3 interface object */
    l3_intf.l3a_intf_id = acc_port_p->l3_intf_id;
    rc = opennsl_l3_intf_delete(unit, &l3_intf);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_intf_delete rc:%d unit:%d l3_intf_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, acc_port_p->l3_intf_id);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d port:0x%x port:0x%x vpn_id:0x%x\n",
             __FUNCTION__, __LINE__, rc, unit,
             acc_port_p->vxlan_port_id, acc_port_p->port,
             acc_port_p->vnid);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_get_access_port
 *      Get access port information
 *
 * [In] unit
 *      HW unit
 *
 * [In] acc_port_p
 *      acc_port_p->vxlan_port_id (Vxlan virtual access port ID)
 *      acc_port_p->vnid
 *
 * [Out] acc_port_p
 *       acc_port_p->port
 *       acc_port_p->vlan
 *       acc_port_p->l3_intf_id
 *       acc_port_p->egr_obj_id
 *       acc_port_p->local_mac
 *       acc_port_p->next_hop_mac
 *       acc_port_p->vrf
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_get_access_port(int unit, bcmsdk_vxlan_port_t *acc_port_p)
{
    int rc;
    opennsl_vxlan_port_t vxlan_port;
    opennsl_l3_intf_t l3_intf;
    opennsl_l3_egress_t l3_egr;
    vxlan_logical_sw_element_t *logical_sw_element_p;

    if (acc_port_p == NULL) {
        VLOG_ERR("Error [%s, %d], acc_port_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    logical_sw_element_p = vxlan_find_logical_switch_hash_element(unit, acc_port_p->vnid);
    if (logical_sw_element_p == NULL) {
        VLOG_ERR("Error [%s, %d], invalid vnid unit:%d vnid:%d\n",
                 __FUNCTION__, __LINE__, unit, acc_port_p->vnid);
        return BCMSDK_E_PARAM;
    }

    vxlan_port.vxlan_port_id = acc_port_p->vxlan_port_id;
    rc = opennsl_vxlan_port_get(unit, logical_sw_element_p->vpn_id,
                                &vxlan_port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_port_get rc:%d unit:%d vpn_id:0x%x vnid:%d vxlan_port_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 logical_sw_element_p->vpn_id, acc_port_p->vnid,
                 acc_port_p->vxlan_port_id);
        return rc;
    }

    rc = opennsl_port_local_get(unit, vxlan_port.match_port,
                                &acc_port_p->port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_local_get rc:%d unit:%d gport:0x%x vxlan_port_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 vxlan_port.match_port,
                 acc_port_p->vxlan_port_id);
        return rc;
    }

    acc_port_p->port = vxlan_port.match_port;
    acc_port_p->vlan = vxlan_port.match_vlan;
    acc_port_p->egr_obj_id = vxlan_port.egress_if;

    rc = opennsl_l3_egress_get(unit, acc_port_p->egr_obj_id, &l3_egr);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_egress_get rc:%d unit:%d egr_obj_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, acc_port_p->egr_obj_id);
        return rc;
    }

    acc_port_p->l3_intf_id = l3_egr.intf;
    memcpy(acc_port_p->next_hop_mac, l3_egr.mac_addr, ETH_ALEN);

    l3_intf.l3a_intf_id = acc_port_p->l3_intf_id;
    rc = opennsl_l3_intf_get(unit, &l3_intf);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_intf_get rc:%d unit:%d l3_intf_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, acc_port_p->l3_intf_id);
        return rc;
    }
    acc_port_p->vrf = l3_intf.l3a_vrf;
    memcpy(acc_port_p->local_mac, l3_intf.l3a_mac_addr, ETH_ALEN);

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d vxlan_port_id:0x%x vlan:%d vnid:%d port:%d\n",
             __FUNCTION__, __LINE__, rc, unit,
             acc_port_p->vxlan_port_id, acc_port_p->vlan, acc_port_p->vnid,
             acc_port_p->port);

    return BCMSDK_E_NONE;
}



/*
 * Function: vxlan_network_port_configure
 *      Configure a port to be vxlan network port.
 *
 * [In] unit
 *      HW unit
 *
 * [In] port
 *      Physical network port
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_network_port_configure(int unit, int port)
{
    int rc;
    bool flag;

    flag = TRUE;
    rc = opennsl_port_control_set(unit, port, opennslPortControlVxlanEnable,
                                  flag);

    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_control_set rc:%d unit:%d port:0x%x opennslPortControlVxlanEnable:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, port, flag);
        return rc;
    }

    /* Default is FALSE.
       Explicitly disable tunnel based vxlan VnId lookup in case it
       has been changed. */
    flag = FALSE;
    rc = opennsl_port_control_set(unit, port,
                                  opennslPortControlVxlanTunnelbasedVnId,
                                  flag);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_control_set rc:%d unit:%d port:0x%x opennslPortControlVxlanTunnelbasedVnId:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, port, flag);
        return rc;
    }

    flag = TRUE;
    rc = opennsl_port_control_set(unit, port,
                                  opennslPortControlVxlanDefaultTunnelEnable,
                                  flag);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_control_set rc:%d unit:%d port:0x%x opennslPortControlVxlanDefaultTunnelEnable:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, port, flag);
        return rc;
    }


    VLOG_DBG("[%s, %d], exit unit:%d port:0x%x\n",
             __FUNCTION__, __LINE__, unit, port);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_network_port_unconfigure
 *      UnConfigure a port from vxlan network port.
 *
 * [In] unit
 *      HW unit
 *
 * [In] port
 *       Physical network port
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_network_port_unconfigure(int unit, int port)
{
    int rc;
    bool flag;

    /* Default is FALSE */
    flag = FALSE;
    rc = opennsl_port_control_set(unit, port, opennslPortControlVxlanEnable,
                                  flag);

    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_control_set rc:%d unit:%d port:0x%x opennslPortControlVxlanEnable:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, port, flag);
        return rc;
    }

    /* Default is FALSE */
    rc = opennsl_port_control_set(unit, port,
                                  opennslPortControlVxlanTunnelbasedVnId,
                                  flag);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_control_set rc:%d unit:%d port:0x%x opennslPortControlVxlanTunnelbasedVnId:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, port, flag);
        return rc;
    }

    /* Default is FALSE */
    rc = opennsl_port_control_set(unit, port,
                                  opennslPortControlVxlanDefaultTunnelEnable,
                                  flag);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_control_set rc:%d unit:%d port:0x%x opennslPortControlVxlanTunnelbasedVnId:%d\n",
                 __FUNCTION__, __LINE__, rc, unit, port, flag);
        return rc;
    }

    VLOG_DBG("[%s, %d], exit unit:%d port:0x%x\n",
             __FUNCTION__, __LINE__, unit, port);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_bind_network_port
 *      Bind an network port to a logical switch
 *
 * [In] unit
 *      HW unit
 *
 * [In] net_port_p
 *      net_port_p->port
 *      net_port_p->local_mac
 *      net_port_p->next_hop_mac
 *      net_port_p->vlan
 *      net_port_p->vrf
 *      net_port_p->tunnel_id
 *      net_port_p->vnid
 *      net_port_p->l3_intf_id
 *
 * [Out] net_port_p
 *       net_port_p->egr_obj_id
 *       net_port_p->station_id
 *       acc_port_p->vxlan_port_id (vxlan virtual port ID)
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_bind_network_port(int unit, bcmsdk_vxlan_port_t *net_port_p)
{
    int rc;
    int rc1;
    opennsl_vxlan_port_t vxlan_port;
    opennsl_gport_t gport;
    opennsl_l3_egress_t l3_egr;
#ifdef L2_STATION
    opennsl_l2_station_t l2_station;
    int i;
#endif
    vxlan_logical_sw_element_t *logical_sw_element_p;
    vxlan_egr_obj_element_t *egr_obj_element_p;
    bcmsdk_vxlan_egr_obj_t egr_obj;

    if (net_port_p == NULL) {
        VLOG_ERR("Error [%s, %d], net_port_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    rc = opennsl_port_gport_get(unit, net_port_p->port, &gport);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_gport_get rc:%d unit:%d port:0x%x gport:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, net_port_p->port, gport);
        return rc;
    }

    rc = vxlan_network_port_configure(unit, net_port_p->port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_network_port_configure rc:%d unit:%d port:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, net_port_p->port);
        return rc;
    }

    /* Check if egress object for this gport already exist,
       if not, create a new one. Otherwise, re-use the existing one */
    egr_obj_element_p = vxlan_find_egr_obj_hash_element(unit, gport);
    if (!egr_obj_element_p) {
        opennsl_l3_egress_t_init(&l3_egr);
        l3_egr.flags = OPENNSL_L3_VXLAN_ONLY;
        l3_egr.intf = net_port_p->l3_intf_id;
        memcpy(l3_egr.mac_addr, net_port_p->next_hop_mac, ETH_ALEN);
        l3_egr.vlan = net_port_p->vlan;
        l3_egr.port = gport;
        rc = opennsl_l3_egress_create(unit, 0, &l3_egr,
                                      &(net_port_p->egr_obj_id));
        if (rc) {
            VLOG_ERR("Error [%s, %d], opennsl_l3_egress_create rc:%d unit:%d next_hop_mac:%02x%02x%02x%02x%02x%02x vlan:%d vrf:%d\n",
                     __FUNCTION__, __LINE__, rc, unit,
                     net_port_p->next_hop_mac[0], net_port_p->next_hop_mac[1],
                     net_port_p->next_hop_mac[2], net_port_p->next_hop_mac[3],
                     net_port_p->next_hop_mac[4], net_port_p->next_hop_mac[5],
                     net_port_p->vlan, net_port_p->vrf);
            goto CLEANUP_EGRESS_OBJ;
        }

        egr_obj.gport = gport;
        egr_obj.egr_obj_id = net_port_p->egr_obj_id;
        rc = vxlan_insert_egr_obj_hash_element(unit, &egr_obj);
        if (rc) {
            VLOG_ERR("Error [%s, %d],  vxlan_insert_egr_obj_hash_element rc:%d unit:%d gport:0x%x egr_obj_id:0x%x\n",
                     __FUNCTION__, __LINE__, rc, unit,
                     egr_obj.gport, egr_obj.egr_obj_id);
            goto CLEANUP_EGRESS_OBJ;
        }
    } else {
        /* If egress object already exist, re-use it */
        net_port_p->egr_obj_id = egr_obj_element_p->egr_obj_id;
    }

    logical_sw_element_p = vxlan_find_logical_switch_hash_element(unit, net_port_p->vnid);
    if (logical_sw_element_p == NULL) {
        VLOG_ERR("Error [%s, %d], invalid vnid unit:%d vnid:%d\n",
                 __FUNCTION__, __LINE__, unit, net_port_p->vnid);
        goto CLEANUP_EGRESS_OBJ;
    }

    opennsl_vxlan_port_t_init(&vxlan_port);
    vxlan_port.flags = OPENNSL_VXLAN_PORT_NETWORK |
        OPENNSL_VXLAN_PORT_EGRESS_TUNNEL;
    vxlan_port.match_port = gport;
    vxlan_port.criteria = OPENNSL_VXLAN_PORT_MATCH_VN_ID;
    vxlan_port.egress_if = net_port_p->egr_obj_id;
    vxlan_port.egress_tunnel_id = net_port_p->tunnel_id;
    vxlan_port.match_tunnel_id = net_port_p->tunnel_id;

    rc = opennsl_vxlan_port_add(unit, logical_sw_element_p->vpn_id,
                                &vxlan_port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_port_add rc:%d unit:%d port:0x%x l3_intf_id:0x%x egr_obj_id:0x%x vlan:%d vnid:%d vpn_id:0x%x local_mac:%02x%02x%02x%02x%02x%02x next_hop_mac:%02x%02x%02x%02x%02x%02x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 net_port_p->port, net_port_p->l3_intf_id,
                 net_port_p->egr_obj_id, net_port_p->vlan,
                 net_port_p->vnid,
                 logical_sw_element_p->vpn_id,
                 net_port_p->local_mac[0], net_port_p->local_mac[1],
                 net_port_p->local_mac[2], net_port_p->local_mac[3],
                 net_port_p->local_mac[4], net_port_p->local_mac[5],
                 net_port_p->next_hop_mac[0], net_port_p->next_hop_mac[1],
                 net_port_p->next_hop_mac[2], net_port_p->next_hop_mac[3],
                 net_port_p->next_hop_mac[4], net_port_p->next_hop_mac[5]
                 );
        goto CLEANUP_EGRESS_OBJ;
    }

    net_port_p->vxlan_port_id = vxlan_port.vxlan_port_id;

    // jin, the opennsl 3.1.0.7 does not support opennsl_l2_station_t
    // with vlan and vlan_mask fields. We will need to communicate
    // with Broadcom about this issue.
#ifdef L2_STATION
    opennsl_l2_station_t_init(&l2_station);
    memcpy(l2_station.dst_mac, net_port_p->local_mac, ETH_ALEN);
    for (i = 0; i < ETH_ALEN; i++) {
        l2_station.dst_mac_mask[i] = 0xff;
    }
    l2_station.vlan = net_port_p->vlan;
    l2_station.vlan_mask = 0xfff;
    l2_station.flags = OPENNSL_L2_STATION_IPV4;
    rc = opennsl_l2_station_add(unit, &(net_port_p->station_id), &l2_station);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l2_station_add rc:%d unit:%d vlan:%d local_mac:%02x%02x%02x%02x%02x%02x\n",
                 __FUNCTION__, __LINE__, rc, unit, net_port_p->vlan,
                 net_port_p->local_mac[0], net_port_p->local_mac[1],
                 net_port_p->local_mac[2], net_port_p->local_mac[3],
                 net_port_p->local_mac[4], net_port_p->local_mac[5]);
        goto CLEANUP_VXLAN_VPORT;
    }
#endif

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d port:0x%x l3_intf_id:0x%x egr_obj_id:0x%x vlan:%d vnid:%d vpn_id:0x%x local_mac:%02x%02x%02x%02x%02x%02x next_hop_mac:%02x%02x%02x%02x%02x%02x station_id:0x%x vxlan_port_id:0x%x\n",
             __FUNCTION__, __LINE__, rc, unit,
             net_port_p->port, net_port_p->l3_intf_id,
             net_port_p->egr_obj_id, net_port_p->vlan,
             net_port_p->vnid,
             logical_sw_element_p->vpn_id,
             net_port_p->local_mac[0], net_port_p->local_mac[1],
             net_port_p->local_mac[2], net_port_p->local_mac[3],
             net_port_p->local_mac[4], net_port_p->local_mac[5],
             net_port_p->next_hop_mac[0], net_port_p->next_hop_mac[1],
             net_port_p->next_hop_mac[2], net_port_p->next_hop_mac[3],
             net_port_p->next_hop_mac[4], net_port_p->next_hop_mac[5],
             net_port_p->station_id,
             net_port_p->vxlan_port_id);

    return BCMSDK_E_NONE;



    /* Error return */
    // jin, temporary comment out due to above opennsl_l2_station_t
    // related block being comment out as CLEANUP_VXLAN_VPORT
    // only defined in above block, without that block of codes
    // enable, it will have compilation error saying that
    // CLEANUP_VXLAN_VPORT is defined but not used
#ifdef L2_STATION
 CLEANUP_VXLAN_VPORT:
#endif
    rc = opennsl_vxlan_port_delete(unit, logical_sw_element_p->vpn_id,
                                   net_port_p->vxlan_port_id);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_port_delete rc:%d unit:%d vpn_id:0x%x vnid:%d vxlan_port_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 logical_sw_element_p->vpn_id,
                 net_port_p->vnid, net_port_p->vxlan_port_id);
        return rc;
    }

 CLEANUP_EGRESS_OBJ:
    rc1 = opennsl_l3_egress_destroy(unit, net_port_p->egr_obj_id);
    if (rc1) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_egress_destroy rc:%d unit:%d egr_obj_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, net_port_p->egr_obj_id);
        return rc1;
    }

    rc1 = vxlan_network_port_unconfigure(unit, net_port_p->port);
    if (rc1) {
        VLOG_ERR("Error [%s, %d], vxlan_network_port_unconfigure rc:%d unit:%d port:0x%x\n",
                 __FUNCTION__, __LINE__, rc1, unit, net_port_p->port);
        return rc1;
    }

    return  rc;
}


/*
 * Function: vxlan_unbind_network_port
 *      Unbind a network port from a logical switch.
 *      This function will not delete the tunnel. Please delete the
 *      vxlan port first, then delete the tunnel.
 *      Please make sure the forwarding path that corresonding
 *      to this path is no longer in used. If the forwarding
 *      is still in used. This function will return BCMSDK_E_BUSY.
 *
 * [In] unit
 *      HW unit
 *
 * [In] net_port_p
 *      net_port_p->vxlan_port_id
 *      net_port_p->vnid
 *      net_port_p->station_id
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_unbind_network_port(int unit, bcmsdk_vxlan_port_t *net_port_p)
{
    int rc;
    opennsl_gport_t gport;
    opennsl_vxlan_port_t vxlan_port;
    opennsl_l3_egress_t l3_egr;
    vxlan_logical_sw_element_t *logical_sw_element_p;
    vxlan_egr_obj_element_t * egr_obj_element_p;

    if (net_port_p == NULL) {
        VLOG_ERR("Error [%s, %d], net_port_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }
    // opennsl 3.1.0.7 does not support opennsl_l2_station_t
#ifdef L2_STATION
    rc = opennsl_l2_station_delete(unit, net_port_p->station_id);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l2_station_delete rc:%d unit:%d station_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, net_port_p->station_id);
        return rc;
    }
#endif
    logical_sw_element_p = vxlan_find_logical_switch_hash_element(unit, net_port_p->vnid);
    if (logical_sw_element_p == NULL) {
        VLOG_ERR("Error [%s, %d], invalid vnid unit:%d vnid:%d\n",
                 __FUNCTION__, __LINE__, unit, net_port_p->vnid);
        return BCMSDK_E_PARAM;
    }

    vxlan_port.vxlan_port_id = net_port_p->vxlan_port_id;
    rc = opennsl_vxlan_port_get(unit, logical_sw_element_p->vpn_id,
                                &vxlan_port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_port_get rc:%d unit:%d vnid:%d vpn_id:0x%x vxlan_port_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 net_port_p->vnid, logical_sw_element_p->vpn_id,
                 net_port_p->vxlan_port_id);
        return rc;
    }

    net_port_p->egr_obj_id = vxlan_port.egress_if;

    /*
     * BCM issue: opennsl_vxlan_port_get() above returns
     * vxlan_port.match_port = 0 causing failure in
     * opennsl_port_local_get().
     * Work around: upper layer passes correct port in
     * net_port_p->port
     * Broadcom case # 1027384 for further reference.
     */
#ifdef PORT_GET
    rc = opennsl_port_local_get(unit, vxlan_port.match_port,
                                &net_port_p->port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_local_get rc:%d unit:%d gport:0x%x vxlan_port_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 vxlan_port.match_port,
                 net_port_p->vxlan_port_id);
        return rc;
    }
#endif
    rc = vxlan_network_port_unconfigure(unit, net_port_p->port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_network_port_unconfigure rc:%d unit:%d port:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, net_port_p->port);
        return rc;
    }

    /* Delete the access port from Vxlan */
    rc = opennsl_vxlan_port_delete(unit, logical_sw_element_p->vpn_id,
                                   net_port_p->vxlan_port_id);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_port_delete rc:%d unit:%d vnid:%d vpn_id:0x%x vxlan_port_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 net_port_p->vnid, logical_sw_element_p->vpn_id,
                 net_port_p->vxlan_port_id);
        return rc;
    }

    rc = opennsl_l3_egress_get(unit, net_port_p->egr_obj_id, &l3_egr);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_egress_get rc:%d unit:%d egr_obj_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, net_port_p->egr_obj_id);
        return rc;
    }

    net_port_p->l3_intf_id = l3_egr.intf;

    /* Destroy the egress object.
       Note: Only unused egress object can be destroyed.
       Attempt to destroy an egress object that use being used by
       forwarding path will result in BCMSDK_E_BUSY error. */
    rc = opennsl_l3_egress_destroy(unit, net_port_p->egr_obj_id);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_egress_destroy rc:%d unit:%d egr_obj_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, net_port_p->egr_obj_id);
        return rc;
    }
#if 1 //MBUI
    rc = opennsl_port_gport_get(unit, net_port_p->port, &gport);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_gport_get rc:%d unit:%d port:0x%x gport:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, net_port_p->port, gport);
        return rc;
    }
    egr_obj_element_p = vxlan_find_egr_obj_hash_element(unit, gport);
    if(egr_obj_element_p) {
        hmap_remove(&vxlan_global.egr_obj_hmap, &egr_obj_element_p->node);
    }
#endif
    VLOG_DBG("[%s, %d], exit rc:%d unit:%d port:0x%x vxlan_port_id:0x%x vnid:%d vpn_id:0x%x\n",
             __FUNCTION__, __LINE__, rc, unit,
             net_port_p->port, net_port_p->vxlan_port_id,
             net_port_p->vnid, logical_sw_element_p->vpn_id);

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_get_network_port
 *      Get network port information
 *
 * [In] unit
 *      HW unit
 *
 * [In] net_port_p
 *      net_port_p->vxlan_port_id
 *      net_port_p->vxlan_vnid
 *
 * [Out] net_port_p
 *       net_port_p->port
 *       net_port_p->egr_obj_id
 *       net_port_p->tunnel_id
 *       net_port_p->vlan
 *       net_port_p->l3_intf_id
 *       net_port_p->vrf
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_get_network_port(int unit, bcmsdk_vxlan_port_t *net_port_p)
{
    int rc;
    opennsl_vxlan_port_t vxlan_port;
    opennsl_l3_intf_t l3_intf;
    opennsl_l3_egress_t l3_egr;
    int i;
    vxlan_logical_sw_element_t *logical_sw_element_p;

    if (net_port_p == NULL) {
        VLOG_ERR("Error [%s, %d], net_port_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    logical_sw_element_p = vxlan_find_logical_switch_hash_element(unit, net_port_p->vnid);
    if (logical_sw_element_p == NULL) {
        VLOG_ERR("Error [%s, %d], invalid vnid unit:%d vnid:%d\n",
                 __FUNCTION__, __LINE__, unit, net_port_p->vnid);
        return BCMSDK_E_PARAM;
    }

    vxlan_port.vxlan_port_id = net_port_p->vxlan_port_id;
    rc = opennsl_vxlan_port_get(unit, logical_sw_element_p->vpn_id,
                                &vxlan_port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_vxlan_port_get rc:%d unit:%d vnid:%d vpn_id:0x%x vxlan_port_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 net_port_p->vnid, logical_sw_element_p->vpn_id,
                 net_port_p->vxlan_port_id);
        return rc;
    }

    rc = opennsl_port_local_get(unit, vxlan_port.match_port,
                                &net_port_p->port);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_port_local_get rc:%d unit:%d gport:0x%x vxlan_port_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit,
                 vxlan_port.match_port,
                 net_port_p->vxlan_port_id);
        return rc;
    }

    net_port_p->egr_obj_id = vxlan_port.egress_if;
    net_port_p->tunnel_id = vxlan_port.match_tunnel_id;

    rc = opennsl_l3_egress_get(unit, net_port_p->egr_obj_id, &l3_egr);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_egress_get rc:%d unit:%d egr_obj_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, net_port_p->egr_obj_id);
        return rc;
    }

    net_port_p->l3_intf_id = l3_egr.intf;
    net_port_p->vlan = l3_egr.vlan;
    for (i = 0; i < ETH_ALEN; i++) {
        net_port_p->next_hop_mac[i] = l3_egr.mac_addr[i];
    }

    l3_intf.l3a_intf_id = net_port_p->l3_intf_id;
    rc = opennsl_l3_intf_get(unit, &l3_intf);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_l3_intf_get rc:%d unit:%d l3_intf_id:0x%x\n",
                 __FUNCTION__, __LINE__, rc, unit, net_port_p->l3_intf_id);
        return rc;
    }
    for (i = 0; i < ETH_ALEN; i++) {
        net_port_p->local_mac[i] = l3_intf.l3a_mac_addr[i];
    }
    net_port_p->vrf = l3_intf.l3a_vrf;

    VLOG_DBG("[%s, %d], exit rc:%d unit:%d vxlan_port_id:0x%x vlan:%d port:%d vrf:%d vnid:%d vpn_id:0x%x local_mac:%02x%02x%02x%02x%02x%02x next_hop_mac:%02x%02x%02x%02x%02x%02x\n",
             __FUNCTION__, __LINE__, rc, unit,
             net_port_p->vxlan_port_id, net_port_p->vlan,
             net_port_p->port, net_port_p->vrf, net_port_p->vnid,
             logical_sw_element_p->vpn_id,
             net_port_p->local_mac[0], net_port_p->local_mac[1],
             net_port_p->local_mac[2], net_port_p->local_mac[3],
             net_port_p->local_mac[4], net_port_p->local_mac[5],
             net_port_p->next_hop_mac[0], net_port_p->next_hop_mac[1],
             net_port_p->next_hop_mac[2], net_port_p->next_hop_mac[3],
             net_port_p->next_hop_mac[4], net_port_p->next_hop_mac[5]
             );

    return BCMSDK_E_NONE;
}


/*
 * Function: vxlan_bind_port
 *      Bind vxlan port information
 */
static
int
vxlan_bind_port(int unit, bcmsdk_vxlan_port_t *port_p)
{
    int rc;

    if (port_p == NULL) {
        VLOG_ERR("Error [%s, %d], port_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    switch (port_p->port_type) {
    case BCMSDK_VXLAN_PORT_TYPE_ACCESS:
        rc = vxlan_bind_access_port(unit, port_p);
        break;
    case BCMSDK_VXLAN_PORT_TYPE_NETWORK:
        rc = vxlan_bind_network_port(unit, port_p);
        break;
    default:
        rc = BCMSDK_E_PARAM;
        break;
    }

    return rc;
}


/*
 * Function: vxlan_unbind_port
 *      Unbind vxlan port information
 */
static
int
vxlan_unbind_port(int unit, bcmsdk_vxlan_port_t *port_p)
{
    int rc;

    if (port_p == NULL) {
        VLOG_ERR("Error [%s, %d], port_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    switch (port_p->port_type) {
    case BCMSDK_VXLAN_PORT_TYPE_ACCESS:
        rc = vxlan_unbind_access_port(unit, port_p);
        break;
    case BCMSDK_VXLAN_PORT_TYPE_NETWORK:
        rc = vxlan_unbind_network_port(unit, port_p);
        break;
    default:
        rc = BCMSDK_E_PARAM;
        break;
    }

    return rc;
}


/*
 * Function: vxlan_get_port
 *      Get port information
 */
static
int
vxlan_get_port(int unit, bcmsdk_vxlan_port_t *port_p)
{
    int rc;

    if (port_p == NULL) {
        VLOG_ERR("Error [%s, %d], port_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    switch (port_p->port_type) {
    case BCMSDK_VXLAN_PORT_TYPE_ACCESS:
        rc = vxlan_get_access_port(unit, port_p);
        break;
    case BCMSDK_VXLAN_PORT_TYPE_NETWORK:
        rc = vxlan_get_network_port(unit, port_p);
        break;
    default:
        rc = BCMSDK_E_PARAM;
        break;
    }

    return rc;
}



/*
 * Function: vxlan_update_port
 *      Update port information
 */
static
int
vxlan_update_port(int unit, bcmsdk_vxlan_port_t *port_p)
{
    int rc;

    if (port_p == NULL) {
        VLOG_ERR("Error [%s, %d], port_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    switch (port_p->port_type) {
    case BCMSDK_VXLAN_PORT_TYPE_ACCESS:
    case BCMSDK_VXLAN_PORT_TYPE_NETWORK:
        /* Hardware not support */
    default:
        rc = BCMSDK_E_PARAM;
        break;
    }

    return rc;
}


/*
 * Function: vxlan_create_multicast
 *      Create Vxlan multicast group
 *      Note: Temporary put multicast implementation here,
 *            Should use multicast APIs from other teams when it is done.
 *
 * [In] unit
 *      HW unit
 *
 * [Out] multicast_p
 *       multicast_p->group_id
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_create_multicast(int unit, bcmsdk_vxlan_multicast_t *multicast_p)
{
    int rc;

    if (multicast_p == NULL) {
        VLOG_ERR("Error [%s, %d], multicast_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    rc = opennsl_multicast_create(unit,
                                  OPENNSL_MULTICAST_TYPE_VXLAN,
                                  &(multicast_p->group_id));
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_multicast_create rc:%d unit:%d\n",
                 __FUNCTION__, __LINE__, rc, unit);
        return rc;
    }

    return rc;
}


/*
 * Function: vxlan_destroy_multicast
 *      Destroy Vxlan multicast group
 *      Note: Temporary put multicast implementation here,
 *            Should use multicast APIs from other teams when it is done.
 *
 * [In] unit
 *      HW unit
 *
 * [In] multicast_p
 *      multicast_p->group_id
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_destroy_multicast(int unit, bcmsdk_vxlan_multicast_t *multicast_p)
{
    int rc;

    if (multicast_p == NULL) {
        VLOG_ERR("Error [%s, %d], multicast_p is NULL unit:%d\n",
                 __FUNCTION__, __LINE__, unit);
        return BCMSDK_E_PARAM;
    }

    rc = opennsl_multicast_destroy(unit,
                                   multicast_p->group_id);
    if (rc) {
        VLOG_ERR("Error [%s, %d], opennsl_multicast_destroy rc:%d unit:%d\n",
                 __FUNCTION__, __LINE__, rc, unit);
        return rc;
    }

    return rc;
}


/*
 * Function: vxlan_hmap_cleanup
 *      Cleanup Vxlan hmap
 *
 * [In] unit
 *      HW unit
 *
 * [In] multicast_p
 *      multicast_p->group_id
 *
 * [Out] return
 *       See BCMSDK_E_XXX
 */
static
int
vxlan_hmap_cleanup(int unit)
{
    vxlan_logical_sw_element_t *logical_sw_element_p,
        *logical_sw_element_next_p;
    vxlan_egr_obj_element_t *egr_obj_element_p,
        *egr_obj_element_next_p;

    HMAP_FOR_EACH_SAFE(logical_sw_element_p, logical_sw_element_next_p,
                       node, &(vxlan_global.logical_sw_hmap)) {
        hmap_remove(&vxlan_global.logical_sw_hmap,
                    &logical_sw_element_p->node);
        free(logical_sw_element_p);
    }

    hmap_destroy(&vxlan_global.logical_sw_hmap);

    HMAP_FOR_EACH_SAFE(egr_obj_element_p, egr_obj_element_next_p,
                       node, &(vxlan_global.egr_obj_hmap)) {
        hmap_remove(&vxlan_global.egr_obj_hmap,
                    &egr_obj_element_p->node);
        free(egr_obj_element_p);
    }

    hmap_destroy(&vxlan_global.egr_obj_hmap);

    return BCMSDK_E_NONE;
}

/**************************************************************************/
/*                              INIT/Cleanup                              */
/**************************************************************************/


int
ops_vxlan_init(int unit)
{
    int rc;

    rc = bcmsdk_vxlan_endis_global(unit, BCMSDK_VXLAN_ENABLE);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_endis_global rc:%d unit:%d\n",
                 __FUNCTION__, __LINE__, rc, unit);
        return rc;
    }

    hmap_init(&vxlan_global.logical_sw_hmap);
    hmap_init(&vxlan_global.egr_obj_hmap);

    return BCMSDK_E_NONE;
} // ops_vxlan_init



int
ops_vxlan_cleanup(int unit)
{
    int rc;

    rc = vxlan_hmap_cleanup(unit);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_hmap_cleanup rc:%d unit:%d\n",
                 __FUNCTION__, __LINE__, rc, unit);
        return rc;
    }

    rc = bcmsdk_vxlan_endis_global(unit, BCMSDK_VXLAN_DISABLE);
    if (rc) {
        VLOG_ERR("Error [%s, %d], vxlan_endis_global rc:%d unit:%d\n",
                 __FUNCTION__, __LINE__, rc, unit);
        return rc;
    }

    return BCMSDK_E_NONE;
} // ops_vxlan_cleanup

/**************************************************************************/
/*                              DEBUG                                     */
/**************************************************************************/
