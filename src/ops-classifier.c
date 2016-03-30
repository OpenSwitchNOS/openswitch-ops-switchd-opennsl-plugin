/*
 * Copyright (C) 2015, 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <util.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <openvswitch/vlog.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/switch.h>
#include <opennsl/vlan.h>
#include <opennsl/l3.h>
#include <opennsl/l2.h>
#include <ofproto/ofproto.h>
#include <ovs/list.h>
#include <opennsl/port.h>
#include <opennsl/field.h>

#include <ofproto/ofproto-provider.h>
#include <openvswitch/types.h>
#include <openvswitch/vlog.h>
#include <uuid.h>

#include "platform-defines.h"
/* Broadcom provider */
#include "ofproto-bcm-provider.h"
/* Private header */
#include "ops-classifier.h"


/** Define a module for VLOG_ functionality */
VLOG_DEFINE_THIS_MODULE(ops_classifier);
struct hmap classifier_map;

opennsl_field_group_t ip_group;

/*
 * Init function (IFP initialization)
 */
int
ops_classifier_init(int unit)
{
    int rc;
    opennsl_field_qset_t qset;

     /* Initialize QSET */
    OPENNSL_FIELD_QSET_INIT(qset);

    /* Select IFP and create group*/

    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyStageIngress);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyInPorts);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifySrcIp);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyDstIp);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyIpProtocol);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyL4SrcPort);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyL4DstPort);

    rc = opennsl_field_group_create(unit, qset, OPS_GROUP_PRI_IPv4, &ip_group);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to create group: unit=%d, group= %d,  rc=%s",
                 unit, ip_group, opennsl_errmsg(rc));
         return rc;
    } else {
        VLOG_DBG("Created group %d successfully", ip_group);
    }

    /* Initialize the classifier hash map */
    hmap_init(&classifier_map);

    return rc;
}

/*
 * Classifier lookup in hash table
 */
struct ops_classifier*
ops_cls_lookup(const struct uuid *cls_id)
{
    struct ops_classifier *cls = NULL;

    uint32_t id = uuid_hash(cls_id);

    HMAP_FOR_EACH_WITH_HASH(cls, node, id, &classifier_map) {
        if (uuid_equals(&cls->id, cls_id)) {
            return cls;
        }
    }
    return NULL;
}

/*
 * Copy classifier entries and store in hash
 */
void
ops_cls_populate_entries(struct ops_classifier  *cls,
                         struct ovs_list        *list,
                         struct ops_cls_list    *clist)
{
    for (int i = 0; i < clist->num_entries; i++) {
        struct ops_classifier_entry *entry =
            xzalloc(sizeof(struct ops_classifier_entry));
        struct ops_cls_list_entry *cls_entry = &clist->entries[i];

        entry->pacl = cls;
        memcpy(&entry->entry_fields, &cls_entry->entry_fields,
               sizeof(struct ops_cls_list_entry_match_fields));
        memcpy(&entry->entry_actions, &cls_entry->entry_actions,
                sizeof(struct ops_cls_list_entry_actions));

        list_push_back(list, &entry->node);
    }
}

/*
 * Add classifier in hash (key uuid)
 */
static struct ops_classifier*
ops_cls_add(struct ops_cls_list  *clist)
{
    struct ops_classifier *cls;

    if (!clist) {
        return NULL;
    }

    cls = xzalloc(sizeof(struct ops_classifier));

    cls->id = clist->list_id;
    cls->name = xstrdup(clist->list_name);
    cls->type = clist->list_type;
    cls->in_asic = false;
    OPENNSL_PBMP_CLEAR(cls->pbmp);
    /* Init classifer list entry list */
    list_init(&cls->entry_list);
    list_init(&cls->stats_list);
    list_init(&cls->range_list);

    list_init(&cls->entry_update_list);
    list_init(&cls->stats_update_list);
    list_init(&cls->range_update_list);

    if (clist->num_entries > 0) {
        VLOG_DBG("%s has %d rule entries", cls->name, clist->num_entries);
        ops_cls_populate_entries(cls, &cls->entry_list, clist);
    }

    hmap_insert(&classifier_map, &cls->node, uuid_hash(&clist->list_id));

    VLOG_DBG("Added classifer %s in hashmap", cls->name);
    return cls;
}

/*
 * Delete classifier entries
 */
static void
ops_cls_delete_entries(struct ovs_list *list)
{
    struct ops_classifier_entry *entry, *next_entry;

    LIST_FOR_EACH_SAFE (entry, next_entry,  node, list) {
        list_remove(&entry->node);
        free(entry);
    }

}

/*
 * Delete stats entries
 */
static void
ops_cls_delete_stats_entries(struct ovs_list *list)
{
    struct ops_stats_entry *sentry = NULL, *next_sentry;

    LIST_FOR_EACH_SAFE (sentry, next_sentry,  node, list) {
        list_remove(&sentry->node);
        free(sentry);
    }

}

/*
 * Delete range entries
 */
static void
ops_cls_delete_range_entries(struct ovs_list *list)
{
    struct ops_range_entry *rentry = NULL, *next_rentry;

    LIST_FOR_EACH_SAFE (rentry, next_rentry,  node, list) {
        list_remove(&rentry->node);
        free(rentry);
    }
}

/*
 * Delete original entires of classifier
 */
static void
ops_cls_delete_orig_entries(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    ops_cls_delete_entries(&cls->entry_list);
    ops_cls_delete_stats_entries(&cls->stats_list);
    ops_cls_delete_range_entries(&cls->range_list);
}

/*
 * Delete updated entries of classifier
 */

static void
ops_cls_delete_updated_entries(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    ops_cls_delete_entries(&cls->entry_update_list);
    ops_cls_delete_stats_entries(&cls->stats_update_list);
    ops_cls_delete_range_entries(&cls->range_update_list);
}


/*
 * Delete classifier from hash table
 */
static void
ops_cls_delete(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    ops_cls_delete_orig_entries(cls);
    ops_cls_delete_updated_entries(cls);

    hmap_remove(&classifier_map, &cls->node);
    VLOG_DBG("Removed ACL %s in hashmap", cls->name);
    free(cls->name);
    free(cls);
}

/*
 * Assign updated entries of classifer to original entires
 */

static void
ops_cls_update_entries(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    /* move the installed update entries to original list */
    list_move(&cls->entry_list, &cls->entry_update_list);
    list_move(&cls->stats_list, &cls->stats_update_list);
    list_move(&cls->range_list, &cls->range_update_list);

    /* reinitalize update list for next update */
    list_init(&cls->entry_update_list);
    list_init(&cls->stats_update_list);
    list_init(&cls->range_update_list);
}

/*
 * Get port(s) from bundle and add to bit map
 */
static int
ops_cls_get_port_bitmap(struct ofproto *ofproto_,
                        void           *aux,
                        int            *hw_unit,
                        opennsl_pbmp_t *pbmp)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);

    struct ofbundle *bundle = bundle_lookup(ofproto, aux);
    if (bundle == NULL) {
        VLOG_ERR("Failed to get port bundle");
        return OPS_FAIL;
    }

    struct bcmsdk_provider_ofport_node *port, *next_port;
    LIST_FOR_EACH_SAFE (port, next_port, bundle_node, &bundle->ports) {
        OPENNSL_PBMP_PORT_ADD(*pbmp, port->up.ofp_port);
    }

    if (OPENNSL_PBMP_IS_NULL(*pbmp)) {
        VLOG_ERR("Port bundle has no ports");
        return OPS_FAIL;
    }

    *hw_unit = bundle->hw_unit;
    return OPS_OK;
}

/*
 * Set rule action
 */
int
ops_cls_set_action(int                          unit,
                   opennsl_field_entry_t        entry,
                   struct ops_classifier       *cls,
                   struct ops_classifier_entry *cls_entry,
                   int                         *stat_index,
                   bool                        *isStatEnabled)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_field_stat_t stats_type[2] = {opennslFieldStatPackets, opennslFieldStatBytes} ;
    int stat_id;

    VLOG_DBG("Classifier list entry action flag: 0x%x", cls_entry->act_flags);

    if (cls_entry->act_flags & OPS_CLS_ACTION_DENY) {
        rc = opennsl_field_action_add(unit, entry, opennslFieldActionDrop,
                                      0, 0);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set drop action: rc=%s", opennsl_errmsg(rc));
            return rc;
        }
    }

    if (cls_entry->act_flags & OPS_CLS_ACTION_COUNT) {
        rc = opennsl_field_stat_create(unit, ip_group, 2, stats_type, &stat_id);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to create stats for ACL %s rc=%s",
                     cls->name, opennsl_errmsg(rc));
            return rc;
        }

        rc = opennsl_field_entry_stat_attach(unit, entry, stat_id);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to attach stats %d to entry %d in ACL %s rc=%s",
                     stat_id, entry, cls->name, opennsl_errmsg(rc));
            rc = opennsl_field_stat_destroy(unit, stat_id);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to destroy stats %d for ACL %s rc=%s",
                          stat_id, cls->name, opennsl_errmsg(rc));
            }
            return rc;
        }

        VLOG_DBG("Attached stats %d to entry %d in ACL %s", stat_id, entry, cls->name);

        *stat_index = stat_id;
        *isStatEnabled = TRUE;
    }

    if (cls_entry->act_flags & OPS_CLS_ACTION_LOG) {
        VLOG_DBG("Log action not supported");
    }

    return rc;
}

/*
 * Display ports
 */
char*
ops_cls_display_port_bit_map(opennsl_pbmp_t *pbmp,
                             char           *buffer,
                             int             bufsize)
{
    int offset = 0, count;
    opennsl_port_t port;

    memset(buffer, 0 ,bufsize);
    OPENNSL_PBMP_ITER(*pbmp, port) {
        count = snprintf(buffer + offset, bufsize - offset, "%d ", port);
        if (count >= bufsize - offset) {
            buffer[bufsize-1] = '\0';
            break;
        }
        offset += count;
    }
    return buffer;
}

/*
 * Set PI error code
 */
void
ops_cls_set_pd_status(int                        rc,
                      int                        rule_index,
                      struct ops_cls_pd_status  *pd_status)
{

    VLOG_DBG("ops classifier error: %d ", rc);

    switch (rc) {
    case OPS_FAIL:
    case OPENNSL_E_INTERNAL:
    case OPENNSL_E_MEMORY:
    case OPENNSL_E_PARAM:
    case OPENNSL_E_FULL:
    case OPENNSL_E_FAIL:
    case OPENNSL_E_RESOURCE:
        pd_status->status_code = OPS_CLS_PD_STATUS_HW_ENTRY_ALLOCATION_ERROR;
        pd_status->entry_id = rule_index;
        break;
    default:
        VLOG_DBG("Unsupported (%d) error type", rc);
        break;
    }
}

/*
 * Set PI (list) error code
 */
void
ops_cls_set_pd_list_status(int                             rc,
                           int                             rule_index,
                           struct ops_cls_pd_list_status  *status)
{

    VLOG_DBG("ops list error: %d ", rc);

    switch (rc) {
    case OPS_FAIL:
    case OPENNSL_E_INTERNAL:
    case OPENNSL_E_MEMORY:
    case OPENNSL_E_PARAM:
    case OPENNSL_E_FULL:
    case OPENNSL_E_FAIL:
    case OPENNSL_E_RESOURCE:
        status->status_code = OPS_CLS_PD_STATUS_HW_ENTRY_ALLOCATION_ERROR;
        status->entry_id = rule_index;
        break;
    default:
        VLOG_DBG("Unsupported (%d) list error type", rc);
        break;
    }

}

/*
 * Get the port range from classifier
 */
void
ops_cls_port_range_get(struct ops_cls_list_entry_match_fields *field,
                       uint16_t                               *port_min,
                       uint16_t                               *port_max)
{
    if(field->L4_src_port_op == OPS_CLS_L4_PORT_OP_RANGE) {
        *port_min = field->L4_src_port_min;
        *port_max = field->L4_src_port_max;
    } else if (field->L4_src_port_op == OPS_CLS_L4_PORT_OP_RANGE) {
        *port_min = 0;
        *port_max = field->L4_src_port_max;
    } else {
        *port_min = field->L4_src_port_min;
        *port_max = 65535;
    }
}

/*
 * Add rule in FP
 */
int
ops_cls_install_rule_in_asic(int                           unit,
                             struct ops_classifier_entry  *cls_entry,
                             opennsl_pbmp_t               *pbmp,
                             int                          *entry_id,
                             int                           index,
                             bool                          isUpdate)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_field_entry_t entry;
    opennsl_field_range_t range;
    opennsl_pbmp_t pbmp_mask;
    uint16_t port_mask = 0xFFFF;
    uint8_t protocol_mask = 0XFF;
    uint16_t min_port, max_port;
    int stat_index;
    bool statEnabled = FALSE;
    bool rangeEnabled = FALSE;
    struct ops_stats_entry *sentry;
    struct ops_range_entry *rentry;
    struct ovs_list *list;


    struct ops_classifier *cls = cls_entry->pacl;
    struct ops_cls_list_entry_match_fields *match = &cls_entry->entry_fields;

    rc = opennsl_field_entry_create(unit, ip_group, &entry);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to create entry for classifier %s rc=%s", cls->name,
                 opennsl_errmsg(rc));
        return rc;
    }

    VLOG_DBG("Classifier %s entry id %d", cls->name, entry);

    /* Ingress port(s) */
    if (OPENNSL_PBMP_NOT_NULL(*pbmp)) {
        char pbmp_string[200];

        OPENNSL_PBMP_CLEAR(pbmp_mask);
        OPENNSL_PBMP_NEGATE(pbmp_mask, pbmp_mask);

        VLOG_DBG("Ingress port(s): [ %s ]",
                 ops_cls_display_port_bit_map(pbmp, pbmp_string, 200));
        rc = opennsl_field_qualify_InPorts(unit, entry, *pbmp, pbmp_mask);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set ingress port(s) [%s]: rc=%s",
                     pbmp_string, opennsl_errmsg(rc));
            goto cleanup;
        }
        OPENNSL_PBMP_ASSIGN(cls->pbmp, *pbmp);
    }

    if (cls_entry->match_flags & OPS_CLS_SRC_IPADDR_VALID) {
        VLOG_DBG("Src ipv4 addr 0x%x and mask 0x%x", htonl(cls_entry->src_ip),
                 htonl(cls_entry->src_mask));

        rc = opennsl_field_qualify_SrcIp(unit, entry, htonl(cls_entry->src_ip),
                                         htonl(cls_entry->src_mask));
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Add entry src ipv4 0x%x and mask 0x%x failed: rc=%s",
                     htonl(cls_entry->src_ip), htonl(cls_entry->src_mask),
                     opennsl_errmsg(rc));
            goto cleanup;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_DEST_IPADDR_VALID) {
        VLOG_DBG("Dst ipv4 addr 0x%x and mask 0x%x",
                 htonl(cls_entry->dst_ip), htonl(cls_entry->dst_mask));

        rc = opennsl_field_qualify_DstIp(unit, entry, htonl(cls_entry->dst_ip),
                                         htonl(cls_entry->dst_mask));
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Add entry dst ipv4 0x%x and mask 0x%x failed: rc=%s",
                     htonl(cls_entry->dst_ip), htonl(cls_entry->dst_mask),
                     opennsl_errmsg(rc));
            goto cleanup;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_PROTOCOL_VALID) {
        VLOG_DBG("IP protocol: 0x%x", match->protocol);

        rc = opennsl_field_qualify_IpProtocol(unit,
                                              entry,
                                              match->protocol,
                                              protocol_mask);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to add entry ip protocol 0x%x and mask 0x%x: "
                         "rc=%s", match->protocol, protocol_mask,
                         opennsl_errmsg(rc));
            goto cleanup;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_L4_SRC_PORT_VALID) {
        VLOG_DBG("L4 src port min: 0x%x max: 0x%x ops %d", match->L4_src_port_min,
                 match->L4_src_port_max, match->L4_src_port_op);

        switch (match->L4_src_port_op) {
        case OPS_CLS_L4_PORT_OP_EQ:
            rc = opennsl_field_qualify_L4SrcPort(unit, entry,
                                                 match->L4_src_port_min,
                                                 port_mask);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed add entry L4 src port 0x%x and mask 0x%x: "
                         "rc=%s", match->L4_src_port_min, port_mask,
                         opennsl_errmsg(rc));
                goto cleanup;
            }
            break;

        case OPS_CLS_L4_PORT_OP_RANGE:
        case OPS_CLS_L4_PORT_OP_LT:
        case OPS_CLS_L4_PORT_OP_GT:
            ops_cls_port_range_get(match, &min_port, &max_port);

            rc = opennsl_field_range_create(unit, &range, OPENNSL_FIELD_RANGE_SRCPORT,
                                            min_port, max_port);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed create L4 src port range min %d, max %d rc=%s",
                         min_port, max_port,
                         opennsl_errmsg(rc));
                goto cleanup;
            }

            rc = opennsl_field_qualify_RangeCheck(unit, entry, range, 0);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed add L4 src port range min %d, max %d rc=%s",
                         min_port, max_port, opennsl_errmsg(rc));
                rc = opennsl_field_range_destroy(unit, range);
                if (OPENNSL_FAILURE(rc)) {
                    VLOG_ERR("Failed to destroy L4 src port range %d rc= %s", range,
                             opennsl_errmsg(rc));
                }
                goto cleanup;
            }
            rangeEnabled = TRUE;
            break;

        case OPS_CLS_L4_PORT_OP_NONE:
        case OPS_CLS_L4_PORT_OP_NEQ:
        default:
            VLOG_DBG("L4 port operation %d not supported",
                      match->L4_src_port_op);
            break;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_L4_DEST_PORT_VALID) {
        VLOG_DBG("L4 dst port min: 0x%x max: 0x%x ops %d", match->L4_dst_port_min,
                 match->L4_dst_port_max, match->L4_dst_port_op);

        switch (match->L4_dst_port_op) {
        case OPS_CLS_L4_PORT_OP_EQ:
            rc = opennsl_field_qualify_L4DstPort(unit, entry,
                                                 match->L4_dst_port_min,
                                                 port_mask);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed add entry L4 dst port 0x%x and mask 0x%x: "
                         "rc=%s", match->L4_dst_port_min, port_mask,
                         opennsl_errmsg(rc));
                goto cleanup;
            }
            break;

        case OPS_CLS_L4_PORT_OP_RANGE:
        case OPS_CLS_L4_PORT_OP_LT:
        case OPS_CLS_L4_PORT_OP_GT:
            ops_cls_port_range_get(match, &min_port, &max_port);

            rc = opennsl_field_range_create(unit, &range, OPENNSL_FIELD_RANGE_DSTPORT,
                                            min_port, max_port);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed create L4 dst port range min %d, max %d rc=%s",
                         min_port, max_port,
                         opennsl_errmsg(rc));
                goto cleanup;
            }

            rc = opennsl_field_qualify_RangeCheck(unit, entry, range, 0);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed add L4 dst port range min %d, max %d rc=%s",
                         min_port, max_port, opennsl_errmsg(rc));
                rc = opennsl_field_range_destroy(unit, range);
                if (OPENNSL_FAILURE(rc)) {
                    VLOG_ERR("Failed to destroy L4 dst port range %d rc= %s", range,
                             opennsl_errmsg(rc));
                }
                goto cleanup;
            }
            rangeEnabled = TRUE;
            break;

        case OPS_CLS_L4_PORT_OP_NONE:
        case OPS_CLS_L4_PORT_OP_NEQ:
        default:
            VLOG_DBG("L4 port operation %d not supported",
                      match->L4_dst_port_op);
            break;
        }
    }

    /* Set the actions */
    rc = ops_cls_set_action(unit, entry, cls, cls_entry, &stat_index,
                            &statEnabled);
    if(OPENNSL_FAILURE(rc)) {
        goto cleanup;
    }

    /* Install the entry */
    rc = opennsl_field_entry_install(unit, entry);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to install entry rc=%s", opennsl_errmsg(rc));
        goto cleanup;
    }

    VLOG_DBG("Classifier %s rule id %d successfully installed",
             cls->name, entry);

    /* store stats entry */
    if (statEnabled) {
        /* add it in range list of acl entry */
        sentry = xzalloc(sizeof(struct ops_stats_entry));
        sentry->index = stat_index;
        sentry->rule_index = index;
        list = isUpdate ? &cls->stats_update_list : &cls->stats_list;
        list_push_back(list, &sentry->node);
    }

    /* store range entry */
    if(rangeEnabled) {
        rentry = xzalloc(sizeof(struct ops_range_entry));
        rentry->index = range;
        list = isUpdate ? &cls->range_update_list : &cls->range_list;
        list_push_back(list, &rentry->node);
    }

    /* Save the entry id in entry field */
    *entry_id = entry;
    cls_entry->in_asic = true;
    return rc;

cleanup:

    if (rangeEnabled) {
        rc = opennsl_field_range_destroy(unit, range);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy L4 src port range %d rc= %s", range,
                     opennsl_errmsg(rc));
        }
    }

    if (statEnabled) {
        rc = opennsl_field_stat_destroy(unit, stat_index);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy stats %d for ACL %s rc=%s",
                      stat_index, cls->name, opennsl_errmsg(rc));
        }
    }

    /* distroy entry and return rc */
    opennsl_field_entry_destroy(unit, entry);
    return rc;

}

/*
 * Add classifier rules in FP
 */
int ops_cls_install_classifier_in_asic(int                    hw_unit,
                                       struct ops_classifier *cls,
                                       struct ovs_list       *list,
                                       opennsl_pbmp_t        *port_bmp,
                                       int                   *rule_index,
                                       bool                   isUpdate)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_classifier_entry *cls_entry = NULL, *next_cls_entry;
    int entry;

    /* Install in ASIC */
    LIST_FOR_EACH_SAFE(cls_entry, next_cls_entry, node, list) {
        rc = ops_cls_install_rule_in_asic(hw_unit, cls_entry, port_bmp,
                                          &entry, *rule_index, isUpdate);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to install classifier %s rule(s) ", cls->name);
            return rc;
        }
        /* save the entry id */
        cls_entry->index = entry;
        (*rule_index)++;
    }
    VLOG_DBG("Classifier %s successfully installed in asic", cls->name);
    return rc;
}

/*
 * Update rule(s) port bitmap in FP
 */
int ops_cls_pbmp_update(int                     hw_unit,
                        struct ops_classifier  *cls,
                        opennsl_pbmp_t         *port_bmp,
                        int                    *rule_index)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_classifier_entry *cls_entry = NULL, *next_cls_entry;
    opennsl_pbmp_t pbmp_mask;
    char pbmp_string[200];
    int entry;

    OPENNSL_PBMP_CLEAR(pbmp_mask);
    OPENNSL_PBMP_NEGATE(pbmp_mask, pbmp_mask);

    VLOG_DBG("Updated port bit map: [ %s ]",
             ops_cls_display_port_bit_map(port_bmp, pbmp_string, 200));

    LIST_FOR_EACH_SAFE(cls_entry, next_cls_entry, node, &cls->entry_list) {
        entry = cls_entry->index;
        rc = opennsl_field_qualify_InPorts(hw_unit, entry, *port_bmp,
                                           pbmp_mask);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to update classifier %s rule port bitmask rc:%s",
                     cls->name, opennsl_errmsg(rc));
            return rc;
        }
        (*rule_index)++;
    }
    return rc;
}

/*
 * Delete rules in asic
 */
int
ops_cls_delete_rules_in_asic(int                    hw_unit,
                             struct ops_classifier *cls,
                             int                   *rule_index,
                             bool                   isUpdate)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_classifier_entry *cls_entry = NULL, *next_cls_entry;
    struct ops_range_entry *rentry = NULL, *next_rentry;
    struct ops_stats_entry *sentry = NULL, *next_sentry;
    int entry;

    struct ovs_list *entry_list, *range_list, *stats_list;

    if (!cls) {
        return OPS_FAIL;
    }

    entry_list = isUpdate ? &cls->entry_update_list : &cls->entry_list;
    range_list = isUpdate ? &cls->range_update_list : &cls->range_list;
    stats_list = isUpdate ?  &cls->stats_update_list : &cls->stats_list;

    LIST_FOR_EACH_SAFE(cls_entry, next_cls_entry, node, entry_list) {
        if (!cls_entry->in_asic) {
            (*rule_index)++;
            continue;
        }

        entry = cls_entry->index;
        rc =  opennsl_field_entry_destroy(hw_unit, entry);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy classifier %s rule %d rc:%s",
                     cls->name, entry, opennsl_errmsg(rc));
        }
        cls_entry->in_asic = false;
        (*rule_index)++;
    }

    LIST_FOR_EACH_SAFE(rentry, next_rentry, node, range_list) {
        entry = rentry->index;
        rc = opennsl_field_range_destroy(hw_unit, entry);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy classifier %s range  %d rc:%s",
                     cls->name, entry, opennsl_errmsg(rc));
        }
    }

    LIST_FOR_EACH_SAFE(sentry, next_sentry, node, stats_list) {
        entry = sentry->index;
        rc = opennsl_field_stat_destroy(hw_unit, entry);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy classifier %s stats  %d rc:%s",
                     cls->name, entry, opennsl_errmsg(rc));
        }
    }

    return rc;
}


/*
 * Update port bitmap of classifier
 */
int ops_cls_update_classifier_in_asic(int                    hw_unit,
                                      struct ops_classifier *cls,
                                      opennsl_pbmp_t        *port_bmp,
                                      enum ops_update_pbmp   action,
                                      int                   *rule_index)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_pbmp_t pbmp;

    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_OR(pbmp, cls->pbmp);
    switch (action) {
    case OPS_PBMP_ADD:
        OPENNSL_PBMP_OR(pbmp, *port_bmp);
        rc = ops_cls_pbmp_update(hw_unit, cls, &pbmp, rule_index);
        if (OPENNSL_SUCCESS(rc)) {
            OPENNSL_PBMP_ASSIGN(cls->pbmp, pbmp);
        }
        break;

    case OPS_PBMP_DEL:
        OPENNSL_PBMP_XOR(pbmp, *port_bmp);
        if (OPENNSL_PBMP_IS_NULL(pbmp)) {
            VLOG_DBG("Port bit is NULL, remove classifer %s in asic",
                     cls->name);
            rc = ops_cls_delete_rules_in_asic(hw_unit, cls, rule_index, FALSE);
            ops_cls_delete(cls);
        } else {
            rc = ops_cls_pbmp_update(hw_unit, cls, &pbmp, rule_index);
        }

        if (OPENNSL_SUCCESS(rc)) {
            OPENNSL_PBMP_ASSIGN(cls->pbmp, pbmp);
        }
        break;

    default:
        break;

    }

    return rc;
}

/*
 * Apply classifier to a port
 */
int
ops_cls_pd_apply(struct ops_cls_list            *list,
                 struct ofproto                 *ofproto,
                 void                           *aux,
                 struct ops_cls_interface_info  *interface_info OVS_UNUSED,
                 enum ops_cls_direction          direction,
                 struct ops_cls_pd_status       *pd_status)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int hw_unit;
    opennsl_pbmp_t port_bmp;
    struct ops_classifier *cls = NULL;
    char pbmp_string[200];
    int  rule_index = 0; /* rule index to PI on failure */

    OPENNSL_PBMP_CLEAR(port_bmp);
    cls = ops_cls_lookup(&list->list_id);
    if (!cls) {
        cls = ops_cls_add(list);
        if (!cls) {
            VLOG_ERR ("Failed to add classifier "UUID_FMT" (%s) in hashmap",
                       UUID_ARGS(&list->list_id), list->list_name);
            rc = OPS_FAIL;
            goto apply_fail;
        }
    } else {
        VLOG_DBG("Classifier "UUID_FMT" (%s) exist in hashmap",
                  UUID_ARGS(&list->list_id), list->list_name);
    }

    /* get the port bits_map */
    if (ops_cls_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_FAIL;
        goto apply_fail;
    }

    VLOG_DBG("Apply classifier %s on port(s) [ %s ]", cls->name,
              ops_cls_display_port_bit_map(&port_bmp, pbmp_string, 200));

    if (!cls->in_asic) {
        /* first binding of classifier*/
        rc = ops_cls_install_classifier_in_asic(hw_unit, cls, &cls->entry_list,
                                                &port_bmp, &rule_index, FALSE);
        if (OPENNSL_FAILURE(rc)) {
            int index = 0;
            ops_cls_delete_rules_in_asic(hw_unit, cls, &index, FALSE);
            ops_cls_delete(cls);
            goto apply_fail;
        }
        cls->in_asic = true;
    } else {
        /* already in asic update port bitmap */
        rc = ops_cls_update_classifier_in_asic(hw_unit, cls, &port_bmp,
                                               OPS_PBMP_ADD, &rule_index);
        if (OPENNSL_FAILURE(rc)) {
            goto apply_fail;
        }
    }

    return OPS_OK;

apply_fail:
    ops_cls_set_pd_status(rc, rule_index, pd_status);
    return OPS_FAIL;
}

/*
 * Remove classifier from port
 */
int
ops_cls_pd_remove(const struct uuid                *list_id,
                  const char                       *list_name OVS_UNUSED,
                  enum ops_cls_type                list_type OVS_UNUSED,
                  struct ofproto                   *ofproto,
                  void                             *aux,
                  struct ops_cls_interface_info    *interface_info OVS_UNUSED,
                  enum ops_cls_direction           direction,
                  struct ops_cls_pd_status         *pd_status)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int hw_unit;
    opennsl_pbmp_t port_bmp;
    struct ops_classifier *cls = NULL;
    char pbmp_string[200];
    int rule_index = 0; /* rule index to PI on failure */

    OPENNSL_PBMP_CLEAR(port_bmp);
    cls = ops_cls_lookup(list_id);
    if (!cls) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",  UUID_ARGS(list_id));
        rc = OPS_FAIL;
        goto remove_fail;
    }

    /* get the port bits_map */
    if (ops_cls_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_FAIL;
        goto remove_fail;
    }

    VLOG_DBG("Remove classifier %s on port(s) [ %s ]", cls->name,
              ops_cls_display_port_bit_map(&port_bmp, pbmp_string, 200));

    if (!cls->in_asic) {
        VLOG_ERR("Port remove failed, classifier %s not in asic", cls->name);
        rc = OPS_FAIL;
        goto remove_fail;
    } else {
        /* already in asic update port bitmap */
        rc = ops_cls_update_classifier_in_asic(hw_unit, cls, &port_bmp,
                                           OPS_PBMP_DEL, &rule_index);
        if(OPENNSL_FAILURE(rc)) {
            goto remove_fail;
        }
    }

    return OPS_OK;

remove_fail:
    ops_cls_set_pd_status(rc, rule_index, pd_status);
    return OPS_FAIL;
}

/*
 * Attach port to different classifier
 */
int
ops_cls_pd_replace(const struct uuid               *list_id_orig,
                   const char                      *list_name_orig OVS_UNUSED,
                   struct ops_cls_list             *list_new,
                   struct ofproto                  *ofproto,
                   void                            *aux,
                   struct ops_cls_interface_info   *interface_info OVS_UNUSED,
                   enum ops_cls_direction          direction,
                   struct ops_cls_pd_status        *pd_status)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int hw_unit;
    opennsl_pbmp_t port_bmp;
    struct ops_classifier *cls_orig = NULL, *cls_new = NULL;
    char pbmp_string[200];
    int rule_index = 0; /* rule index to PI on failure */

    cls_orig = ops_cls_lookup(list_id_orig);
    if (!cls_orig) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",
                 UUID_ARGS(list_id_orig));
        rc = OPS_FAIL;
        goto replace_fail;
    }

    cls_new = ops_cls_lookup(&list_new->list_id);
    if (!cls_new) {
        cls_new = ops_cls_add(list_new);
        if (!cls_new) {
            VLOG_ERR ("Failed to add classifier "UUID_FMT" (%s) in hashmap",
                       UUID_ARGS(&list_new->list_id), list_new->list_name);
            rc =  OPS_FAIL;
            goto replace_fail;
        }
    } else {
        VLOG_DBG("Replace classifier "UUID_FMT" (%s) exist in haspmap",
                  UUID_ARGS(&list_new->list_id), list_new->list_name);
    }

    OPENNSL_PBMP_CLEAR(port_bmp);
    /* get the port bits_map */
    if (ops_cls_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_FAIL;
        goto replace_fail;
    }

    VLOG_DBG("Replace classifier %s with %s on port(s) [ %s ]",
             cls_orig->name, cls_new->name,
             ops_cls_display_port_bit_map(&port_bmp, pbmp_string, 200));

    if (!cls_new->in_asic) {
        /* first binding of classifier*/
        rc = ops_cls_install_classifier_in_asic(hw_unit, cls_new,
                                            &cls_new->entry_list,
                                            &port_bmp, &rule_index,
                                            FALSE);
        if (OPENNSL_FAILURE(rc)) {
            int index = 0;
            ops_cls_delete_rules_in_asic(hw_unit, cls_new, &index, FALSE);
            goto replace_fail;
        }
        cls_new->in_asic = true;
    } else {
        /* already in asic update port bitmap */
        rc = ops_cls_update_classifier_in_asic(hw_unit, cls_new, &port_bmp,
                                           OPS_PBMP_ADD, &rule_index);
        if (OPENNSL_FAILURE(rc)) {
            goto replace_fail;
        }
    }

    if (cls_orig->in_asic) {
        /* already in asic update port bitmap */
        rule_index = 0;
        rc = ops_cls_update_classifier_in_asic(hw_unit, cls_orig, &port_bmp,
                                           OPS_PBMP_DEL, &rule_index);
        if(OPENNSL_FAILURE(rc)) {
            goto replace_fail;
        }
    }

    return OPS_OK;

replace_fail:
    ops_cls_set_pd_status(rc, rule_index, pd_status);
    return OPS_FAIL;
}

/*
 * Create a new ACL.
 */
int
ops_cls_pd_list_update(struct ops_cls_list                 *list,
                       struct ops_cls_pd_list_status       *status)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_classifier *cls = NULL;
    int hw_unit =  0;
    opennsl_pbmp_t port_bmp;
    int rule_index = 0; /* rule index to PI on failure */

    cls = ops_cls_lookup(&list->list_id);
    if (!cls) {
        cls = ops_cls_add(list);
        if (!cls) {
            VLOG_ERR ("Failed to add classifier %s in hashmap", list->list_name);
            rc = OPS_FAIL;
            goto update_fail;
        }
    } else {
        VLOG_DBG("Classifier %s exist in haspmap", list->list_name);
    }

    if (!cls->in_asic) {
        ops_cls_delete_entries(&cls->entry_list);

        if (list->num_entries > 0) {
            ops_cls_populate_entries(cls, &cls->entry_list, list);
        }
    } else {  /* already in asic */
        if (list->num_entries > 0) {
            /*
             * Install updated ACL in FP, if it fails, remove
             * the updated ACL and leave original ACL. On successful
             * update remove the original ACL entries.
             */

            ops_cls_populate_entries(cls, &cls->entry_update_list, list);

            OPENNSL_PBMP_CLEAR(port_bmp);
            OPENNSL_PBMP_ASSIGN(port_bmp, cls->pbmp);

            rc = ops_cls_install_classifier_in_asic(hw_unit, cls,
                                                    &cls->entry_update_list,
                                                    &port_bmp, &rule_index, TRUE);
            int index = 0;
            if(OPENNSL_FAILURE(rc)) {
                ops_cls_delete_rules_in_asic(hw_unit, cls, &index, TRUE);
                ops_cls_delete_updated_entries(cls);
                goto update_fail;
            } else {
                ops_cls_delete_rules_in_asic(hw_unit, cls, &index, FALSE);
                ops_cls_delete_orig_entries(cls);
                ops_cls_update_entries(cls);
            }

        }
    }
    return OPS_OK;

update_fail:
    ops_cls_set_pd_list_status(rc, rule_index, status);
    return OPS_FAIL;
}

int
ops_cls_pd_statistics_get(const struct uuid              *list_id,
                          const char                     *list_name,
                          enum ops_cls_type              list_type,
                          struct ofproto                 *ofproto,
                          void                           *aux,
                          struct ops_cls_interface_info  *interface_info,
                          enum ops_cls_direction         direction,
                          struct ops_cls_statistics      *statistics,
                          int                            num_entries,
                          struct ops_cls_pd_list_status  *status)
{
    struct ops_classifier *cls;
    int hw_unit, rc, rule_index = 0;
    opennsl_pbmp_t port_bmp;
    uint64 packets;
    struct ops_stats_entry *sentry = NULL, *next_sentry;
    opennsl_field_stat_t stats_type = opennslFieldStatPackets;

    cls = ops_cls_lookup(list_id);
    if (!cls) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",  UUID_ARGS(list_id));
        rc = OPS_FAIL;
        goto stats_get_fail;
    }

    VLOG_DBG("Classifier %s hit count request", cls->name);

    /* get the hardware unit */
    OPENNSL_PBMP_CLEAR(port_bmp);
    if (ops_cls_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_FAIL;
        goto stats_get_fail;
    }

    LIST_FOR_EACH_SAFE(sentry, next_sentry, node, &cls->stats_list) {
        if (sentry && sentry->rule_index < num_entries) {
            rc = opennsl_field_stat_get(hw_unit, sentry->index, stats_type, &packets);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to get packets stats for stats index"
                         " %d in classifier %s rc:%s",
                         sentry->index, cls->name, opennsl_errmsg(rc));
                rule_index = sentry->rule_index;
                goto stats_get_fail;
            }
            statistics[sentry->rule_index].stats_enabled = TRUE;
            statistics[sentry->rule_index].hitcounts = packets;
        }
    }

    return OPS_OK;

stats_get_fail:
    ops_cls_set_pd_list_status(rc, rule_index, status);
    return OPS_FAIL;
}


int
ops_cls_pd_statistics_clear(const struct uuid               *list_id,
                            const char                      *list_name,
                            enum ops_cls_type               list_type,
                            struct ofproto                  *ofproto,
                            void                            *aux,
                            struct ops_cls_interface_info   *interface_info,
                            enum ops_cls_direction          direction,
                            struct ops_cls_pd_list_status   *status)
{
    struct ops_classifier *cls;
    int hw_unit, rc, rule_index = 0;
    opennsl_pbmp_t port_bmp;
    uint64 value = 0;
    struct ops_stats_entry *sentry = NULL, *next_sentry;

    cls = ops_cls_lookup(list_id);
    if (!cls) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",  UUID_ARGS(list_id));
        rc = OPS_FAIL;
        goto stats_clear_fail;
    }

    VLOG_DBG("Classifier %s clear hit count request", cls->name);

    /* get the hardware unit */
    OPENNSL_PBMP_CLEAR(port_bmp);
    if (ops_cls_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_FAIL;
        goto stats_clear_fail;
    }

    LIST_FOR_EACH_SAFE(sentry, next_sentry, node, &cls->stats_list) {
        rc = opennsl_field_stat_all_set(hw_unit, sentry->index, value);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set  packets stats for stats index"
                     " %d in classifier %s rc:%s",
                     sentry->index, cls->name, opennsl_errmsg(rc));
            rule_index = sentry->rule_index;
            goto stats_clear_fail;
        }
    }

    return OPS_OK;

stats_clear_fail:
    ops_cls_set_pd_list_status(rc, rule_index, status);
    return OPS_FAIL;
}


int
ops_cls_pd_statistics_clear_all(struct ops_cls_pd_list_status *status)
{
    VLOG_ERR("%s unimplemented", __func__);
    return OPS_FAIL;
}