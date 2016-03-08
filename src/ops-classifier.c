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
ops_classifier_lookup(const struct uuid *classifier_id)
{
    struct ops_classifier *cl = NULL;

    uint32_t id = uuid_hash(classifier_id);

    HMAP_FOR_EACH_WITH_HASH(cl, node, id, &classifier_map) {
        if (uuid_equals(&cl->id, classifier_id)) {
            return cl;
        }
    }
    return NULL;
}

/*
 * Copy classifier entries and store in hash
 */
void
ops_classifier_populate_entries(struct ops_classifier  *cl,
                                struct ovs_list        *list,
                                struct ops_cls_list    *clist)
{
    for (int i = 0; i < clist->num_entries; i++) {
        struct ops_classifier_entry *entry =
            xzalloc(sizeof(struct ops_classifier_entry));
        struct ops_cls_list_entry *cl_entry = &clist->entries[i];

        entry->pacl = cl;
        memcpy(&entry->entry_fields, &cl_entry->entry_fields,
               sizeof(struct ops_cls_list_entry_match_fields));
        memcpy(&entry->entry_actions, &cl_entry->entry_actions,
                sizeof(struct ops_cls_list_entry_actions));

        list_push_back(list, &entry->node);
    }
}

/*
 * Add classifier in hash (key uuid)
 */
static struct ops_classifier*
ops_classifier_add(struct ops_cls_list  *clist)
{
    struct ops_classifier *cl;

    if (!clist) {
        return NULL;
    }

    cl = xzalloc(sizeof(struct ops_classifier));

    cl->id = clist->list_id;
    cl->name = xstrdup(clist->list_name);
    cl->type = clist->list_type;
    cl->in_asic = false;
    OPENNSL_PBMP_CLEAR(cl->pbmp);
    /* Init classifer list entry list */
    list_init(&cl->entry_list);
    list_init(&cl->update_entry_list);

    if (clist->num_entries > 0) {
        VLOG_DBG("%s has %d rule entries", cl->name, clist->num_entries);
        ops_classifier_populate_entries(cl, &cl->entry_list, clist);
    }

    hmap_insert(&classifier_map, &cl->node, uuid_hash(&clist->list_id));

    VLOG_DBG("Added classifer %s in hashmap", cl->name);
    return cl;
}

/*
 * Delete classifier entries
 */
static void
ops_classifier_delete_entries(struct ops_classifier *cl,
                              struct ovs_list       *list)
{
    struct ops_classifier_entry *entry, *next_entry;

    LIST_FOR_EACH_SAFE (entry, next_entry,  node, list) {
        list_remove(&entry->node);
        free(entry);
    }

}

/*
 * Delete classifier from hash table
 */
static void
ops_classifier_delete(struct ops_classifier *cl)
{
    if (!cl) {
        return;
    }

    ops_classifier_delete_entries(cl, &cl->entry_list);
    ops_classifier_delete_entries(cl, &cl->update_entry_list);

    hmap_remove(&classifier_map, &cl->node);
    VLOG_DBG("Removed ACL %s in hashmap", cl->name);
    free(cl->name);
    free(cl);
}

/*
 * Get port(s) from bundle and add to bit map
 */
static int
ops_get_port_bitmap(struct ofproto *ofproto_,
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
ops_set_action(int                          unit,
               opennsl_field_entry_t        entry,
               struct ops_classifier_entry *cl_entry)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    if (cl_entry->act_flags & OPS_CLS_ACTION_DENY) {
        rc = opennsl_field_action_add(unit, entry, opennslFieldActionDrop,
                                      0, 0);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set drop action: rc=%s", opennsl_errmsg(rc));
            return rc;
        }
    }

    if (cl_entry->act_flags & OPS_CLS_ACTION_LOG) {
        VLOG_DBG("Log action not supported");
    }

    if (cl_entry->act_flags & OPS_CLS_ACTION_COUNT) {
        VLOG_DBG("Count action not supported");
    }

    return rc;
}

/*
 * Display ports
 */
char*
ops_display_port_bit_map(opennsl_pbmp_t *pbmp,
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
ops_set_cls_pd_status(int                        rc,
                      int                        rule_index,
                      struct ops_cls_pd_status  *pd_status)
{

    VLOG_DBG("ops classifier error: %d ", rc);

    switch (rc) {
    case OPS_FAIL:
    case OPENNSL_E_INTERNAL:
    case OPENNSL_E_MEMORY:
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
ops_set_cls_pd_list_status(int                             rc,
                           int                             rule_index,
                           struct ops_cls_pd_list_status  *status)
{

    VLOG_DBG("ops list error: %d ", rc);

    switch (rc) {
    case OPS_FAIL:
    case OPENNSL_E_INTERNAL:
    case OPENNSL_E_MEMORY:
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
 * Add rule in FP
 */
int
ops_install_rule_in_asic(int                           unit,
                         struct ops_classifier_entry  *cl_entry,
                         opennsl_pbmp_t               *pbmp,
                         int                          *entry_id)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_field_entry_t entry;
    opennsl_pbmp_t pbmp_mask;
    uint16_t port_mask = 0xFFFF;
    uint8_t protocol_mask = 0XFF;

    struct ops_classifier *cl = cl_entry->pacl;
    struct ops_cls_list_entry_match_fields *match = &cl_entry->entry_fields;

    rc = opennsl_field_entry_create(unit, ip_group, &entry);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to create entry for classifier %s rc=%s", cl->name,
                 opennsl_errmsg(rc));
        return rc;
    }

    VLOG_DBG("Classifier %s entry id %d", cl->name, entry);

    if (cl_entry->match_flags & OPS_CLS_SRC_IPADDR_VALID) {
        VLOG_DBG("Src ipv4 addr 0x%x and mask 0x%x", htonl(cl_entry->src_ip),
                 htonl(cl_entry->src_mask));

        rc = opennsl_field_qualify_SrcIp(unit, entry, htonl(cl_entry->src_ip),
                                         htonl(cl_entry->src_mask));
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Add entry src ipv4 0x%x and mask 0x%x failed: rc=%s",
                     htonl(cl_entry->src_ip), htonl(cl_entry->src_mask),
                     opennsl_errmsg(rc));
            goto cleanup;
        }
    }

    if (cl_entry->match_flags & OPS_CLS_DEST_IPADDR_VALID) {
        VLOG_DBG("Dst ipv4 addr 0x%x and mask 0x%x",
                 htonl(cl_entry->dst_ip), htonl(cl_entry->dst_mask));

        rc = opennsl_field_qualify_DstIp(unit, entry, htonl(cl_entry->dst_ip),
                                         htonl(cl_entry->dst_mask));
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Add entry dst ipv4 0x%x and mask 0x%x failed: rc=%s",
                     htonl(cl_entry->dst_ip), htonl(cl_entry->dst_mask),
                     opennsl_errmsg(rc));
            goto cleanup;
        }
    }

    if (cl_entry->match_flags & OPS_CLS_L4_SRC_PORT_VALID) {
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
        case OPS_CLS_L4_PORT_OP_NONE:
        case OPS_CLS_L4_PORT_OP_NEQ:
        case OPS_CLS_L4_PORT_OP_LT:
        case OPS_CLS_L4_PORT_OP_GT:
        default:
            VLOG_DBG("L4 port operation %d not supported",
                      match->L4_src_port_op);
            break;
        }
    }

    if (cl_entry->match_flags & OPS_CLS_L4_DEST_PORT_VALID) {
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
        case OPS_CLS_L4_PORT_OP_NONE:
        case OPS_CLS_L4_PORT_OP_NEQ:
        case OPS_CLS_L4_PORT_OP_LT:
        case OPS_CLS_L4_PORT_OP_GT:
        default:
            VLOG_DBG("L4 port operation %d not supported",
                      match->L4_dst_port_op);
            break;
        }
    }

    if (cl_entry->match_flags & OPS_CLS_PROTOCOL_VALID) {
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

    /* Ingress port(s) */
    if (OPENNSL_PBMP_NOT_NULL(*pbmp)) {
        char pbmp_string[200];

        OPENNSL_PBMP_CLEAR(pbmp_mask);
        OPENNSL_PBMP_NEGATE(pbmp_mask, pbmp_mask);

        VLOG_DBG("Ingress port(s): [ %s ]",
                 ops_display_port_bit_map(pbmp, pbmp_string, 200));
        rc = opennsl_field_qualify_InPorts(unit, entry, *pbmp, pbmp_mask);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set ingress port(s) [%s]: rc=%s",
                     pbmp_string, opennsl_errmsg(rc));
            goto cleanup;
        }
        OPENNSL_PBMP_ASSIGN(cl->pbmp, *pbmp);
    }

    /* Set the actions */
    rc = ops_set_action(unit, entry, cl_entry);
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
             cl->name, entry);
    /* Save the entry id in entry field */
    *entry_id = entry;
    cl_entry->in_asic = true;
    return rc;

cleanup:
    /* distroy entry and return rc */
    opennsl_field_entry_destroy(unit, entry);
    return rc;

}

/*
 * Add classifier rules in FP
 */
int ops_install_classifier_in_asic(int                    hw_unit,
                                   struct ops_classifier *cl,
                                   struct ovs_list       *list,
                                   opennsl_pbmp_t        *port_bmp,
                                   int                   *rule_index)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_classifier_entry *cl_entry = NULL, *next_cl_entry;
    int entry;

    /* Install in ASIC */
    LIST_FOR_EACH_SAFE(cl_entry, next_cl_entry, node, list) {
        rc = ops_install_rule_in_asic(hw_unit, cl_entry, port_bmp, &entry);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to install classifier %s rule(s) ", cl->name);
            return rc;
        }
        /* save the entry id */
        cl_entry->index = entry;
        (*rule_index)++;
    }
    VLOG_DBG("Classifier %s successfully installed in asic", cl->name);
    return rc;
}

/*
 * Update rule(s) port bitmap in FP
 */
int ops_classifier_pbmp_update(int                     hw_unit,
                               struct ops_classifier  *cl,
                               opennsl_pbmp_t         *port_bmp,
                               int                    *rule_index)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_classifier_entry *cl_entry = NULL, *next_cl_entry;
    opennsl_pbmp_t pbmp_mask;
    char pbmp_string[200];
    int entry;

    OPENNSL_PBMP_CLEAR(pbmp_mask);
    OPENNSL_PBMP_NEGATE(pbmp_mask, pbmp_mask);

    VLOG_DBG("Updated port bit map: [ %s ]",
             ops_display_port_bit_map(port_bmp, pbmp_string, 200));

    LIST_FOR_EACH_SAFE(cl_entry, next_cl_entry, node, &cl->entry_list) {
        entry = cl_entry->index;
        rc = opennsl_field_qualify_InPorts(hw_unit, entry, *port_bmp,
                                           pbmp_mask);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to update classifier %s rule port bitmask rc:%s",
                     cl->name, opennsl_errmsg(rc));
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
ops_delete_rules_in_asic(int                    hw_unit,
                         struct ops_classifier *cl,
                         struct ovs_list       *list,
                         int                   *rule_index)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_classifier_entry *cl_entry = NULL, *next_cl_entry;
    int entry;

    LIST_FOR_EACH_SAFE(cl_entry, next_cl_entry, node, list) {
        if (!cl_entry->in_asic) {
            (*rule_index)++;
            continue;
        }

        entry = cl_entry->index;
        rc =  opennsl_field_entry_destroy(hw_unit, entry);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy classifier %s rule %d rc:%s",
                     cl->name, entry, opennsl_errmsg(rc));
        }
        cl_entry->in_asic = false;
        (*rule_index)++;
    }
    return rc;
}

/*
 * Update port bitmap of classifier
 */
int ops_update_classifier_in_asic(int                    hw_unit,
                                  struct ops_classifier *cl,
                                  opennsl_pbmp_t        *port_bmp,
                                  enum ops_update_pbmp   action,
                                  int                   *rule_index)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_pbmp_t pbmp;

    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_OR(pbmp, cl->pbmp);
    switch (action) {
    case OPS_PBMP_ADD:
        OPENNSL_PBMP_OR(pbmp, *port_bmp);
        rc = ops_classifier_pbmp_update(hw_unit, cl, &pbmp, rule_index);
        if (OPENNSL_SUCCESS(rc)) {
            OPENNSL_PBMP_ASSIGN(cl->pbmp, pbmp);
        }
        break;

    case OPS_PBMP_DEL:
        OPENNSL_PBMP_XOR(pbmp, *port_bmp);
        if (OPENNSL_PBMP_IS_NULL(pbmp)) {
            VLOG_DBG("Port bit is NULL, remove classifer %s in asic",
                     cl->name);
            rc = ops_delete_rules_in_asic(hw_unit, cl, &cl->entry_list,
                                          rule_index);
            ops_classifier_delete(cl);
        } else {
            rc = ops_classifier_pbmp_update(hw_unit, cl, &pbmp, rule_index);
        }

        if (OPENNSL_SUCCESS(rc)) {
            OPENNSL_PBMP_ASSIGN(cl->pbmp, pbmp);
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
    struct ops_classifier *cl = NULL;
    char pbmp_string[200];
    int  rule_index = 0; /* rule index to PI on failure */

    OPENNSL_PBMP_CLEAR(port_bmp);
    cl = ops_classifier_lookup(&list->list_id);
    if (!cl) {
        cl = ops_classifier_add(list);
        if (!cl) {
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
    if (ops_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_FAIL;
        goto apply_fail;
    }

    VLOG_DBG("Apply classifier %s on port(s) [ %s ]", cl->name,
              ops_display_port_bit_map(&port_bmp, pbmp_string, 200));

    if (!cl->in_asic) {
        /* first binding of classifier*/
        rc = ops_install_classifier_in_asic(hw_unit, cl, &cl->entry_list,
                                            &port_bmp, &rule_index);
        if (OPENNSL_FAILURE(rc)) {
            int dummy_index = 0;
            ops_delete_rules_in_asic(hw_unit, cl, &cl->entry_list, &dummy_index);
            ops_classifier_delete(cl);
            goto apply_fail;
        }
        cl->in_asic = true;
    } else {
        /* already in asic update port bitmap */
        rc = ops_update_classifier_in_asic(hw_unit, cl, &port_bmp,
                                           OPS_PBMP_ADD, &rule_index);
        if (OPENNSL_FAILURE(rc)) {
            goto apply_fail;
        }
    }

    return OPS_OK;

apply_fail:
    ops_set_cls_pd_status(rc, rule_index, pd_status);
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
    struct ops_classifier *cl = NULL;
    char pbmp_string[200];
    int rule_index = 0; /* rule index to PI on failure */

    OPENNSL_PBMP_CLEAR(port_bmp);
    cl = ops_classifier_lookup(list_id);
    if (!cl) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",  UUID_ARGS(list_id));
        rc = OPS_FAIL;
        goto remove_fail;
    }

    /* get the port bits_map */
    if (ops_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_FAIL;
        goto remove_fail;
    }

    VLOG_DBG("Remove classifier %s on port(s) [ %s ]", cl->name,
              ops_display_port_bit_map(&port_bmp, pbmp_string, 200));

    if (!cl->in_asic) {
        VLOG_ERR("Port remove failed, classifier %s not in asic", cl->name);
        rc = OPS_FAIL;
        goto remove_fail;
    } else {
        /* already in asic update port bitmap */
        rc = ops_update_classifier_in_asic(hw_unit, cl, &port_bmp,
                                           OPS_PBMP_DEL, &rule_index);
        if(OPENNSL_FAILURE(rc)) {
            goto remove_fail;
        }
    }

    return OPS_OK;

remove_fail:
    ops_set_cls_pd_status(rc, rule_index, pd_status);
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
    struct ops_classifier *cl_orig = NULL, *cl_new = NULL;
    char pbmp_string[200];
    int rule_index = 0; /* rule index to PI on failure */

    cl_orig = ops_classifier_lookup(list_id_orig);
    if (!cl_orig) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",
                 UUID_ARGS(list_id_orig));
        rc = OPS_FAIL;
        goto replace_fail;
    }

    cl_new = ops_classifier_lookup(&list_new->list_id);
    if (!cl_new) {
        cl_new = ops_classifier_add(list_new);
        if (!cl_new) {
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
    if (ops_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_FAIL;
        goto replace_fail;
    }

    VLOG_DBG("Replace classifier %s with %s on port(s) [ %s ]",
             cl_orig->name, cl_new->name,
             ops_display_port_bit_map(&port_bmp, pbmp_string, 200));

    if (!cl_new->in_asic) {
        /* first binding of classifier*/
        rc = ops_install_classifier_in_asic(hw_unit, cl_new,
                                            &cl_new->entry_list,
                                            &port_bmp, &rule_index);
        if (OPENNSL_FAILURE(rc)) {
            int dummy_index = 0;
            ops_delete_rules_in_asic(hw_unit, cl_new, &cl_new->entry_list,
                                     &dummy_index);
            goto replace_fail;
        }
        cl_new->in_asic = true;
    } else {
        /* already in asic update port bitmap */
        rc = ops_update_classifier_in_asic(hw_unit, cl_new, &port_bmp,
                                           OPS_PBMP_ADD, &rule_index);
        if (OPENNSL_FAILURE(rc)) {
            goto replace_fail;
        }
    }

    if (cl_orig->in_asic) {
        /* already in asic update port bitmap */
        rule_index = 0;
        rc = ops_update_classifier_in_asic(hw_unit, cl_orig, &port_bmp,
                                           OPS_PBMP_DEL, &rule_index);
        if(OPENNSL_FAILURE(rc)) {
            goto replace_fail;
        }
    }

    return OPS_OK;

replace_fail:
    ops_set_cls_pd_status(rc, rule_index, pd_status);
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
    struct ops_classifier *cl = NULL;
    int hw_unit =  0;
    opennsl_pbmp_t port_bmp;
    int rule_index = 0; /* rule index to PI on failure */

    cl = ops_classifier_lookup(&list->list_id);
    if (!cl) {
        cl = ops_classifier_add(list);
        if (!cl) {
            VLOG_ERR ("Failed to add classifier %s in hashmap", list->list_name);
            rc = OPS_FAIL;
            goto update_fail;
        }
    } else {
        VLOG_DBG("Classifier %s exist in haspmap", list->list_name);
    }

    if (!cl->in_asic) {
        ops_classifier_delete_entries(cl, &cl->entry_list);

        if (list->num_entries > 0) {
            ops_classifier_populate_entries(cl, &cl->entry_list, list);
        }
    } else {  /* already in asic */
        if (list->num_entries > 0) {
            /*
             * Install updated ACL in FP, if it fails, remove
             * the updated ACL and leave original ACL. On successful
             * update remove the original ACL entries.
             */

            ops_classifier_populate_entries(cl, &cl->update_entry_list, list);

            OPENNSL_PBMP_CLEAR(port_bmp);
            OPENNSL_PBMP_ASSIGN(port_bmp, cl->pbmp);

            rc = ops_install_classifier_in_asic(hw_unit, cl, &cl->update_entry_list,
                                                &port_bmp, &rule_index);
            int dummy_index = 0;
            if(OPENNSL_FAILURE(rc)) {
                ops_delete_rules_in_asic(hw_unit, cl, &cl->update_entry_list,
                                         &dummy_index);
                ops_classifier_delete_entries(cl, &cl->update_entry_list);
                goto update_fail;
            } else {
                ops_delete_rules_in_asic(hw_unit, cl, &cl->entry_list, &dummy_index);
                ops_classifier_delete_entries(cl, &cl->entry_list);
                list_move(&cl->entry_list, &cl->update_entry_list);
                list_init(&cl->update_entry_list);
            }

        }
    }
    return OPS_OK;

update_fail:
    ops_set_cls_pd_list_status(rc, rule_index, status);
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
    VLOG_ERR("%s unimplemented", __func__);
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
    VLOG_ERR("%s unimplemented", __func__);
    return OPS_FAIL;
}


int
ops_cls_pd_statistics_clear_all(struct ops_cls_pd_list_status *status)
{
    VLOG_ERR("%s unimplemented", __func__);
    return OPS_FAIL;
}
