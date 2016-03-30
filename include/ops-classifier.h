/*
 * Copyright (C) 2015, 2016 Hewlett Packard Enterprise Development LP
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
 */

#ifndef __OPS_CLASSIFIER_H__
#define __OPS_CLASSIFIER_H__ 1


#include "ofproto-ops-classifier.h"

/************************************************************************//**
 * @defgroup ops-switchd-classifier-api classifier plug-in interface
 *
 * See ops/doc/switchd_classifier_api_design.md for additional information
 *
 * @todo write ops/doc/switchd_classifier_api_design.md
 ***************************************************************************/

/************************************************************************//**
 * @ingroup ops-switchd-classifier-api
 *
 * @file
 * Prototypes for the Classifier List plug-in interface. For now,
 * documentation for these functions can be found in the ops-openvswitch
 * repo:
 * vswitchd/plugins/ops-classifier/include/ofproto-ops-classifier.h"
 ***************************************************************************/
int ops_cls_pd_apply(struct ops_cls_list            *list,
                     struct ofproto                 *ofproto,
                     void                           *aux,
                     struct ops_cls_interface_info  *interface_info,
                     enum ops_cls_direction         direction,
                     struct ops_cls_pd_status       *pd_status);

int ops_cls_pd_remove(const struct uuid                *list_id,
                      const char                       *list_name,
                      enum ops_cls_type                list_type,
                      struct ofproto                   *ofproto,
                      void                             *aux,
                      struct ops_cls_interface_info    *interface_info,
                      enum ops_cls_direction           direction,
                      struct ops_cls_pd_status         *pd_status);

int ops_cls_pd_replace(const struct uuid               *list_id_orig,
                       const char                      *list_name_orig,
                       struct ops_cls_list             *list_new,
                       struct ofproto                  *ofproto,
                       void                            *aux,
                       struct ops_cls_interface_info   *interface_info,
                       enum ops_cls_direction          direction,
                       struct ops_cls_pd_status        *pd_status);

int ops_cls_pd_list_update(struct ops_cls_list              *list,
                           struct ops_cls_pd_list_status    *status);

int ops_cls_pd_statistics_get(const struct uuid              *list_id,
                              const char                     *list_name,
                              enum ops_cls_type              list_type,
                              struct ofproto                 *ofproto,
                              void                           *aux,
                              struct ops_cls_interface_info *interface_info,
                              enum ops_cls_direction         direction,
                              struct ops_cls_statistics      *statistics,
                              int                            num_entries,
                              struct ops_cls_pd_list_status  *status);

int ops_cls_pd_statistics_clear(const struct uuid               *list_id,
                                const char                      *list_name,
                                enum ops_cls_type               list_type,
                                struct ofproto                  *ofproto,
                                void                            *aux,
                                struct ops_cls_interface_info   *interface_info,
                                enum ops_cls_direction          direction,
                                struct ops_cls_pd_list_status   *status);

int ops_cls_pd_statistics_clear_all(struct ops_cls_pd_list_status *status);





/**
 * Initialization function for BCM Classifier switchd plug-in
 *
 * @param  unit                - chip to operate on
 *
 * @retval 0                   - if initialized successfully
 * @retval != 0                - if not initialized successfully
 */
int ops_classifier_init (int unit);

struct ops_classifier {
    struct hmap_node node;
    struct uuid id;
    char *name;                                /* name of classifier list */
    bool in_asic;                              /* classifer already in asic */
    enum ops_cls_type type;                    /* type of classifier list - aclv4, aclv6 */
    opennsl_pbmp_t pbmp;                       /* port classifier is applied */
    struct ovs_list entry_list;                /* list of ops_classifier_entry */
    struct ovs_list range_list;                /* list of ops_range_entry */
    struct ovs_list stats_list;                /* list of stats entry */
    struct ovs_list entry_update_list;         /* updated ops_classifier_entry list */
    struct ovs_list range_update_list;         /* updated list of ops_range_entry */
    struct ovs_list stats_update_list;         /* updated list of stats entry */
};

struct ops_classifier_entry {
    struct ovs_list node;
    uint32_t index;                     /* classifier index*/
    struct ops_classifier *pacl;
    bool in_asic;                       /* installed in asic */
    struct ops_cls_list_entry_match_fields entry_fields;   /* field(s)/value(s) to match */
#define match_flags entry_fields.entry_flags
#define src_ip      entry_fields.src_ip_address.v4.s_addr
#define src_mask    entry_fields.src_ip_address_mask.v4.s_addr
#define dst_ip      entry_fields.dst_ip_address.v4.s_addr
#define dst_mask    entry_fields.dst_ip_address_mask.v4.s_addr
    struct ops_cls_list_entry_actions entry_actions;        /* action(s) to take */
#define act_flags   entry_actions.action_flags
};

struct ops_range_entry {
    struct ovs_list node;
    uint32_t index;                     /* range index */
};

struct ops_stats_entry {
    struct ovs_list node;
    uint32_t index;                     /* stats index */
    uint16_t rule_index;                /* rule index of PI classifier*/
};

enum ops_update_pbmp {
    OPS_PBMP_ADD = 0,
    OPS_PBMP_DEL,
};

#endif /* __OPS_CLASSIFIER_H__ */
