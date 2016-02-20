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
 * File: ops-stg.h
 *
 * Purpose: This file provides public definitions for Opennsl Spanning Tree Group API's.
 */

#ifndef __OPS_STG_H__
#define __OPS_STG_H__ 1

#include <ovs/dynamic-string.h>
#include <opennsl/types.h>

#define OPS_STG_RESERVED      0
#define OPS_STG_DEFAULT       1
#define OPS_STG_MIN           1
#define OPS_STG_MAX           64
#define OPS_STG_VALID(v)  ((v)>=OPS_STG_MIN && (v)<=OPS_STG_MAX)
#define OPS_STG_COUNT     (OPS_STG_MAX - OPS_STG_MIN + 1)

typedef enum ops_stg_port_state {
    OPS_STG_PORT_STATE_DISABLED = 0,
    OPS_STG_PORT_STATE_BLOCKED,
    OPS_STG_PORT_STATE_LEARNING,
    OPS_STG_PORT_STATE_FORWARDING,
    OPS_STG_PORT_STATE_NOT_SET
}ops_stg_port_state_t;

extern int ops_stg_init(int hw_unit);
extern void ops_stg_dump(struct ds *ds, int stgid);

extern int ops_stg_default_get(opennsl_stg_t *stg_ptr);
extern int ops_stg_vlan_add(opennsl_stg_t stg, opennsl_vlan_t vid);
extern int ops_stg_vlan_remove(opennsl_stg_t stg, opennsl_vlan_t vid);
extern int ops_stg_create(opennsl_stg_t *stg_ptr);
extern int ops_stg_delete(opennsl_stg_t stg);
extern int ops_stg_list_delete(opennsl_stg_t *list_ptr, int count);
extern int ops_stg_stp_set(opennsl_stg_t stg, opennsl_port_t port,
                              int stp_state, bool port_stp_set);
extern int ops_stg_stp_get(opennsl_stg_t stg, opennsl_port_t port,
                              int *stp_state_ptr);


#endif /* __OPS_STG_H__ */
