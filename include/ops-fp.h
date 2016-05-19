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
 * File: ops-fp.h
 *
 * Purpose: This file provides public definitions for FP functionality.
 *
 */

#ifndef __OPS_FP_H__
#define __OPS_FP_H__ 1

#include <opennsl/l3.h>
#include <opennsl/field.h>
#include "platform-defines.h"

struct ops_l3_feature_fp_info {
    opennsl_field_group_t l3_feature_grpid;
    opennsl_field_entry_t subint_fp_entry_id;
    int subint_count[MAX_HW_PORTS];
};

enum ops_fp_grp_prio {
    FP_GROUP_PRIORITY_0 = 0,
    FP_GROUP_PRIORITY_1,
    FP_GROUP_PRIORITY_2
};

extern int ops_fp_init(int hw_unit);
extern struct ops_l3_feature_fp_info l3_feature_grp_info[MAX_SWITCH_UNIT_ID];
extern opennsl_error_t ops_get_l3_feature_grp_id(int hw_unit, opennsl_field_group_t *grpid);
extern opennsl_error_t ops_get_l3_feature_subint_fp_entry_id(int hw_unit, opennsl_field_entry_t *entry_id);
#endif
