/* Copyright (C) 2015. 2016 Hewlett Packard Enterprise Development LP
 * All Rights Reserved.

 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/* Purpose: This file contains code to handle FP related functionality
 * in the Broadcom ASIC.
 */

#include <string.h>
#include <openvswitch/vlog.h>
#include "ops-fp.h"

VLOG_DEFINE_THIS_MODULE(ops_fp);

struct ops_l3_feature_fp_info l3_feature_grp_info[MAX_SWITCH_UNIT_ID];

int
ops_fp_init(int hw_unit)
{
    /* Group ID for l3 feature */
    l3_feature_grp_info[hw_unit].l3_feature_grpid = -1;
    /* Entry id for all subinterface */
    l3_feature_grp_info[hw_unit].subint_fp_entry_id = -1;
    memset(l3_feature_grp_info[hw_unit].subint_count, 0, MAX_HW_PORTS);
    return 0;
}
