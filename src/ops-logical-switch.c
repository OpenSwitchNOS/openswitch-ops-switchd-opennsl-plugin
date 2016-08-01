/*
 * (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <openvswitch/vlog.h>
#include "log-switch-asic-provider.h"
#include "ops-logical-switch.h"
#include <opennsl/error.h>
#include "bcm-common.h"
#include "ops-vxlan.h"

VLOG_DEFINE_THIS_MODULE(ops_logical_switch);

/* Set logical switch */
int
ops_set_logical_switch(const struct ofproto *ofproto_,  void *aux,
                   enum logical_switch_action action,
                   struct logical_switch_node *log_switch)
{
    int rc = BCMSDK_E_NONE;
    int hw_unit = 0;
    bcmsdk_vxlan_opcode_t opcode;
    bcmsdk_vxlan_logical_switch_t lsw;

    switch (action) {
    case LSWITCH_ACTION_ADD:
        opcode = BCMSDK_VXLAN_OPCODE_CREATE;

        lsw.vnid = log_switch->tunnel_key;

        break;
    case LSWITCH_ACTION_DEL:
        lsw.vnid = log_switch->tunnel_key;
        opcode = BCMSDK_VXLAN_OPCODE_DESTROY;
        break;
    case LSWITCH_ACTION_MOD:
    default:
        VLOG_ERR("Error [%s, %d] action:%d name:%s key:%d hw_unit:%d\n",
                 __FUNCTION__, __LINE__,
                 action, log_switch->name, log_switch->tunnel_key,
                 hw_unit);
        return 1;
    }

    rc = bcmsdk_vxlan_logical_switch_operation(hw_unit, opcode, &lsw);

    return rc;
}
