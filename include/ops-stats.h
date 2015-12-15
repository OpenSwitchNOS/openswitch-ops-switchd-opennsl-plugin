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
 * File: ops-stats.h
 *
 * Purpose: This file provides public definitions for Interface statistics API.
 */

#ifndef __OPS_STAT_H__
#define __OPS_STAT_H__ 1

#include <ofproto/ofproto.h>
#include "local_bcm_api.h"

struct ops_stats_egress_id {
    struct   hmap_node egress_node;
    int      egress_object_id;
    uint32_t egress_num_id;
    uint32_t egress_stat_id;
};

struct ops_l3_stats_ingress {
    int      ingress_vlan_id;
    uint32_t ingress_num_id;
    uint32_t ingress_stat_id;
};

struct ops_deleted_stats {
    uint32_t del_packets;
    uint32_t del_bytes;
    uint32_t del_drop_packets;
};

extern int bcmsdk_get_port_stats(int hw_unit, int hw_port, struct netdev_stats *stats);

extern int bcmsdk_get_l3_egress_stats(int hw_unit,
                               struct netdev_stats *stats, int egress_object_id,
                               uint32_t egress_num_id);

extern int bcmsdk_get_l3_ingress_stats(int hw_unit,
                               struct netdev_stats *stats, int ingress_vlan_id,
                               uint32_t ingress_num_id);
#endif /* __OPS_STAT_H__ */
