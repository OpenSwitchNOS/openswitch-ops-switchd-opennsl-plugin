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
 * File: netdev-bcmsdk.h
 */

#ifndef NETDEV_BCMSDK_H
#define NETDEV_BCMSDK_H 1

#define STR_EQ(s1, s2)      ((s1 != NULL) && (s2 != NULL) && \
                             (strlen((s1)) == strlen((s2))) && \
                             (!strncmp((s1), (s2), strlen((s2)))))

/* BCM SDK provider API. */
extern void netdev_bcmsdk_register(void);
extern void netdev_bcmsdk_get_hw_info(struct netdev *netdev,
                                      int *hw_unit, int *hw_id, uint8_t *mac);
extern void netdev_bcmsdk_link_state_callback(int hw_unit, int hw_id,
                                              int link_status);

extern int netdev_bcmsdk_set_l3_ingress_stat_obj(const struct netdev *netdev_,
                                                 const int vlan_id,
                                                 const uint32_t ing_stat_id,
                                                 const uint32_t ing_num_id);

extern int netdev_bcmsdk_set_l3_egress_id(const struct netdev *netdev,
                                          const int l3_egress_id,
                                          const uint32_t egr_stat_id,
                                          const uint32_t egr_num_id);

extern int netdev_bcmsdk_remove_l3_egress_id(const struct netdev *netdev,
                                             const int l3_egress_id);
#endif /* netdev-bcmsdk.h */
