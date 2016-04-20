/*
 * Copyright (C) 2015-2016 Hewlett-Packard Development Company, L.P.
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

#define SPEED_1G                    1000
#define SPEED_10G                   10000
#define SPEED_25G                   25000
#define SPEED_40G                   40000
#define SPEED_50G                   50000
#define SPEED_100G                  100000

#define STR_EQ(s1, s2)      ((s1 != NULL) && (s2 != NULL) && \
                             (strlen((s1)) == strlen((s2))) && \
                             (!strncmp((s1), (s2), strlen((s2)))))

/* BCM SDK provider API. */
extern void netdev_bcmsdk_register(void);
extern void netdev_bcmsdk_get_hw_info(struct netdev *netdev,
                                      int *hw_unit, int *hw_id, uint8_t *mac);
extern void netdev_bcmsdk_get_hw_info_from_name(const char *name,
                                                int *hw_unit, int *hw_id);
extern void netdev_bcmsdk_link_state_callback(int hw_unit, int hw_id,
                                              int link_status);
extern void
netdev_bcmsdk_get_subintf_vlan(struct netdev *netdev, opennsl_vlan_t *vlan);
extern void handle_bcmsdk_knet_l3_port_filters(struct netdev *netdev_, opennsl_vlan_t vlan_id, bool enable);
extern void handle_bcmsdk_knet_subinterface_filters(struct netdev *netdev_, bool enable);
extern bool netdev_hw_id_from_name(const char *name, int *hw_unit, int *hw_id);
extern void netdev_bcmsdk_populate_sflow_stats(bool ingress, const char *name, uint64_t bytes);

extern void netdev_bcmsdk_get_sflow_intf_info(int hw_unit, int hw_id,
                                              uint32_t *index, uint64_t *speed,
                                              uint32_t *direction,
                                              uint32_t *status);
#endif /* netdev-bcmsdk.h */
