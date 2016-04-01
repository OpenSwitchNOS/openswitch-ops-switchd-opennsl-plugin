/*
 * Copyright (C) 2016 Hewlett-Packard Enterprise Development Company, L.P.
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
 * File: ops-mac-learning.c
 */
#include "hmap.h"
#include "ofproto/ofproto.h"
#include "packets.h"
#include "errno.h"
#include "ops-mac-learning.h"
#include <ovs-thread.h>
#include "netdev-bcmsdk.h"
#include "platform-defines.h"

VLOG_DEFINE_THIS_MODULE(ops_mac_learning);

/*
 * The buffers are defined as 2 because:
 *    To allow simultaneous read access to bridge.c and ops-mac-learning.c code
 *    threads will be: bcm_init thread, switchd main thread and thread created for
 *    bcm callback without worrying about wait for acquiring the lock.
 */
#define MAX_BUFFERS   2

struct ovs_mutex mlearn_mutex = OVS_MUTEX_INITIALIZER;
struct ofproto_mlearn_hmap G_buffer[MAX_BUFFERS] OVS_GUARDED_BY(mlearn_mutex);

static int G_current_hmap_in_use = 0 OVS_GUARDED_BY(mlearn_mutex);

static uint32_t mlearn_table_hash_calc(const struct eth_addr mac,
                                       const uint16_t vlan,
                                       int hw_unit)
{
    int hash = hash_2words(hash_uint64_basis(eth_addr_vlan_to_uint64(mac, vlan), 0), hw_unit);
    return (hash);
}

static bool ops_mac_table_is_full(const struct ofproto_mlearn_hmap *mlearn_hmap)
{
    return ((mlearn_hmap->buffer).actual_size == (mlearn_hmap->buffer).size);
}

static void ops_mac_entry_add(
        struct ofproto_mlearn_hmap *hmap_entry,
        const uint8_t mac[ETH_ADDR_LEN],
        const int16_t vlan,
        const int port_id,
        int hw_unit,
        const ofproto_mac_event event)
{
    struct ofproto_mlearn_hmap_node *entry = NULL;
    struct eth_addr mac_eth;
    uint32_t hash = 0;
    int actual_size = 0;
    bool found = false;
    char port_name[PORT_NAME_SIZE];

    memcpy(mac_eth.ea, mac, sizeof(mac_eth.ea));
    hash = mlearn_table_hash_calc(mac_eth, vlan, hw_unit);
    actual_size = (hmap_entry->buffer).actual_size;
    memset((void*)port_name, 0, sizeof(port_name));

    netdev_port_name_from_hw_id(hw_unit, port_id, port_name);

    HMAP_FOR_EACH_WITH_HASH (entry, hmap_node, hash,
                             &(hmap_entry->table)) {
        if ((entry->vlan == vlan) && eth_addr_equals(entry->mac, mac_eth) &&
            (entry->hw_unit == hw_unit)) {
            found = true;
            entry->oper = event;
            entry->port = port_id;
            entry->hw_unit = hw_unit;
            strncpy(entry->port_name, port_name, PORT_NAME_SIZE);
        }
    }

    if (!found) {
        if (actual_size < (hmap_entry->buffer).size) {
            struct ofproto_mlearn_hmap_node *mlearn_node =
                                    &((hmap_entry->buffer).nodes[actual_size + 1]);

            memcpy(&mlearn_node->mac, &mac_eth, sizeof(mac_eth));
            mlearn_node->port = port_id;
            mlearn_node->vlan = vlan;
            mlearn_node->hw_unit = hw_unit;
            mlearn_node->oper = event;
            strncpy(mlearn_node->port_name, port_name, PORT_NAME_SIZE);
            hmap_insert(&hmap_entry->table,
                        &(mlearn_node->hmap_node),
                        hash);
            (hmap_entry->buffer).actual_size++;
        } else {
            VLOG_ERR("Error, not able to insert elements in hmap, size is: %u\n",
                     hmap_entry->buffer.actual_size);
        }
    }
}

void ops_clear_mlearn_hmap (struct ofproto_mlearn_hmap *mhmap)
OVS_REQUIRES(mlearn_mutex)
{
    if (mhmap) {
        memset(&(mhmap->buffer), 0, sizeof(mhmap->buffer));
        mhmap->buffer.size = BUFFER_SIZE;
        hmap_clear(&(mhmap->table));
    }
}

int ops_mac_learning_run () OVS_REQUIRES(mlearn_mutex)
{
    if (hmap_count(&(G_buffer[G_current_hmap_in_use].table))) {
        mac_learning_trigger_callback();
        G_current_hmap_in_use = G_current_hmap_in_use ^ 1;
        ops_clear_mlearn_hmap(&G_buffer[G_current_hmap_in_use]);
    }

    return (0);
}

/*
 * This function is for getting callback from ASIC
 * for MAC learning.
 */
void
ops_mac_learn_cb(int   unit,
                 opennsl_l2_addr_t  *l2addr,
                 int    operation,
                 void   *userdata)
{
    if (l2addr == NULL) {
        VLOG_ERR("%s: Invalid arguments. l2-addr is NULL", __FUNCTION__);
        return;
    }

    switch (operation) {
        case OPENNSL_L2_CALLBACK_ADD:
            ops_mac_entry_add(&G_buffer[G_current_hmap_in_use],
                              l2addr->mac,
                              l2addr->vid,
                              l2addr->port,
                              unit,
                              MLEARN_ADD);
            break;
        case OPENNSL_L2_CALLBACK_DELETE:
             ops_mac_entry_add(&G_buffer[G_current_hmap_in_use],
                               l2addr->mac,
                               l2addr->vid,
                               l2addr->port,
                               unit,
                               MLEARN_DEL);
            break;
        default:
            break;
    }

    /*
     * notify vswitchd
     */
    if (ops_mac_table_is_full(&G_buffer[G_current_hmap_in_use])) {
        ops_mac_learning_run();
    }
}

int
ops_l2_traverse_cb (int unit,
                    opennsl_l2_addr_t *l2addr,
                    void *user_data)
{
     if (l2addr == NULL) {
        VLOG_ERR("%s: Invalid arguments. l2-addr is NULL", __FUNCTION__);
        return (EINVAL);
     }

     ops_mac_entry_add(&G_buffer[G_current_hmap_in_use],
                       l2addr->mac,
                       l2addr->vid,
                       l2addr->port,
                       unit,
                       MLEARN_ADD);
     return (0);
}

int ops_mac_learning_get_hmap(struct ofproto_mlearn_hmap **mhmap)
OVS_REQUIRES(mlearn_mutex)
{
    if (!mhmap) {
        VLOG_ERR("%s: Invalid argument", __FUNCTION__);
        return (EINVAL);
    }

    *mhmap = &G_buffer[G_current_hmap_in_use ^ 1];

    return (0);
}

int
ops_mac_learning_init()
{
    int idx = 0;
    int rc = 0;

    for (; idx < MAX_BUFFERS; idx++) {
        hmap_init(&(G_buffer[idx].table));
        G_buffer[idx].buffer.actual_size = 0;
        G_buffer[idx].buffer.size = BUFFER_SIZE;
        hmap_reserve(&(G_buffer[idx].table), BUFFER_SIZE);
    }

    for (idx=0; idx<MAX_SWITCH_UNITS; idx++) {
        rc = opennsl_l2_traverse(idx,
                                 ops_l2_traverse_cb,
                                 NULL);
        if (rc != 0) {
            VLOG_ERR("%s: error: %d\n", __FUNCTION__, rc);
            return (rc);
        }
    }

    return (0);
}
