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
#include "ovs-thread.h"
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

/*
 * mlearn_mutex is the mutex going to be used to access the all_macs_learnt and
 * what hmap is currently in use.
 */
struct ovs_mutex mlearn_mutex = OVS_MUTEX_INITIALIZER;

/*
 * all_macs_learnt:
 *      It is for storing the MACs learnt.
 *
 * Threads that can access this data structure: bcm thread, bcm timer thead,
 * bcm thread created by ASIC for the traversal.
 */
struct mlearn_hmap all_macs_learnt[MAX_BUFFERS] OVS_GUARDED_BY(mlearn_mutex);

static int current_hmap_in_use = 0 OVS_GUARDED_BY(mlearn_mutex);

/*
 * Function: mlearn_table_hash_calc
 *
 * This function calculates the hash based on MAC address, vlan and hardware unit number.
 */
static uint32_t mlearn_table_hash_calc(const struct eth_addr mac,
                                       const uint16_t vlan,
                                       int hw_unit)
{
    int hash = hash_2words(hash_uint64_basis(eth_addr_vlan_to_uint64(mac, vlan), 0), hw_unit);
    return (hash);
}

/*
 * Function: ops_mac_table_is_full
 *
 * This function is used to find if the hmap has reached it's capacity or not.
 */
static bool ops_mac_table_is_full(const struct mlearn_hmap *mlearn_hmap)
{
    return ((mlearn_hmap->buffer).actual_size == (mlearn_hmap->buffer).size);
}

/*
 * Function: ops_mac_entry_add
 *
 * This function is used to add the entries in the all_macs_learnt hmap.
 *
 * If the entry is already present, it is modified or else it's created.
 */
static void ops_mac_entry_add(
        struct mlearn_hmap *hmap_entry,
        const uint8_t mac[ETH_ADDR_LEN],
        const int16_t vlan,
        const int port_id,
        int hw_unit,
        const mac_event event)
{
    struct mlearn_hmap_node *entry = NULL;
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
            struct mlearn_hmap_node *mlearn_node =
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

/*
 * Function: ops_clear_mlearn_hmap
 *
 * This function clears the hmap and the buffer for storing the hmap nodes.
 */
void ops_clear_mlearn_hmap (struct mlearn_hmap *mhmap)
{
    if (mhmap) {
        memset(&(mhmap->buffer), 0, sizeof(mhmap->buffer));
        mhmap->buffer.size = BUFFER_SIZE;
        hmap_clear(&(mhmap->table));
    }
}

/*
 * Function: ops_mac_learning_run
 *
 * This function will be invoked when either of the two conditions
 * are satisfied:
 * 1. current in use hmap for storing all macs learnt is full
 * 2. timer thread times out
 *
 * This function will check if there is any new MACs learnt, if yes,
 * then it triggers callback from bridge.
 * Also it changes the current hmap in use.
 *
 * current_hmap_in_use = current_hmap_in_use ^ 1 is used to toggle
 * the current hmap in use as the buffers are 2.
 */
int ops_mac_learning_run ()
{
    ovs_mutex_lock(&mlearn_mutex);
    if (hmap_count(&(all_macs_learnt[current_hmap_in_use].table))) {
        mac_learning_trigger_callback();
        current_hmap_in_use = current_hmap_in_use ^ 1;
        ops_clear_mlearn_hmap(&all_macs_learnt[current_hmap_in_use]);
    }
    ovs_mutex_unlock(&mlearn_mutex);

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
            ovs_mutex_lock(&mlearn_mutex);
            ops_mac_entry_add(&all_macs_learnt[current_hmap_in_use],
                              l2addr->mac,
                              l2addr->vid,
                              l2addr->port,
                              unit,
                              MLEARN_ADD);
            ovs_mutex_unlock(&mlearn_mutex);
            break;
        case OPENNSL_L2_CALLBACK_DELETE:
            ovs_mutex_lock(&mlearn_mutex);
             ops_mac_entry_add(&all_macs_learnt[current_hmap_in_use],
                               l2addr->mac,
                               l2addr->vid,
                               l2addr->port,
                               unit,
                               MLEARN_DEL);
             ovs_mutex_unlock(&mlearn_mutex);
            break;
        default:
            break;
    }

    /*
     * notify vswitchd
     */
    if (ops_mac_table_is_full(&all_macs_learnt[current_hmap_in_use])) {
        ops_mac_learning_run();
    }
}

/*
 * Function: ops_l2_traverse_cb
 *
 * This function is triggered during the initialization. Currently,
 * when switchd process restarts, it resets the ASIC, but when HA
 * will be in place, this function will traverse the already learnt
 * entries in the hardware.
 */
int
ops_l2_traverse_cb (int unit,
                    opennsl_l2_addr_t *l2addr,
                    void *user_data)
{
     if (l2addr == NULL) {
        VLOG_ERR("%s: Invalid arguments. l2-addr is NULL", __FUNCTION__);
        return (EINVAL);
     }

     ovs_mutex_lock(&mlearn_mutex);
     ops_mac_entry_add(&all_macs_learnt[current_hmap_in_use],
                       l2addr->mac,
                       l2addr->vid,
                       l2addr->port,
                       unit,
                       MLEARN_ADD);
     ovs_mutex_unlock(&mlearn_mutex);
     return (0);
}

/*
 * Function: ops_mac_learning_get_hmap
 *
 * This function will be invoked by the mac learning plugin code,
 * so that the switchd main thread can get the new MACs learnt/deleted
 * and can update the MAC table in the OVSDB accordingly.
 */
int ops_mac_learning_get_hmap(struct mlearn_hmap **mhmap)
{
    VLOG_INFO("In %s", __FUNCTION__);
    if (!mhmap) {
        VLOG_ERR("%s: Invalid argument", __FUNCTION__);
        return (EINVAL);
    }

    ovs_mutex_lock(&mlearn_mutex);
    if (hmap_count(&(all_macs_learnt[current_hmap_in_use ^ 1].table))) {
        *mhmap = &all_macs_learnt[current_hmap_in_use ^ 1];
    } else {
        *mhmap = NULL;
    }
    ovs_mutex_unlock(&mlearn_mutex);

    return (0);
}

/*
 * Function: ops_mac_learning_init
 *
 * This function is invoked in the bcm init.
 *
 * It initializes the hmaps, reserves the buffer capacity of the hmap
 * to avoid the time spent in the malloc and free.
 *
 * It also registers for the initial traversal of the MACs already
 * learnt in the ASIC for all hw_units.
 */
int
ops_mac_learning_init()
{
    int idx = 0;
    int rc = 0;

    for (; idx < MAX_BUFFERS; idx++) {
        hmap_init(&(all_macs_learnt[idx].table));
        all_macs_learnt[idx].buffer.actual_size = 0;
        all_macs_learnt[idx].buffer.size = BUFFER_SIZE;
        hmap_reserve(&(all_macs_learnt[idx].table), BUFFER_SIZE);
    }

    for (idx = 0; idx < MAX_SWITCH_UNITS; idx++) {
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
