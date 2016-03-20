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
 * File: bcm-plugins.c
 */

#include <openvswitch/vlog.h>
#include <netdev-provider.h>
#include "bcm.h"
#include "bufmon-bcm-provider.h"
#include "netdev-bcmsdk.h"
#include "ofproto-bcm-provider.h"
#include "plugin-extensions.h"
#include "qos-asic-provider.h"

#define init libovs_bcm_plugin_LTX_init
#define run libovs_bcm_plugin_LTX_run
#define wait libovs_bcm_plugin_LTX_wait
#define destroy libovs_bcm_plugin_LTX_destroy
#define netdev_register libovs_bcm_plugin_LTX_netdev_register
#define ofproto_register libovs_bcm_plugin_LTX_ofproto_register
#define bufmon_register libovs_bcm_plugin_LTX_bufmon_register

VLOG_DEFINE_THIS_MODULE(bcm_plugin);

/* QOS platform-dependent API get added here. */
struct qos_asic_plugin_interface opennsl_qos_interface = {
    .set_port_qos_cfg = &set_port_qos_cfg,
    .set_cos_map = &set_cos_map,
    .set_dscp_map = &set_dscp_map,
    .apply_qos_profile = &apply_qos_profile,
};

struct plugin_extension_interface opennsl_qos_extension = {
    QOS_ASIC_PLUGIN_INTERFACE_NAME,
    QOS_ASIC_PLUGIN_INTERFACE_MAJOR,
    QOS_ASIC_PLUGIN_INTERFACE_MINOR,
    (void *)&opennsl_qos_interface
};


/* To avoid compiler warning... */
static void netdev_change_seq_changed(const struct netdev *) __attribute__((__unused__));

void
init(void) {

    register_plugin_extension(&opennsl_qos_extension);
    VLOG_INFO("The %s asic plugin interface was registered", QOS_ASIC_PLUGIN_INTERFACE_NAME);

    ovs_bcm_init();
}

void
run(void) {
}

void
wait(void) {
}

void
destroy(void) {
    // OPS_TODO: add graceful shutdown of BCM threads.
}

void
netdev_register(void) {
    netdev_bcmsdk_register();
}

void
ofproto_register(void) {
    ofproto_class_register(&ofproto_bcm_provider_class);
}

void
bufmon_register(void) {
    bufmon_class_register(&bufmon_bcm_provider_class);
}
