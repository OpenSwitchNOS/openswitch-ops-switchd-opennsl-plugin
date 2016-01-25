/*
 * Copyright (C) 2015-2016 Hewlett Packard Enterprise Development Company, L.P.
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
 * File: ops-bcm-init.c
 *
 * Purpose: Main file for the implementation of OpenSwitch BCM SDK application initialization.
 */

#include <ctype.h>

#include <openvswitch/vlog.h>

#include <sal/driver.h>
#include <opennsl/error.h>
#include <opennsl/rx.h>

#include "bcm.h"
#include "platform-defines.h"
#include "ops-bcm-init.h"
#include "ops-knet.h"
#include "ops-port.h"
#include "ops-routing.h"
#include "ops-vlan.h"
#include "ops-debug.h"
#include "ops-sflow.h"

VLOG_DEFINE_THIS_MODULE(ops_bcm_init);

#define OPENNSL_RX_REASON_GET(_reasons, _reason) \
     (((_reasons).pbits[(_reason)/32]) & (1U << ((_reason)%32)))

extern SFLAgent *ops_sflow_agent;

extern int
opennsl_rx_register(int, const char *, opennsl_rx_cb_f, uint8, void *, uint32);

/* TODO: This callback is also sending sFlow pkts to collectors. It must
 * do minimal computation in order to receive subsequent sFlow pkts.
 * Callback should queue up pkts received from ASIC and return.
 * Temporarily, configure a low sampling rate (say 1 in 10 pkts, when
 * incoming rate is 1 pkt/s as in case of 'ping'). Eventually, a different
 * thread will process incoming pkts.
 */

opennsl_rx_t opennsl_rx_callback(int unit, opennsl_pkt_t *pkt, void *cookie)
{
    if (!pkt) {
        VLOG_ERR("Invalid pkt sent by ASIC");
        return OPENNSL_RX_HANDLED;
    }

    if (OPENNSL_RX_REASON_GET(pkt->reserved25, opennslRxReasonSampleDest) ||
        OPENNSL_RX_REASON_GET(pkt->reserved25, opennslRxReasonSampleSource)) {

        VLOG_DBG("%s:%d; sFlow's sampled pkt.", __FUNCTION__, __LINE__);

        /* Write incoming data to Receivers buffer. When buffer is full,
         * data is sent to Collectors. */
        ops_sflow_write_sampled_pkt(pkt);
    }

    return OPENNSL_RX_HANDLED;
}

int
ops_rx_init(int unit)
{
    opennsl_error_t  rc = OPENNSL_E_NONE;
    opennsl_rx_cfg_t rx_cfg;

    rc = opennsl_rx_register(unit,
                            "opennsl rx callback function",
                            opennsl_rx_callback,
                            100,    /* Relative priority of callback. 0 is lowest */
                            NULL,   /* No data is passed to callback. */
                            -1);

    /* Get the current RX config settings. */
    (void)opennsl_rx_cfg_get(unit, &rx_cfg);

    /* Set a global rate limit on number of RX pkts per second. */
    rx_cfg.global_pps = OPS_RX_GLOBAL_PPS;

    rc = opennsl_rx_start(unit, &rx_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to start BCM RX subsystem. unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    /* Always strip CRC from the incoming packet. */
    rc = opennsl_rx_control_set(unit, opennslRxControlCRCStrip, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set BCM RX control option. unit=%d rc=%s ",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    return 0;

} // ops_rx_init

int
ops_bcm_appl_init(void)
{
    int unit = 0;
    int rc = 0;

    ops_debug_init();

    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {

        rc = ops_port_init(unit);
        if (rc) {
            VLOG_ERR("Port subsystem init failed");
            return 1;
        }

        rc = ops_vlan_init(unit);
        if (rc) {
            VLOG_ERR("VLAN subsystem init failed");
            return 1;
        }

        rc = ops_rx_init(unit);
        if (rc) {
            VLOG_ERR("RX subsystem init failed");
            return 1;
        }

        rc = ops_knet_init(unit);
        if (rc) {
            VLOG_ERR("KNET subsystem init failed");
            return 1;
        }

        rc = ops_l3_init(unit);
        if (rc) {
            VLOG_ERR("L3 subsystem init failed");
            return 1;
        }

        rc = ops_sflow_init(unit);
        if (rc) {
            VLOG_ERR("sflow init failed");
            return 1;
        }
    }

    return 0;

} // ops_bcm_appl_init

int
ops_switch_main(int argc, char *argv[])
{
    opennsl_error_t rv;

    VLOG_INFO("Initializing OpenNSL driver.");

    /* Initialize the system. */
    rv = opennsl_driver_init();

    if (rv != OPENNSL_E_NONE) {
        VLOG_ERR("Failed to initialize the system.  rc=%s",
                 opennsl_errmsg(rv));
        return rv;
    }

    VLOG_INFO("OpenNSL driver init complete");

    if (ops_bcm_appl_init() != 0) {
        VLOG_ERR("OpenSwitch BCM application init failed!");
        return 1;
    }

    /* Let OVS know that BCM initialization is complete. */
    ovs_bcm_init_done();

#ifndef CDP_EXCLUDE
    opennsl_driver_shell();
    VLOG_INFO("OpenNSL BCM shell initialized");
#endif

    return 0;
}
