
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
 * File: ops-mirrors.c
 *
 * Purpose: This file has code to manage mirrors/span sessions for
 *          BCM hardware.  It uses the opennsl interface for all
 *          hw related operations.
 */

#include <stdio.h>
#include <openvswitch/vlog.h>
#include "ops-mirrors.h"

VLOG_DEFINE_THIS_MODULE(ops_mirrors);

/* should all the extra mirroring debugging be turned on */
bool mirror_debug_on = true;

/* where all mirroring code debugging is written into */
char *mirror_debug_file = "/tmp/mirror_debug_file";

void
debug_module (char *debug_filename, char *source_file,
    const char *function_name, int line_number, char *fmt, ...)
{
    va_list args;
    FILE *fp;

    if (NULL == debug_filename) {
        debug_filename = "/tmp/default_debug_filename";
    }
    fp = fopen(debug_filename, "a");
    if (NULL == fp) {
        VLOG_ERR("OPENING DEBUG FILE <%s> FAILED: "
            "file %s, function %s, line %d",
            debug_filename, source_file, function_name, line_number);
        return;
    }
    fprintf(fp, "FUNCTION: %s LINE: %d\n    ", function_name, line_number);
    va_start(args, fmt);
    vfprintf(fp, fmt, args);
    va_end(args);
    fprintf(fp, "\n");
    fflush(fp);
    fclose(fp);
}

/*
 * Error return calls are all Linux errnos as close to
 * the meanings of the BCM SDK I can make them.
 */

/*
 * Always call this to initialize the mirroring subsystem
 */
int
bcmsdk_mirrors_init (int unit)
{
    opennsl_error_t rc;

    DEBUG_MIRROR("initializing mirroring/span subsystem");

    rc = opennsl_switch_control_set(unit, opennslSwitchDirectedMirroring, TRUE);
    if (OPENNSL_FAILURE(rc)) {
        DEBUG_MIRROR("opennsl_switch_control_set failed: unit %d: %s (%d)",
                unit, opennsl_errmsg(rc), rc);
        return 1;
    }

    rc = opennsl_mirror_init(unit);
    if (OPENNSL_FAILURE(rc)) {
        DEBUG_MIRROR("opennsl_mirror_init failed: unit %d: %s (%d)",
                unit, opennsl_errmsg(rc), rc);
        return 1;
    }

    DEBUG_MIRROR("mirroring subsystem succesfully initialized");
    return 0;
}

/*
 * Creates a mirror end point where the 'mirror to port' is a simple interface.
 */
int
bcmsdk_simple_port_mirror_endpoint_create (
        int unit,                               /* which chip the endpoint is at */
        opennsl_port_t port,                    /* port id */
        opennsl_mirror_destination_t *mdestp)   /* supplied by/returned to caller */
{
    opennsl_error_t rc;

    /* apparently this never fails */
    opennsl_mirror_destination_t_init(mdestp);

    rc = opennsl_port_gport_get(unit, port, &mdestp->gport);
    if (OPENNSL_FAILURE(rc)) {
        DEBUG_MIRROR("opennsl_port_gport_get failed: "
                 "unit %d port %d: %s (%d)",
                     unit, port, opennsl_errmsg(rc), rc);
        return 1;
    }

    rc = opennsl_mirror_destination_create(unit, mdestp);
    if (OPENNSL_FAILURE(rc)) {
        DEBUG_MIRROR("opennsl_mirror_destination_create failed: "
                 "unit %d port %d: %s (%d)",
                    unit, port, opennsl_errmsg(rc), rc);
        return 1;
    }

    return 0;
}

/*
 * Creates a mirror end point where the mirror to port is a lag.
 * Note that since a lag can stretch over multiple chips, there
 * is no 'unit' parameter in this case.
 */
int
bcmsdk_lag_mirror_endpoint_create (
        opennsl_port_t lag_id,                  /* port id */
        opennsl_mirror_destination_t *mdestp)   /* returned to caller */
{
    int rc;
    opennsl_gport_t gport = 0;

    /* apparently this never fails */
    opennsl_mirror_destination_t_init(mdestp);

    /* BCM_GPORT_TRUNK_SET(gport, lag_id); */

    mdestp->gport = gport;
    rc = opennsl_mirror_destination_create(0, mdestp);
    if (OPENNSL_FAILURE(rc)) {
        DEBUG_MIRROR("bcmsdk_lag_mirror_endpoint_create failed: lag id %d: %s (%d)",
                    lag_id, opennsl_errmsg(rc), rc);
        return 1;
    }

    return 0;
}

int
bcmsdk_mirror_associate_port (
        int unit,                   /* chip number of the port to be added */
        opennsl_port_t port,        /* port number */
        uint32 flags,               /* ingress, egress or both */
        opennsl_gport_t mdest_id)   /* mirror destination to add to */
{
    opennsl_error_t rc;

    rc = opennsl_mirror_port_dest_add(unit, port, flags, mdest_id);
    if (OPENNSL_FAILURE(rc)) {
        DEBUG_MIRROR("opennsl_mirror_port_dest_add failed: "
                 "unit %d port %d flags 0x%x mdest_id %d: %s (%d)",
                    unit, port, flags, mdest_id,
                    opennsl_errmsg(rc), rc);
        return 1;
    }

    return 0;
}

int
bcmsdk_mirror_disassociate_port (
        int unit,                       /* which unit the port is on */
        opennsl_port_t port,            /* port to be deleted */
        uint32 flags,                   /* which flags to be deleted with */
        opennsl_gport_t mdest_id)       /* which MTP to be deleted from */
{
    opennsl_error_t rc;

    rc = opennsl_mirror_port_dest_delete(unit, port, flags, mdest_id);
    if (OPENNSL_FAILURE(rc)) {
        DEBUG_MIRROR("opennsl_mirror_port_dest_delete failed: "
                 "unit %d port %d mdest_id %d: %s (%d) flags 0x%x",
                    unit, port, mdest_id,
                    opennsl_errmsg(rc), rc, flags);
        return 1;
    }

    return 0;
}

/*
 * Destroy a specified mirror endpoint.
 */
int
bcmsdk_mirror_endpoint_destroy (
        int unit,                       /* which chip the endpoint is */
        int mirror_endpoint_id)         /* the actual endpoint to be destroyed */
{
    opennsl_error_t rc;

    rc = opennsl_mirror_destination_destroy(unit, mirror_endpoint_id);
    if (OPENNSL_FAILURE(rc)) {
        DEBUG_MIRROR("opennsl_mirror_destination_destroy failed: "
                 "unit %d mirror_endpoint_id %d: %s (%d)",
                    unit, mirror_endpoint_id, opennsl_errmsg(rc), rc);
        return 1;
    }

    return 0;
}
