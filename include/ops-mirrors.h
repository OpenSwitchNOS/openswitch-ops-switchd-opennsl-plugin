/*
 * Copyright (C) 2016 Hewlett-Packard Enterprise Company, L.P.
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
 * File: ops-mirrors.h
 *
 * Purpose: This file has code to manage mirrors/span sessions for
 *          BCM hardware.  It uses the opennsl interface for all
 *          hw related operations.
 */

#ifndef __OPS_MIRRORS_H__
#define __OPS_MIRRORS_H__ 1

#include <inttypes.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/switch.h>
#include <opennsl/mirror.h>

/* should all the extra mirroring debugging be turned on */
extern bool mirror_debug_on;

/* where all mirroring debugging is written into */
extern char *mirror_debug_file;

extern void
debug_module(char *filename, char *source_file, const char *function_name,
    int line_number, char *fmt, ...);

#define DEBUG_MODULE(debug_flag, file, fmt, args...) \
    if (debug_flag) { \
        debug_module(file, __FILE__, __FUNCTION__, __LINE__, fmt, ## args); \
    }

#define DEBUG_MIRROR(fmt, args...) \
    DEBUG_MODULE(mirror_debug_on, mirror_debug_file, fmt, ## args)

#define ERROR_MIRROR    DEBUG_MIRROR

/*
 * these turn off private mirror debugging and error logging
 * and turns on the 'standard' vlogging mechanism.  For final
 * release, leave them intact.
 */
#undef DEBUG_MIRROR
#undef ERROR_MIRROR
#define DEBUG_MIRROR    VLOG_DBG
#define ERROR_MIRROR    VLOG_ERR

extern int
bcmsdk_mirrors_init(int unit);

extern int
bcmsdk_simple_port_mirror_endpoint_create(int unit, opennsl_port_t port,
        opennsl_mirror_destination_t *mdestp);

extern int
bcmsdk_lag_mirror_endpoint_create(opennsl_port_t lag_id,
        opennsl_mirror_destination_t *mdestp);

extern int
bcmsdk_mirror_associate_port(int unit, opennsl_port_t port, uint32 flags,
        opennsl_gport_t mdest_id);

extern int
bcmsdk_mirror_disassociate_port(int unit, opennsl_port_t port, uint32 flags,
        opennsl_gport_t mdest_id);

extern int
bcmsdk_mirror_endpoint_destroy(int unit, opennsl_gport_t mirror_endpoint_id);

#endif /* __OPS_MIRRORS_H__ */
