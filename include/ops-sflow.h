/*
 * (C) Copyright 2015-2016 Hewlett Packard Enterprise Development Company, L.P.
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
 * File: ops-sflow.h
 */

#ifndef __OPS_SFLOW_H__
#define __OPS_SFLOW_H__  1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <ofproto/ofproto.h>

#include <openvswitch/vlog.h>

#include <ovs/unixctl.h>
#include <ovs/dynamic-string.h>
#include <ovs/util.h>
#include <ovs/hmap.h>
#include <ovs/shash.h>
#include <ovs-thread.h>

#include <shared/pbmp.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/port.h>
#include <opennsl/rx.h>

#include <sflow.h>
#include <sflow_api.h>

#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h> /* for htonl */

#include "ops-knet.h"

#ifdef SFLOW_DO_SOCKET
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#endif

#include <net/if.h>

#define SFLOW_COLLECTOR_DFLT_PORT   "6343"

/* sFlow parameters */
extern SFLAgent *ops_sflow_agent;
extern struct ofproto_sflow_options *sflow_options;

/* sFlow knet filter id's */
extern int knet_sflow_source_filter_id;
extern int knet_sflow_dest_filter_id;

extern int opennsl_port_sample_rate_set(int unit, int port, int ingress_rate, int egress_rate);
extern int opennsl_port_sample_rate_get(int unit, int port, int *ingress_rate, int *egress_rate);

extern int ops_sflow_init(int unit);
extern void ops_sflow_write_sampled_pkt(opennsl_pkt_t *pkt);
extern void print_pkt(const opennsl_pkt_t *pkt);

extern void ops_sflow_agent_enable();
extern void ops_sflow_agent_disable();

extern bool
ops_sflow_options_equal(const struct ofproto_sflow_options *oso1,
                        const struct ofproto_sflow_options *oso2);

extern void
ops_sflow_set_sampling_rate(const int unit, const int port,
                            const int ingress_rate, const int egress_rate);

extern void ops_sflow_set_collector_ip(const char *ip, const char *port);

extern void
ops_sflow_agent_ip(const char *ip, const int af);

extern void
ops_sflow_set_per_interface (const int unit, const int port, bool set);

#endif /* __OPS_SFLOW_H__ */
