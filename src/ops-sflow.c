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
 * File: ops-sflow.c
 *
 * Purpose: sflow configuration implementation in BCM shell and show output.
 */

#include "ops-sflow.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SFLOW_DFLT_AGENT_IP4        "10.10.10.1"
#define SFLOW_DFLT_COLLECTOR_IP4    "20.20.20.2"

VLOG_DEFINE_THIS_MODULE(ops_sflow);

/* sFlow parameters */
SFLAgent *ops_sflow_agent;
struct ofproto_sflow_options *sflow_options;

static struct ovs_mutex mutex;

/* callbacks registered during sFlow initialization; used for various
 * utilities.
 */
void *
ops_sflow_agent_alloc_cb(void *magic OVS_UNUSED,
                        SFLAgent *ops_agent OVS_UNUSED,
                        size_t sz)
{
    return xmalloc(sz);
}

int
ops_sflow_agent_free_cb(void *magic OVS_UNUSED,
                        SFLAgent *ops_agent OVS_UNUSED,
                        void *obj)
{
    free(obj);
    return 0;
}

void
ops_sflow_agent_error_cb(void *magic OVS_UNUSED, SFLAgent *ops_agent OVS_UNUSED,
                        char *err)
{
    VLOG_ERR("%s", err);
}

void
print_pkt(const opennsl_pkt_t *pkt)
{
    uint8   i;

    if (!pkt)
        return;

    VLOG_ERR("[%s:%d]; # of blocks=%d, pkt_len=%d, tot_len=%d",
            __FUNCTION__, __LINE__, pkt->blk_count,
            pkt->pkt_len, pkt->tot_len);

    VLOG_ERR("[%s:%d]; vlan=%d, src_port=%d, dest_port=%d, "
            "rx_port=%d, untagged=%d, vtag0=%d, vtag1=%d, "
            "vtag2=%d, vtag3=%d", __FUNCTION__, __LINE__,
            pkt->vlan, pkt->src_port, pkt->dest_port, pkt->rx_port,
            pkt->rx_untagged, pkt->_vtag[0], pkt->_vtag[1],
            pkt->_vtag[2], pkt->_vtag[3]);

    for(i=0; i<pkt->blk_count; i++) {
        VLOG_ERR("[%s:%d]; blk num=%d, blk len=%d", __FUNCTION__, __LINE__,
                i, pkt->pkt_data[i].len);

        /* print only 18 bytes:
         *  6 bytes DMAC
         *  6 bytes SMAC
         *  4 bytes 802.1q
         *  2 bytes Ethernet Hdr
         */
            VLOG_ERR("%02X %02X %02X %02X %02X %02X "
                    "%02X %02X %02X %02X %02X %02X "
                    "%02X %02X %02X %02X %02X %02X ",
                    pkt->pkt_data[i].data[0], pkt->pkt_data[i].data[1],
                    pkt->pkt_data[i].data[2], pkt->pkt_data[i].data[3],
                    pkt->pkt_data[i].data[4], pkt->pkt_data[i].data[5],
                    pkt->pkt_data[i].data[6], pkt->pkt_data[i].data[7],
                    pkt->pkt_data[i].data[8], pkt->pkt_data[i].data[9],
                    pkt->pkt_data[i].data[10], pkt->pkt_data[i].data[11],
                    pkt->pkt_data[i].data[12], pkt->pkt_data[i].data[13],
                    pkt->pkt_data[i].data[14], pkt->pkt_data[i].data[15],
                    pkt->pkt_data[i].data[16], pkt->pkt_data[i].data[17]);
    }
}

/* Fn to write received sample pkt to buffer. Wrapper for
 * sfl_sampler_writeFlowSample() routine. */
void ops_sflow_write_sampled_pkt(opennsl_pkt_t *pkt)
{
    SFL_FLOW_SAMPLE_TYPE    fs;
    SFLFlow_sample_element  hdrElem;
    SFLSampled_header       *header;
    SFLSampler              *sampler;

    if (!pkt) {
        VLOG_ERR("%s:%d; NULL sFlow pkt received.", __FUNCTION__, __LINE__);
        return;
    }

    /* sFlow Agent is uninitialized. Error condition or it's not enabled
     * yet. */
    if (ops_sflow_agent == NULL) {
        VLOG_ERR("sFlow Agent uninitialized.");
        return;
    }

    sampler = ops_sflow_agent->samplers;
    if (!sampler) {
        VLOG_ERR("Sampler on sFlow Agent uninitialized.");
        return;
    }

    ovs_mutex_lock(&mutex);

    memset(&fs, 0, sizeof fs);

    /* Sampled header. */
    /* Code from ofproto-dpif-sflow.c */
    memset(&hdrElem, 0, sizeof hdrElem);
    hdrElem.tag = SFLFLOW_HEADER;
    header = &hdrElem.flowType.header;
    header->header_protocol = SFLHEADER_ETHERNET_ISO8023;

    /* The frame_length is original length of packet before it was sampled
     * (tot_len).
     */
    header->frame_length = pkt->tot_len;

    /* Ethernet FCS stripped off. */
    header->stripped = 4;
    header->header_length = MIN(header->frame_length,
                                sampler->sFlowFsMaximumHeaderSize);

    /* TODO: OpenNSL saves incoming data blocks as an array of structs
     * (containing {len, data} pairs). Is pointing 'header_bytes' to
     * beginning of this array sufficient? */
    header->header_bytes = (uint8_t *)pkt->pkt_data;

    /* Submit the flow sample to be encoded into the next datagram. */
    SFLADD_ELEMENT(&fs, &hdrElem);
    sfl_sampler_writeFlowSample(sampler, &fs);

    ovs_mutex_unlock(&mutex);
}

static void
ops_sflow_set (struct unixctl_conn *conn, int argc, const char *argv[],
              void *aux OVS_UNUSED)
{
    int rc;
    int ingress_rate, egress_rate;
    int port;

    int unit=0;
    opennsl_port_t tempPort = 0;
    opennsl_port_config_t port_config;
    SFLSampler  *sampler;

    bcm_port_config_t_init(&port_config);

    /* Retrieve the port configuration of the unit */
    rc = opennsl_port_config_get (unit, &port_config);
    if (rc == -1) {
        VLOG_ERR("[%s:%d]: Failed to retrieve port config", __FUNCTION__, __LINE__);
        goto done;
    }

    if (strncmp(argv[1], "global", 6) == 0) {
        port = 0;   /* invalid port # */
    } else {
        port = atoi(argv[1]);
    }

    ingress_rate = atoi(argv[2]);
    egress_rate = atoi(argv[3]);


    if (port) {
        rc = opennsl_port_sample_rate_set(0, port, ingress_rate, egress_rate);
    } else { /* set globally, on all ports */
        /* Iterate over all front-panel (e - ethernet) ports */
        OPENNSL_PBMP_ITER (port_config.e, tempPort) {
            opennsl_port_sample_rate_set(unit, tempPort, ingress_rate,
                                    egress_rate);
        }
    }

    /* set sampling rate on Sampler corresponding to 'port' */
    if (ops_sflow_agent) {
        sampler = ops_sflow_agent->samplers;

        if (sampler == NULL) {
            VLOG_ERR("[%s:%d]: There is no Sampler for port: %d", __FUNCTION__, __LINE__, port);
            goto done;
        }

        /* TODO: ingress rate or egress rate? Pick ingress, for now. */
        sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, ingress_rate);
    }

done:
    unixctl_command_reply(conn, '\0');
}

static void
ops_sflow_show (struct unixctl_conn *conn, int argc, const char *argv[],
              void *aux OVS_UNUSED)
{
    int rc, idx;
    struct ds ds = DS_EMPTY_INITIALIZER;
    int ingress_rate, egress_rate;
    int port=OPS_TOTAL_PORTS_AS5712;

    if (argc > 1) {
        port = atoi(argv[1]);
    }

    ds_put_format(&ds, "\t\t SFLOW SETTINGS\n");
    ds_put_format(&ds, "\t\t ==============\n");

    ds_put_format(&ds, "\tPORT\tINGRESS RATE\tEGRESS RATE\n");
    ds_put_format(&ds, "\t====\t============\t===========\n");

    if (argc > 1) { /* sflow for specific port */
        rc = opennsl_port_sample_rate_get(0, port, &ingress_rate, &egress_rate);
        if (rc == 0) {
        }

        ds_put_format(&ds, "\t%2d\t%6d\t%6d\n", port, ingress_rate, egress_rate);
    } else { /* sflow on all ports of switch */
        for(idx = 1; idx <= port; idx++) {
            rc = opennsl_port_sample_rate_get(0, idx, &ingress_rate, &egress_rate);
            if (rc == 0) {
            }

            ds_put_format(&ds, "\t%2d\t%6d\t%6d\n", idx, ingress_rate, egress_rate);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
ops_sflow_options_init(struct ofproto_sflow_options *oso)
{
    sset_init(&(oso->targets)); // 'targets' is not used in Dill sprint.
    oso->sampling_rate = SFL_DEFAULT_SAMPLING_RATE;
    oso->polling_interval = SFL_DEFAULT_POLLING_INTERVAL;
    oso->header_len = SFL_DEFAULT_HEADER_SIZE;
    oso->control_ip = NULL;
}

/* Initial creation of sFlow Agent. Creates an Agent only once. */
SFLAgent *
ops_sflow_create(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    SFLAgent *sfl_agent;

    if (ovsthread_once_start(&once)) {
        ovs_mutex_init_recursive(&mutex);
        ovsthread_once_done(&once);
    }

    sfl_agent = xmalloc(sizeof (SFLAgent));
    return sfl_agent;
}

/* Setup an sFlow Agent. For now, have only one receiver/sampler/poller and
 * enhance later. 'oso' is used to feed Agent fields. For first time, 'oso'
 * is NULL.
 *
 * TODO: Make sure sFlow Agent is created only once. Look in to
 * dpif_sflow_create() which uses ovs_thread_once() construct.
 */
static void
ops_sflow_enable_agent ()
{
    SFLReceiver *receiver;
    SFLSampler  *sampler;
    SFLDataSource_instance dsi;
    SFLAddress  agentIP, receiverIP;
    struct in_addr myIP;
    uint32_t    dsIndex;
    time_t      now;

    if(!sflow_options) {
        VLOG_ERR("ofproto_sflow_options is NULL");
        sflow_options = xmalloc(sizeof *sflow_options);
        memset (sflow_options, 0, sizeof *sflow_options);
        ops_sflow_options_init(sflow_options);
    }

    /* create/enable sFlow Agent */
    if (!ops_sflow_agent) {
        ops_sflow_agent = ops_sflow_create();
    } else {
        VLOG_ERR("sFlow Agent is already created/running.");
        return;
    }

    agentIP.type = SFLADDRESSTYPE_IP_V4;

    memset(&myIP, 0, sizeof myIP);
    // Agents' source IP. Sent in pkt shipped to Collectors.
    // TODO: Hardcoded. Get IP address from agent interface name provided!
    if (inet_aton(SFLOW_DFLT_AGENT_IP4, &myIP) == 0) {
       VLOG_ERR("Invalid src IP for sFlow Agent. Assign 0 and proceed.");
    }
    agentIP.address.ip_v4.addr = myIP.s_addr;

    time (&now);    // current time.

    /* AGENT: init sFlow Agent */
    sfl_agent_init(ops_sflow_agent, /* global instance of sFlow Agent */
            &agentIP,   /* Agents src IP */
            sflow_options->sub_id,
            now,    /* Boot time */
            now,    /* Current time (same as Boot time) */
            0,      /* TODO: Unclear how 'magic' param is used. Setting to 0 for now. */
            ops_sflow_agent_alloc_cb,
            ops_sflow_agent_free_cb,
            ops_sflow_agent_error_cb,
            NULL);  /* Each receiver will send pkts to collector. */

    /* TODO: May be Receiver should not be added when sFlow Agent is
     * created. Perhaps it should be added only when collector ip is
     * explicitly configured. */
    /* RECEIVER: aka Collector */
    receiver = sfl_agent_addReceiver(ops_sflow_agent);
    sfl_receiver_set_sFlowRcvrOwner(receiver, "Openswitch sFlow Receiver");
    sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xffffffff);

    memset(&myIP, 0, sizeof myIP);
    if (inet_aton(SFLOW_DFLT_COLLECTOR_IP4, &myIP) == 0) {
       VLOG_ERR("Invalid receiver IP. Assign 0 and proceed.");
    }
    receiverIP.type = SFLADDRESSTYPE_IP_V4;
    receiverIP.address.ip_v4.addr = myIP.s_addr;

    sfl_receiver_set_sFlowRcvrAddress(receiver, &receiverIP);

    /* SAMPLER: OvS lib for sFlow seems to encourage one Sampler per
     * interface. Currently, OPS will have only one Sampler for all
     * interfaces. This may change when per-interface sampling is enabled. */
    dsIndex = 1000 + sflow_options->sub_id;
    SFL_DS_SET(dsi, SFL_DSCLASS_PHYSICAL_ENTITY, dsIndex, 0);
    sampler = sfl_agent_addSampler(ops_sflow_agent, &dsi);

    sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, SFL_DEFAULT_SAMPLING_RATE);
    sfl_sampler_set_sFlowFsMaximumHeaderSize(sampler, SFL_DEFAULT_HEADER_SIZE);
    sfl_sampler_set_sFlowFsReceiver(sampler, 1);

    VLOG_ERR("%s:%d; sFlow Agent Created!!!", __FUNCTION__, __LINE__);
}

static void
ops_sflow_enable(struct unixctl_conn *conn, int argc, const char *argv[],
                void *aux OVS_UNUSED)
{
    if (strncmp(argv[1], "yes", 3) == 0) {
        ops_sflow_enable_agent();
    } else if (strncmp(argv[1], "no", 2) == 0) {
        sfl_agent_release(ops_sflow_agent);

    } else {
        /* Error condition */
    }

    unixctl_command_reply(conn, '\0');
}

/* Equivalent of '[no] sflow agent-interface <intf-name>' */
static void
ops_sflow_agent_intf(struct unixctl_conn *conn, int argc, const char *argv[],
                    void *aux OVS_UNUSED)
{
    /* TODO: Need to figure out to get IP from interface name (in OVSDB).
     * Currently, hard coded to IPv4. */

    struct in_addr addr;
    SFLAddress  myIP;

    if (!ops_sflow_agent) {
        VLOG_ERR("%s:%d; sFlow Agent is not running. Can't set Agent Address.",
                __FUNCTION__, __LINE__);
        goto done;
    }

    memset(&addr, 0, sizeof addr);
    memset(&myIP, 0, sizeof myIP);

    /* TODO: Hardcoded. Get IP address from interface name (argv[1]) */
    if (inet_pton(AF_INET, "10.10.10.1", &addr) <= 0) {
        VLOG_ERR("%s:%d; Invalid interface address. Failed to assign IP.",
                __FUNCTION__, __LINE__);
        goto done;
    }

    myIP.type = SFLADDRESSTYPE_IP_V4;
    myIP.address.ip_v4.addr = addr.s_addr;

    sfl_agent_set_agentAddress(ops_sflow_agent, &myIP);

    VLOG_ERR("%s:%d; Successfully set sFlow Agent Address to=%s",
            __FUNCTION__, __LINE__, "10.10.10.1");

done:
    unixctl_command_reply(conn, '\0');
}

/* This function creates a receiver and sets an IP for it. */
static void
ops_sflow_set_collector_ip(struct unixctl_conn *conn, int argc, const char *argv[],
                        void *aux OVS_UNUSED)
{
    SFLReceiver *receiver;
    SFLAddress  receiverIP;
    struct in_addr myIP;
    struct in6_addr myIP6;

    if (ops_sflow_agent == NULL) {
        VLOG_ERR("sFlow Agent uninitialized.");
        goto done;
    }

    receiver = sfl_agent_addReceiver(ops_sflow_agent);
    sfl_receiver_set_sFlowRcvrOwner(receiver, "Openswitch sFlow Receiver");
    sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xffffffff);

    /* v6 address */
    if (strchr(argv[1], ':')) {
        memset(&myIP6, 0, sizeof myIP6);
        if (inet_pton(AF_INET6, argv[1], &myIP6) < 0) {
            VLOG_ERR("Invalid collector IP:%s", argv[1]);
            goto done;
        }
        receiverIP.type = SFLADDRESSTYPE_IP_V6;
        memcpy(receiverIP.address.ip_v6.addr, myIP6.s6_addr, 16);
    } else { /* v4 address */
        memset(&myIP, 0, sizeof myIP);
        if (inet_pton(AF_INET, argv[1], &myIP) < 0) {
            VLOG_ERR("Invalid collector IP:%s", argv[1]);
            goto done;
        }
        receiverIP.type = SFLADDRESSTYPE_IP_V4;
        receiverIP.address.ip_v4.addr = myIP.s_addr;
    }

    sfl_receiver_set_sFlowRcvrAddress(receiver, &receiverIP);

done:
    unixctl_command_reply(conn, '\0');
}

/* Send a UDP pkt to collector ip (input) on a port (optional input, default
 * port is 6343). Test purposes only. */
    static void
ops_sflow_send_test_pkt(struct unixctl_conn *conn, int argc, const char *argv[],
        void *aux OVS_UNUSED)
{
#define SFLOWPORT "6343" // default sflow port
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int numbytes;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Any protocol type works.
    hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo(argv[1], (argv[2]?argv[2]:SFLOWPORT), &hints, &servinfo)) != 0) {
        VLOG_ERR("getaddrinfo: %s\n", gai_strerror(rv));
        goto done;
    }

    // loop through all the results and make a socket
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                        p->ai_protocol)) == -1) {
            VLOG_ERR("talker: socket failed");
            continue;
        }
        break;
    }

    if (p == NULL) {
        VLOG_ERR("talker: failed to bind socket\n");
        goto done;
    }

    if ((numbytes = sendto(sockfd, "Hello", 5, 0, p->ai_addr,
                    p->ai_addrlen)) == -1) {
        VLOG_ERR("talker: sendto");
        goto done;
    }

    freeaddrinfo(servinfo);
    VLOG_ERR("talker: sent %d bytes to %s\n", numbytes, argv[1]);
    close(sockfd);

done:
    unixctl_command_reply(conn, '\0');
}

static void sflow_main()
{
    unixctl_command_register("sflow/set-rate", "[port-id | global] ingress-rate egress-rate", 3, 3, ops_sflow_set, NULL);
    unixctl_command_register("sflow/show-rate", "[port-id]", 0 , 1, ops_sflow_show, NULL);

    unixctl_command_register("sflow/enable-agent", "[yes|no]", 1 , 1, ops_sflow_enable, NULL);
    unixctl_command_register("sflow/set-collector-ip", "collector-ip [port]", 1 , 2, ops_sflow_set_collector_ip, NULL);
    unixctl_command_register("sflow/send-test-pkt", "collector-ip [port]", 1 , 2, ops_sflow_send_test_pkt, NULL);
    unixctl_command_register("sflow/agent-interface", "[add interface-name | delete]", 1 , 2, ops_sflow_agent_intf, NULL);
}

///////////////////////////////// INIT /////////////////////////////////

int
ops_sflow_init (int unit OVS_UNUSED)
{
    /* TODO: Make this in to a thread so as to read messages from callback
     * function in Rx thread. */

    sflow_main();

    return 0;
}
