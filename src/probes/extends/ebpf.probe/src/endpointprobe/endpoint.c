/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: algorithmofdish
 * Create: 2021-10-25
 * Description: endpoint_probe user prog
 ******************************************************************************/
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include <bpf/bpf.h>
#include "bpf.h"
#include "args.h"
#include "tcp.skel.h"
#include "udp.skel.h"
#include "endpoint.h"
#include "tcp.h"
#include "event.h"

#define EP_ENTITY_ID_LEN 64

#define OO_NAME     "endpoint"

#define LISTEN_TBL_NAME     "listen"
#define CONNECT_TBL_NAME    "connect"
#define BIND_TBL_NAME       "bind"
#define UDP_TBL_NAME        "udp"

#define ENDPOINT_PATH "/sys/fs/bpf/probe/__endpoint_sock"
#define OUTPUT_PATH "/sys/fs/bpf/probe/__endpoint_output"
#define ARGS_PATH "/sys/fs/bpf/probe/__endpoint_args"
#define RM_BPF_PATH "/usr/bin/rm -rf /sys/fs/bpf/probe/__endpoint*"

#define __LOAD_ENDPOINT_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, g_endpoint_map, ENDPOINT_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_ep_output, OUTPUT_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, args_map, ARGS_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

static struct probe_params params = {.period = DEFAULT_PERIOD};

static void print_tcp_listen_metrics(struct endpoint_val_t *value)
{
    fprintf(stdout,
            "|%s|%d|%s|%d|%s|%lu|%lu|%lu|%lu|%lu|%lu|\n",
            LISTEN_TBL_NAME,
            value->key.key.tcp_listen_key.tgid,
            "*",
            value->key.key.tcp_listen_key.port,
            LISTEN_TBL_NAME,
            value->ep_stats.stats[EP_STATS_LISTEN_DROPS],
            value->ep_stats.stats[EP_STATS_ACCEPT_OVERFLOW],
            value->ep_stats.stats[EP_STATS_SYN_OVERFLOW],
            value->ep_stats.stats[EP_STATS_PASSIVE_OPENS],
            value->ep_stats.stats[EP_STATS_PASSIVE_FAILS],
            value->ep_stats.stats[EP_STATS_RETRANS_SYNACK]);
}

static void print_tcp_connect_metrics(struct endpoint_val_t *value)
{
    unsigned char s_addr[INET6_ADDRSTRLEN];
    ip_str(value->key.key.tcp_connect_key.ip_addr.family, 
           (unsigned char *)&(value->key.key.tcp_connect_key.ip_addr.ip), 
           s_addr, 
           INET6_ADDRSTRLEN);
    fprintf(stdout,
            "|%s|%d|%s|%d|%s|%lu|%lu|\n",
            CONNECT_TBL_NAME,
            value->key.key.tcp_connect_key.tgid,
            s_addr,
            0,
            CONNECT_TBL_NAME,
            value->ep_stats.stats[EP_STATS_ACTIVE_OPENS],
            value->ep_stats.stats[EP_STATS_ACTIVE_FAILS]);
}

static void print_bind_metrics(struct endpoint_val_t *value)
{
    unsigned char s_addr[INET6_ADDRSTRLEN];
    ip_str(value->key.key.udp_server_key.ip_addr.family, 
           (unsigned char *)&(value->key.key.udp_server_key.ip_addr.ip), 
           s_addr, 
           INET6_ADDRSTRLEN);
    fprintf(stdout,
            "|%s|%d|%s|%d|%s|%lu|%lu|%lu|%d|\n",
            BIND_TBL_NAME,
            value->key.key.udp_server_key.tgid,
            s_addr,
            0,
            BIND_TBL_NAME,
            value->ep_stats.stats[EP_STATS_QUE_RCV_FAILED],
            value->ep_stats.stats[EP_STATS_UDP_SENDS],
            value->ep_stats.stats[EP_STATS_UDP_RCVS],
            value->udp_err_code);
}

static void print_udp_metrics(struct endpoint_val_t *value)
{
    unsigned char s_addr[INET6_ADDRSTRLEN];
    ip_str(value->key.key.udp_client_key.ip_addr.family, 
           (unsigned char *)&(value->key.key.udp_client_key.ip_addr.ip), 
           s_addr, 
           INET6_ADDRSTRLEN);
    fprintf(stdout,
            "|%s|%d|%s|%d|%s|%lu|%lu|%lu|%d|\n",
            UDP_TBL_NAME,
            value->key.key.udp_client_key.tgid,
            s_addr,
            0,
            UDP_TBL_NAME,
            value->ep_stats.stats[EP_STATS_QUE_RCV_FAILED],
            value->ep_stats.stats[EP_STATS_UDP_SENDS],
            value->ep_stats.stats[EP_STATS_UDP_RCVS],
            value->udp_err_code);
}

static void build_entity_id(struct endpoint_val_t *ep, char *buf, int buf_len)
{
    unsigned char s_addr[INET6_ADDRSTRLEN];

    if (ep->key.type == SK_TYPE_LISTEN_TCP) {
        (void)snprintf(buf, buf_len, "%d_%s_%d_%s",
                        ep->key.key.tcp_listen_key.tgid,
                        "*",
                        ep->key.key.tcp_listen_key.port,
                        LISTEN_TBL_NAME);
    } else if (ep->key.type == SK_TYPE_CLIENT_TCP) {
        ip_str(ep->key.key.tcp_connect_key.ip_addr.family, 
               (unsigned char *)&(ep->key.key.tcp_connect_key.ip_addr.ip), 
               s_addr, 
               INET6_ADDRSTRLEN);
        (void)snprintf(buf, buf_len, "%d_%s_%d_%s",
                        ep->key.key.tcp_connect_key.tgid,
                        s_addr,
                        0,
                        CONNECT_TBL_NAME);
    } else if (ep->key.type == SK_TYPE_LISTEN_UDP) {
        ip_str(ep->key.key.udp_server_key.ip_addr.family, 
               (unsigned char *)&(ep->key.key.udp_server_key.ip_addr.ip), 
               s_addr, 
               INET6_ADDRSTRLEN);
        (void)snprintf(buf, buf_len, "%d_%s_%d_%s",
                        ep->key.key.udp_server_key.tgid,
                        s_addr,
                        0,
                        BIND_TBL_NAME);
    } else {
        ip_str(ep->key.key.udp_client_key.ip_addr.family, 
               (unsigned char *)&(ep->key.key.udp_client_key.ip_addr.ip), 
               s_addr, 
               INET6_ADDRSTRLEN);
        (void)snprintf(buf, buf_len, "%d_%s_%d_%s",
                        ep->key.key.udp_client_key.tgid,
                        s_addr,
                        0,
                        UDP_TBL_NAME);
    }
}

static void report_ep(struct endpoint_val_t *ep)
{
    char entityId[EP_ENTITY_ID_LEN];

    if (params.logs == 0)
        return;

    entityId[0] = 0;
    if (ep->ep_stats.stats[EP_STATS_LISTEN_DROPS] != 0) {
        build_entity_id(ep, entityId, EP_ENTITY_ID_LEN);
        report_logs(OO_NAME,
                    entityId,
                    "listendrop",
                    EVT_SEC_WARN,
                    "TCP listen drops(%lu).",
                    ep->ep_stats.stats[EP_STATS_LISTEN_DROPS]);
    }

    if (ep->ep_stats.stats[EP_STATS_ACCEPT_OVERFLOW] != 0) {
        if (entityId[0] != 0)
            build_entity_id(ep, entityId, EP_ENTITY_ID_LEN);

        report_logs(OO_NAME,
                    entityId,
                    "accept_overflow",
                    EVT_SEC_WARN,
                    "TCP accept queue overflow(%lu).",
                    ep->ep_stats.stats[EP_STATS_ACCEPT_OVERFLOW]);
    }

    if (ep->ep_stats.stats[EP_STATS_SYN_OVERFLOW] != 0) {
        if (entityId[0] != 0)
            build_entity_id(ep, entityId, EP_ENTITY_ID_LEN);

        report_logs(OO_NAME,
                    entityId,
                    "syn_overflow",
                    EVT_SEC_WARN,
                    "TCP syn queue overflow(%lu).",
                    ep->ep_stats.stats[EP_STATS_SYN_OVERFLOW]);
    }

    if (ep->ep_stats.stats[EP_STATS_PASSIVE_FAILS] != 0) {
        if (entityId[0] != 0)
            build_entity_id(ep, entityId, EP_ENTITY_ID_LEN);

        report_logs(OO_NAME,
                    entityId,
                    "passive_open_failed",
                    EVT_SEC_WARN,
                    "TCP passive open failed(%lu).",
                    ep->ep_stats.stats[EP_STATS_PASSIVE_FAILS]);
    }

    entityId[0] = 0;
    if (ep->ep_stats.stats[EP_STATS_ACTIVE_FAILS] != 0) {
        build_entity_id(ep, entityId, EP_ENTITY_ID_LEN);
        report_logs(OO_NAME,
                    entityId,
                    "active_open_failed",
                    EVT_SEC_WARN,
                    "TCP active open failed(%lu).",
                    ep->ep_stats.stats[EP_STATS_ACTIVE_FAILS]);
    }

    entityId[0] = 0;
    if (ep->ep_stats.stats[EP_STATS_QUE_RCV_FAILED] != 0) {
        build_entity_id(ep, entityId, EP_ENTITY_ID_LEN);

        if (ep->key.type == SK_TYPE_LISTEN_UDP) {
            report_logs(OO_NAME,
                        entityId,
                        "bind_rcv_drops",
                        EVT_SEC_WARN,
                        "UDP(S) queue drops(%lu).",
                        ep->ep_stats.stats[EP_STATS_QUE_RCV_FAILED]);
        } else {
            report_logs(OO_NAME,
                        entityId,
                        "udp_rcv_drops",
                        EVT_SEC_WARN,
                        "UDP(C) queue drops(%lu).",
                        ep->ep_stats.stats[EP_STATS_QUE_RCV_FAILED]);
        }
    }
}

static void print_endpoint_metrics(void *ctx, int cpu, void *data, __u32 size)
{
    struct endpoint_val_t *value  = (struct endpoint_val_t *)data;
    if (value->key.type == SK_TYPE_LISTEN_TCP) {
        print_tcp_listen_metrics(value);
    } else if (value->key.type == SK_TYPE_CLIENT_TCP) {
        print_tcp_connect_metrics(value);
    } else if (value->key.type == SK_TYPE_LISTEN_UDP) {
        print_bind_metrics(value);
    } else {
        print_udp_metrics(value);
    }

    report_ep(value);
    (void)fflush(stdout);
}

static void load_args(int args_fd, struct probe_params* params)
{
    __u32 key = 0;
    struct endpoint_args_s args = {0};

    args.period = (__u64)params->period * 1000000000;
    args.filter_by_task = (__u32)params->filter_task_probe;
    args.filter_by_tgid = (__u32)params->filter_pid;

    (void)bpf_map_update_elem(args_fd, &key, &args, BPF_ANY);
}

static void load_listen_fd(int fd)
{
    struct tcp_listen_ports *tlps = NULL;
    struct tcp_listen_port *tlp = NULL;
    struct listen_sockfd_key_t listen_sockfd_key = {0};

    tlps = get_listen_ports();
    if (tlps == NULL) {
        return;
    }

    for (int i = 0; i < tlps->tlp_num; i++) {
        tlp = tlps->tlp[i];
        listen_sockfd_key.tgid = tlp->pid;
        listen_sockfd_key.fd = tlp->fd;
        (void)bpf_map_update_elem(fd, &listen_sockfd_key, &(tlp->fd), BPF_ANY);
    }

    free_listen_ports(&tlps);
    return;
}

int main(int argc, char **argv)
{
    int err = -1;
    int out_put_fd;
    const int load_udp = 1;
    struct perf_buffer* pb = NULL;
    FILE *fp = NULL;

    err = args_parse(argc, argv, &params);
    if (err != 0) {
        return -1;
    }
    printf("arg parse interval time:%us\n", params.period);
    fp = popen(RM_BPF_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
    }

    INIT_BPF_APP(endpoint, EBPF_RLIM_LIMITED);

    __LOAD_ENDPOINT_PROBE(tcp, err2, 1);
    __LOAD_ENDPOINT_PROBE(udp, err, load_udp);

    out_put_fd = GET_MAP_FD(tcp, g_ep_output);
    pb = create_pref_buffer(out_put_fd, print_endpoint_metrics);
    if (pb == NULL) {
        fprintf(stderr, "ERROR: crate perf buffer failed\n");
        goto err;
    }

    load_listen_fd(GET_MAP_FD(tcp, listen_sockfd_map));
    load_args(GET_MAP_FD(tcp, args_map), &params);

    printf("Successfully started!\n");
    poll_pb(pb, THOUSAND);

err:
    if (load_udp) {
        UNLOAD(udp);
    }
err2:
    UNLOAD(tcp);

    if (pb)
        perf_buffer__free(pb);

    return -err;
}
