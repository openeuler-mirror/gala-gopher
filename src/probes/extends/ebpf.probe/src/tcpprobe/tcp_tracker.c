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
 * Author: sky
 * Create: 2021-05-22
 * Description: tcp_probe user prog
 ******************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <time.h>

#ifdef GOPHER_DEBUG
#include <arpa/inet.h>
#endif

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "ipc.h"
#include "conntrack.h"
#include "flowtracer_reader.h"
#include "tcpprobe.h"
#include "tcp_tracker.h"

#if 1

struct backend_ip_s {
    union ip_addr_u{
        u32 ip;
        unsigned char ip6[IP6_LEN];
    } ip_addr;
    u16 port;
    u16 family;
};

struct __tcp_histo_s tcp_wind_histios[__MAX_WIND_SIZE] = {
    {WIND_SIZE_1, 0, 1000},
    {WIND_SIZE_2, 1000, 10000},
    {WIND_SIZE_3, 10000, 100000},
    {WIND_SIZE_4, 100000, 1000000},
    {WIND_SIZE_5, 1000000, 10000000}
};

struct __tcp_histo_s tcp_sockbuf_histios[__MAX_SOCKBUF_SIZE] = {
    {SOCKBUF_SIZE_1, 0, 131072},
    {SOCKBUF_SIZE_2, 131072, 262144},
    {SOCKBUF_SIZE_3, 262144, 524288},
    {SOCKBUF_SIZE_4, 524288, 1048576},
    {SOCKBUF_SIZE_5, 1048576, 2097152},
    {SOCKBUF_SIZE_6, 2097152, 4194304},
    {SOCKBUF_SIZE_7, 4194304, 8388608},
    {SOCKBUF_SIZE_8, 8388608, 16777216}
};

struct __tcp_histo_s tcp_rtt_histios[__MAX_RTT_SIZE] = {
    {RTT_SIZE_1, 0, 50},
    {RTT_SIZE_2, 50, 100},
    {RTT_SIZE_3, 100, 200},
    {RTT_SIZE_4, 200, 500},
    {RTT_SIZE_5, 500, 1000}
};

struct __tcp_histo_s tcp_rto_histios[__MAX_RTO_SIZE] = {
    {RTO_SIZE_1, 0, 1000},
    {RTO_SIZE_2, 1000, 10000},
    {RTO_SIZE_3, 10000, 20000},
    {RTO_SIZE_4, 20000, 40000},
    {RTO_SIZE_5, 40000, 80000}
};

struct __tcp_histo_s tcp_delay_histios[__MAX_DELAY_SIZE] = {
    {DELAY_SIZE_1, 0, 1000000},
    {DELAY_SIZE_2, 1000000, 10000000},
    {DELAY_SIZE_3, 10000000, 100000000},
    {DELAY_SIZE_4, 100000000, 1000000000},
    {DELAY_SIZE_5, 1000000000, 10000000000}
};



struct toa_socket_s *create_toa_sock(const struct toa_sock_id_s *id)
{
    struct toa_socket_s *toa_sock = (struct toa_socket_s *) malloc(sizeof(struct toa_socket_s));
    if (toa_sock == NULL) {
        return NULL;
    }
    memset(toa_sock, 0, sizeof(struct toa_socket_s));
    memcpy(&(toa_sock->id), id, sizeof(struct toa_sock_id_s));
    return toa_sock;
}

#define TCP_TRACKER_MAX (4 * 1024)
static struct tcp_tracker_s* create_tcp_tracker(struct tcp_mng_s *tcp_mng, const struct tcp_tracker_id_s *id)
{
    unsigned char src_ip_str[INET6_ADDRSTRLEN];
    unsigned char dst_ip_str[INET6_ADDRSTRLEN];
    unsigned char toa_src_ip_str[INET6_ADDRSTRLEN];

    if (tcp_mng->tcp_tracker_count >= TCP_TRACKER_MAX) {
        ERROR("[TCPPROBE]: Create 'tcp_tracker' failed(upper to limited).\n");
        return NULL;
    }

    struct tcp_tracker_s* tracker = (struct tcp_tracker_s *)malloc(sizeof(struct tcp_tracker_s));
    if (tracker == NULL) {
        return NULL;
    }

    memset(tracker, 0, sizeof(struct tcp_tracker_s));
    memcpy(&(tracker->id), id, sizeof(struct tcp_tracker_id_s));

    ip_str(tracker->id.family, (unsigned char *)&(tracker->id.c_ip), src_ip_str, INET6_ADDRSTRLEN);
    ip_str(tracker->id.family, (unsigned char *)&(tracker->id.s_ip), dst_ip_str, INET6_ADDRSTRLEN);
    tracker->src_ip = strdup((const char *)src_ip_str);
    tracker->dst_ip = strdup((const char *)dst_ip_str);
    if (tracker->id.toa_famlily == AF_INET || tracker->id.toa_famlily == AF_INET6) {
        ip_str(tracker->id.toa_famlily, (unsigned char *)&(tracker->id.toa_c_ip), toa_src_ip_str, INET6_ADDRSTRLEN);
        tracker->toa_src_ip = strdup((const char *)toa_src_ip_str);
        if (!tracker->toa_src_ip) {
            goto err;
        }
    }

    if (tracker->src_ip == NULL || tracker->dst_ip == NULL) {
        goto err;
    }

    tracker->last_report = (time_t)time(NULL);
    tcp_mng->tcp_tracker_count++;
    return tracker;

err:
    destroy_tcp_tracker(tracker);
    return NULL;
}

struct toa_socket_s *lkup_toa_sock(struct tcp_mng_s *tcp_mng, const struct toa_sock_id_s *id)
{
    struct toa_socket_s *sock = NULL;
    H_FIND(tcp_mng->toa_socks, id, sizeof(struct toa_sock_id_s), sock);
    return sock;
}

static struct tcp_tracker_s* lkup_tcp_tracker(struct tcp_mng_s *tcp_mng, const struct tcp_tracker_id_s *id)
{
    struct tcp_tracker_s* tracker = NULL;

    H_FIND(tcp_mng->trackers, id, sizeof(struct tcp_tracker_id_s), tracker);
    return tracker;
}

static int __transform_cluster_ip(struct tcp_mng_s *tcp_mng, const struct tcp_link_s *tcp_link, struct tcp_connect_s *connect)
{
    int transform = ADDR_TRANSFORM_NONE;

    char cluster_ip_backend = tcp_mng->ipc_body.probe_param.cluster_ip_backend;
    if (cluster_ip_backend == 0) {  // transform is disabled
        return ADDR_TRANSFORM_NONE;
    }

    connect->role = tcp_link->role;
    connect->family = tcp_link->family;

    if (tcp_link->family == AF_INET) {
        connect->cip_addr.c_ip = tcp_link->c_ip;
        connect->sip_addr.s_ip = tcp_link->s_ip;
    } else {
        memcpy(&(connect->cip_addr), tcp_link->c_ip6, IP6_LEN);
        memcpy(&(connect->sip_addr), tcp_link->s_ip6, IP6_LEN);
    }

    connect->c_port = tcp_link->c_port;
    connect->s_port = tcp_link->s_port;

    if (cluster_ip_backend == 1) { // use conntrack
        // Only transform Kubernetes cluster IP backend for the client TCP connection.
        if (tcp_link->role == 0) {
            return ADDR_TRANSFORM_NONE;
        }
        (void)get_cluster_ip_backend(connect, &transform);
    } else if (cluster_ip_backend == 2) { // use FlowTracer
        transform = lookup_flowtracer(connect);
    }

    if (!transform) {
        return ADDR_TRANSFORM_NONE;
    }

#ifdef GOPHER_DEBUG
    char s_ip1[IP6_STR_LEN], s_ip2[IP6_STR_LEN], c_ip1[IP6_STR_LEN], c_ip2[IP6_STR_LEN];
    inet_ntop(tcp_link->family, &tcp_link->s_ip, s_ip1, sizeof(s_ip1));
    inet_ntop(connect->family, &connect->sip_addr, s_ip2, sizeof(s_ip2));
    inet_ntop(tcp_link->family, &tcp_link->c_ip, c_ip1, sizeof(c_ip1));
    inet_ntop(connect->family, &connect->cip_addr, c_ip2, sizeof(c_ip2));
    DEBUG("[TCPPROBE]: Flow (%s:%u - %s:%u) is transformed into (%s:%u - %s:%u)\n",
            c_ip1, tcp_link->c_port, s_ip1, tcp_link->s_port, c_ip2, connect->c_port, s_ip2, connect->s_port);
#endif

    return transform;
}

void __init_toa_sock_id(struct toa_sock_id_s *toa_sock_id, const struct tcp_link_s *tcp_link)
{
    toa_sock_id->family = tcp_link->family;
    toa_sock_id->role = tcp_link->role;
    toa_sock_id->c_port = tcp_link->c_port;
    toa_sock_id->s_port = tcp_link->s_port;

    if (tcp_link->family == AF_INET) {
        toa_sock_id->c_ip = tcp_link->c_ip;
        toa_sock_id->s_ip = tcp_link->s_ip;
    } else {
        memcpy(toa_sock_id->c_ip6, tcp_link->c_ip6, IP6_LEN);
        memcpy(toa_sock_id->s_ip6, tcp_link->s_ip6, IP6_LEN);
    }
    return;
}

static void __init_tracker_id(struct tcp_tracker_id_s *tracker_id, const struct tcp_link_s *tcp_link,
                              const struct toa_socket_s *toa_sock)
{
    tracker_id->tgid = tcp_link->tgid;
    tracker_id->family = tcp_link->family;
    tracker_id->role = tcp_link->role;
    tracker_id->port = tcp_link->s_port;
    memcpy(tracker_id->comm, tcp_link->comm, TASK_COMM_LEN);

    if (tcp_link->family == AF_INET) {
        tracker_id->c_ip = tcp_link->c_ip;
        tracker_id->s_ip = tcp_link->s_ip;
    } else {
        memcpy(tracker_id->c_ip6, tcp_link->c_ip6, IP6_LEN);
        memcpy(tracker_id->s_ip6, tcp_link->s_ip6, IP6_LEN);
    }

    if (toa_sock == NULL) {
        return;
    }

    tracker_id->toa_famlily = toa_sock->opt_family;
    if (tcp_link->opt_family == AF_INET) {
        tracker_id->toa_c_ip = toa_sock->opt_c_ip;
    } else {
        memcpy(tracker_id->toa_c_ip6, toa_sock->opt_c_ip6, IP6_LEN);
    }

    return;
}

#define __TCP_FLOW_TRACKER_MAX (4 * 1024)
static struct tcp_flow_tracker_s* create_tcp_flow_tracker(struct tcp_mng_s *tcp_mng,
    const struct tcp_flow_tracker_id_s *id)
{
    if (tcp_mng->tcp_flow_tracker_count >= __TCP_FLOW_TRACKER_MAX) {
        ERROR("[TCPPROBE]: Create 'tcp_flow_tracker' failed(upper to limited).\n");
        return NULL;
    }

    struct tcp_flow_tracker_s* tracker = (struct tcp_flow_tracker_s *)malloc(sizeof(struct tcp_flow_tracker_s));
    if (tracker == NULL) {
        return NULL;
    }

    memset(tracker, 0, sizeof(struct tcp_flow_tracker_s));
    memcpy(&(tracker->id), id, sizeof(struct tcp_flow_tracker_id_s));
    tracker->last_report = (time_t)time(NULL);
    tcp_mng->tcp_flow_tracker_count++;
    return tracker;
}
static struct tcp_flow_tracker_s* lkup_tcp_flow_tracker(struct tcp_mng_s *tcp_mng,
    const struct tcp_flow_tracker_id_s *id)
{
    struct tcp_flow_tracker_s* tracker = NULL;

    H_FIND(tcp_mng->flow_trackers, id, sizeof(struct tcp_flow_tracker_id_s), tracker);
    return tracker;
}

static void __init_flow_tracker_id(struct tcp_flow_tracker_id_s *tracker_id, const struct tcp_link_s *tcp_link)
{
    tracker_id->tgid = tcp_link->tgid;
    tracker_id->role = tcp_link->role;
    tracker_id->port = tcp_link->s_port;

    if (tcp_link->role == 0) {
        ip_str(tcp_link->family, (unsigned char *)&(tcp_link->c_ip),
            (unsigned char *)tracker_id->remote_ip, sizeof(tracker_id->remote_ip));
    } else {
        ip_str(tcp_link->family, (unsigned char *)&(tcp_link->s_ip),
            (unsigned char *)tracker_id->remote_ip, sizeof(tracker_id->remote_ip));
    }

    return;
}

#endif

struct tcp_tracker_s *get_tcp_tracker(struct tcp_mng_s *tcp_mng, const void *link, const struct toa_socket_s *toa_sock)
{
    struct tcp_connect_s connect = {0};
    struct tcp_tracker_id_s tracker_id = {0};
    const struct tcp_link_s *tcp_link = link;

    __init_tracker_id(&tracker_id, tcp_link, toa_sock);

    int transform = __transform_cluster_ip(tcp_mng, tcp_link, &connect);
    if (transform & ADDR_TRANSFORM_SERVER) {
        if (connect.family == AF_INET) {
            tracker_id.s_ip = connect.sip_addr.s_ip;
        } else {
            memcpy(tracker_id.s_ip6, &(connect.sip_addr.s_ip6), IP6_LEN);
        }
        tracker_id.port = connect.s_port;
    } else if (transform & ADDR_TRANSFORM_CLIENT) {
        if (connect.family == AF_INET) {
            tracker_id.c_ip = connect.cip_addr.c_ip;
        } else {
            memcpy(tracker_id.c_ip6, &(connect.cip_addr.c_ip6), IP6_LEN);
        }
    }

    struct tcp_tracker_s* tracker = lkup_tcp_tracker(tcp_mng, (const struct tcp_tracker_id_s *)&tracker_id);
    if (tracker) {
        return tracker;
    }

    struct tcp_tracker_s* new_tracker = create_tcp_tracker(tcp_mng, &tracker_id);
    if (new_tracker == NULL) {
        return NULL;
    }

    H_ADD_KEYPTR(tcp_mng->trackers, &new_tracker->id, sizeof(struct tcp_tracker_id_s), new_tracker);
    return new_tracker;
}

void destroy_tcp_tracker(struct tcp_tracker_s* tracker)
{
    if (!tracker) {
        return;
    } 
    if (tracker->src_ip) {
        free(tracker->src_ip);
    }

    if (tracker->dst_ip) {
        free(tracker->dst_ip);
    }

    if (tracker->toa_src_ip) {
        free(tracker->toa_src_ip);
    }
    free_histo_buckets(&tracker->snd_wnd_buckets, __MAX_WIND_SIZE);
    free_histo_buckets(&tracker->rcv_wnd_buckets, __MAX_WIND_SIZE);
    free_histo_buckets(&tracker->avl_snd_wnd_buckets, __MAX_WIND_SIZE);
    free_histo_buckets(&tracker->snd_cwnd_buckets, __MAX_WIND_SIZE);
    free_histo_buckets(&tracker->not_sent_buckets, __MAX_WIND_SIZE);
    free_histo_buckets(&tracker->not_acked_buckets, __MAX_WIND_SIZE);
    free_histo_buckets(&tracker->reordering_buckets, __MAX_WIND_SIZE);

    free_histo_buckets(&tracker->srtt_buckets, __MAX_RTT_SIZE);
    free_histo_buckets(&tracker->rcv_rtt_buckets, __MAX_RTT_SIZE);
    free_histo_buckets(&tracker->syn_srtt_buckets, __MAX_RTT_SIZE);

    free_histo_buckets(&tracker->rto_buckets, __MAX_RTO_SIZE);
    free_histo_buckets(&tracker->ato_buckets, __MAX_RTO_SIZE);

    free_histo_buckets(&tracker->snd_buf_buckets, __MAX_SOCKBUF_SIZE);
    free_histo_buckets(&tracker->rcv_buf_buckets, __MAX_SOCKBUF_SIZE);

    free(tracker);
}

void destroy_tcp_trackers(struct tcp_mng_s *tcp_mng)
{
    struct tcp_tracker_s *tracker, *tmp;

    H_ITER(tcp_mng->trackers, tracker, tmp) {
        H_DEL(tcp_mng->trackers, tracker);
        destroy_tcp_tracker(tracker);
    }
}

void destroy_toa_sockets(struct tcp_mng_s *tcp_mng)
{
    struct toa_socket_s *sock, *tmp;
    H_ITER(tcp_mng->toa_socks, sock, tmp) {
        H_DEL(tcp_mng->toa_socks, sock);
        free(sock);
    }
    tcp_mng->toa_socks = NULL;
}

struct tcp_flow_tracker_s* get_tcp_flow_tracker(struct tcp_mng_s *tcp_mng, const void *link)
{
    struct tcp_connect_s connect = {0};
    struct tcp_flow_tracker_id_s tracker_id = {0};
    const struct tcp_link_s *tcp_link = link;

    __init_flow_tracker_id(&tracker_id, tcp_link);

    int transform = __transform_cluster_ip(tcp_mng, tcp_link, &connect);
    if (transform & ADDR_TRANSFORM_SERVER) {
        tracker_id.remote_ip[0] = 0;
        ip_str(connect.family, (unsigned char *)&(connect.sip_addr),
            (unsigned char *)tracker_id.remote_ip, sizeof(tracker_id.remote_ip));
        tracker_id.port = connect.s_port;
    }

    struct tcp_flow_tracker_s* tracker = lkup_tcp_flow_tracker(tcp_mng,
        (const struct tcp_flow_tracker_id_s *)&tracker_id);
    if (tracker) {
        return tracker;
    }

    struct tcp_flow_tracker_s* new_tracker = create_tcp_flow_tracker(tcp_mng, &tracker_id);
    if (new_tracker == NULL) {
        return NULL;
    }

    H_ADD_KEYPTR(tcp_mng->flow_trackers, &new_tracker->id, sizeof(struct tcp_flow_tracker_id_s), new_tracker);
    return new_tracker;
}

void destroy_tcp_flow_tracker(struct tcp_flow_tracker_s* tracker)
{
    free(tracker);
    return;
}

void destroy_tcp_flow_trackers(struct tcp_mng_s *tcp_mng)
{
    struct tcp_flow_tracker_s *tracker, *tmp;

    H_ITER(tcp_mng->flow_trackers, tracker, tmp) {
        H_DEL(tcp_mng->flow_trackers, tracker);
        destroy_tcp_flow_tracker(tracker);
    }
    free_histo_buckets(&tcp_mng->flow_trackers->send_delay_buckets, __MAX_DELAY_SIZE);
    free_histo_buckets(&tcp_mng->flow_trackers->recv_delay_buckets, __MAX_DELAY_SIZE);
}
