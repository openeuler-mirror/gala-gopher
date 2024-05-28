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


struct __tcp_histo_s {
    u32 range;
    u64 min, max;
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

#define HISTO_BUCKET_INIT(buckets, size, histios) \
do { \
    for (int i = 0; i < size; i++) { \
        (void)init_histo_bucket(&(buckets[i]), histios[i].min, histios[i].max); \
    } \
} while (0)

static void init_tcp_buckets(struct tcp_tracker_s* tracker)
{
    HISTO_BUCKET_INIT(tracker->snd_wnd_buckets, __MAX_WIND_SIZE, tcp_wind_histios);
    HISTO_BUCKET_INIT(tracker->rcv_wnd_buckets, __MAX_WIND_SIZE, tcp_wind_histios);
    HISTO_BUCKET_INIT(tracker->avl_snd_wnd_buckets, __MAX_WIND_SIZE, tcp_wind_histios);
    HISTO_BUCKET_INIT(tracker->snd_cwnd_buckets, __MAX_WIND_SIZE, tcp_wind_histios);
    HISTO_BUCKET_INIT(tracker->not_sent_buckets, __MAX_WIND_SIZE, tcp_wind_histios);
    HISTO_BUCKET_INIT(tracker->not_acked_buckets, __MAX_WIND_SIZE, tcp_wind_histios);
    HISTO_BUCKET_INIT(tracker->reordering_buckets, __MAX_WIND_SIZE, tcp_wind_histios);

    HISTO_BUCKET_INIT(tracker->srtt_buckets, __MAX_RTT_SIZE, tcp_rtt_histios);
    HISTO_BUCKET_INIT(tracker->rcv_rtt_buckets, __MAX_RTT_SIZE, tcp_rtt_histios);
    HISTO_BUCKET_INIT(tracker->syn_srtt_buckets, __MAX_RTT_SIZE, tcp_rtt_histios);

    HISTO_BUCKET_INIT(tracker->rto_buckets, __MAX_RTO_SIZE, tcp_rto_histios);
    HISTO_BUCKET_INIT(tracker->ato_buckets, __MAX_RTO_SIZE, tcp_rto_histios);

    HISTO_BUCKET_INIT(tracker->snd_buf_buckets, __MAX_SOCKBUF_SIZE, tcp_sockbuf_histios);
    HISTO_BUCKET_INIT(tracker->rcv_buf_buckets, __MAX_SOCKBUF_SIZE, tcp_sockbuf_histios);
}

static struct tcp_tracker_s* create_tcp_tracker(struct tcp_mng_s *tcp_mng, const struct tcp_tracker_id_s *id)
{
    unsigned char src_ip_str[INET6_ADDRSTRLEN];
    unsigned char dst_ip_str[INET6_ADDRSTRLEN];

#define __TCP_TRACKER_MAX (4 * 1024)
    if (tcp_mng->tcp_tracker_count >= __TCP_TRACKER_MAX) {
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

    if (tracker->src_ip == NULL || tracker->dst_ip == NULL) {
        goto err;
    }

    tracker->last_report = (time_t)time(NULL);
    init_tcp_buckets(tracker);
    tcp_mng->tcp_tracker_count++;
    return tracker;

err:
    if (tracker) {
        destroy_tcp_tracker(tracker);
    }
    return NULL;
}

static struct tcp_tracker_s* lkup_tcp_tracker(struct tcp_mng_s *tcp_mng, const struct tcp_tracker_id_s *id)
{
    struct tcp_tracker_s* tracker = NULL;

    H_FIND(tcp_mng->trackers, id, sizeof(struct tcp_tracker_id_s), tracker);
    return tracker;
}

static void __transform_cluster_ip(struct tcp_mng_s *tcp_mng, const struct tcp_link_s *tcp_link, struct backend_ip_s *backend_ip)
{
    int transform = 0;

    if (tcp_mng->ipc_body.probe_param.cluster_ip_backend == 0) {
        return;
    }

    // Only transform Kubernetes cluster IP backend for the client TCP connection.
    if (tcp_link->role == 0) {
        return;
    }

    struct tcp_connect_s connect;

    connect.role = tcp_link->role;
    connect.family = tcp_link->family;

    if (tcp_link->family == AF_INET) {
        connect.cip_addr.c_ip = tcp_link->c_ip;
        connect.sip_addr.s_ip = tcp_link->s_ip;
    } else {
        memcpy(&(connect.cip_addr), tcp_link->c_ip6, IP6_LEN);
        memcpy(&(connect.sip_addr), tcp_link->s_ip6, IP6_LEN);
    }
    connect.c_port = tcp_link->c_port;
    connect.s_port = tcp_link->s_port;

    (void)get_cluster_ip_backend(&connect, &transform);
    if (!transform) {
        return;
    }

#ifdef GOPHER_DEBUG
    char ip1[IP6_LEN], ip2[IP6_LEN];
    ip1[0] = 0;
    (void)inet_ntop(tcp_link->family, (const void *)&(tcp_link->s_ip), ip1, IP6_LEN);
    ip2[0] = 0;
    (void)inet_ntop(connect.family, (const void *)&(connect.sip_addr), ip2, IP6_LEN);
    DEBUG("[TCPPROBE]: Cluster IP[%s:%u->%s:%u] transform successfully.\n", ip1, tcp_link->s_port, ip2, connect.s_port);
#endif

    backend_ip->family = tcp_link->family;

    if (backend_ip->family == AF_INET) {
        backend_ip->ip_addr.ip = connect.sip_addr.s_ip;
    } else {
        memcpy(&(backend_ip->ip_addr), &(connect.sip_addr), IP6_LEN);
    }
    backend_ip->port = connect.s_port;
    return;
}

static void __init_tracker_id(struct tcp_tracker_id_s *tracker_id, const struct tcp_link_s *tcp_link)
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
    return;
}

static void init_tcp_flow_buckets(struct tcp_flow_tracker_s* tracker)
{
    HISTO_BUCKET_INIT(tracker->send_delay_buckets, __MAX_DELAY_SIZE, tcp_delay_histios);
    HISTO_BUCKET_INIT(tracker->recv_delay_buckets, __MAX_DELAY_SIZE, tcp_delay_histios);
}

static struct tcp_flow_tracker_s* create_tcp_flow_tracker(struct tcp_mng_s *tcp_mng,
    const struct tcp_flow_tracker_id_s *id)
{
#define __TCP_FLOW_TRACKER_MAX (4 * 1024)
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
    init_tcp_flow_buckets(tracker);
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

struct tcp_tracker_s* get_tcp_tracker(struct tcp_mng_s *tcp_mng, const void *link)
{
    struct backend_ip_s backend_ip = {0};
    struct tcp_tracker_id_s tracker_id = {0};
    const struct tcp_link_s *tcp_link = link;

    __init_tracker_id(&tracker_id, tcp_link);

    __transform_cluster_ip(tcp_mng, tcp_link, &backend_ip);
    if (backend_ip.family != 0 && backend_ip.port != 0) {
        if (backend_ip.family == AF_INET) {
            tracker_id.s_ip = backend_ip.ip_addr.ip;
        } else {
            memcpy(tracker_id.s_ip6, &(backend_ip.ip_addr), IP6_LEN);
        }
        tracker_id.port = backend_ip.port;
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
    if (tracker->src_ip) {
        free(tracker->src_ip);
    }

    if (tracker->dst_ip) {
        free(tracker->dst_ip);
    }

    free(tracker);
    return;
}

void destroy_tcp_trackers(struct tcp_mng_s *tcp_mng)
{
    struct tcp_tracker_s *tracker, *tmp;

    H_ITER(tcp_mng->trackers, tracker, tmp) {
        H_DEL(tcp_mng->trackers, tracker);
        destroy_tcp_tracker(tracker);
    }
}

struct tcp_flow_tracker_s* get_tcp_flow_tracker(struct tcp_mng_s *tcp_mng, const void *link)
{
    struct backend_ip_s backend_ip = {0};
    struct tcp_flow_tracker_id_s tracker_id = {0};
    const struct tcp_link_s *tcp_link = link;

    __init_flow_tracker_id(&tracker_id, tcp_link);

    __transform_cluster_ip(tcp_mng, tcp_link, &backend_ip);
    if (backend_ip.family != 0 && backend_ip.port != 0) {
        tracker_id.remote_ip[0] = 0;
        ip_str(backend_ip.family, (unsigned char *)&(backend_ip.ip_addr),
            (unsigned char *)tracker_id.remote_ip, sizeof(tracker_id.remote_ip));
        tracker_id.port = backend_ip.port;
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
}