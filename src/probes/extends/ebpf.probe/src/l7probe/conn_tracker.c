/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wo_cow
 * Create: 2023-03-07
 * Description: L7 Traffic Tracking
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "container.h"
#include "histogram.h"
#include "include/conn_tracker.h"
#include "include/connect.h"
#include "protocol/expose/protocol_parser.h"
#include "include/data_stream.h"
#include "l7_common.h"

#define OO_NAME        "l7"
#define L7_TBL_LINK    "l7_link"
#define L7_TBL_RPC     "l7_rpc"

struct latency_histo_s {
    enum latency_range_t range;
    int min, max;
};

struct latency_histo_s latency_histios[__MAX_LT_RANGE] = {
    {LT_RANGE_1, 0, 1},
    {LT_RANGE_2, 1, 3},
    {LT_RANGE_3, 3, 10},
    {LT_RANGE_4, 10, 20},
    {LT_RANGE_5, 20, 50},
    {LT_RANGE_6, 50, 100},
    {LT_RANGE_7, 100, 300},
    {LT_RANGE_8, 300, 500},
    {LT_RANGE_9, 500, 1000},
    {LT_RANGE_10, 1000, 10000}
};

const char *proto_name[PROTO_MAX] = {
    "unknown",
    "http",
    "http2",
    "mysql",
    "pgsql",
    "dns",
    "redis",
    "nats",
    "cql",
    "mongo",
    "kafka"
};

const char *l7_role_name[L7_ROLE_MAX] = {
    "unknown",
    "client",
    "server"
};

const char *l4_role_name[L4_ROLE_MAX] = {
    "udp",
    "tcp_client",
    "tcp_server"
};

static void init_latency_buckets(struct histo_bucket_s latency_buckets[], size_t size)
{
    for (int i = 0; i < __MAX_LT_RANGE && i < size; i++) {
        (void)init_histo_bucket(&(latency_buckets[i]), latency_histios[i].min, latency_histios[i].max);
    }
}

#if 1

static void destroy_tracker_record(struct conn_tracker_s* tracker)
{
    for (int i = 0; i < tracker->records.record_buf_size && i < RECORD_BUF_SIZE; i++) {
        if (tracker->records.records[i] != NULL) {
            free_record_data(tracker->protocol, tracker->records.records[i]);
            tracker->records.records[i] = NULL;
        }
    }
    tracker->records.record_buf_size = 0;
    tracker->records.err_count = 0;
    tracker->records.req_count = 0;
    tracker->records.resp_count = 0;
    return;
}

static void destroy_conn_tracker(struct conn_tracker_s* tracker)
{
    destroy_tracker_record(tracker);
    deinit_data_stream(&(tracker->send_stream));
    deinit_data_stream(&(tracker->recv_stream));
    free(tracker);
    return;
}

static struct conn_tracker_s* create_conn_tracker(const struct tracker_id_s *id)
{
    struct conn_tracker_s* tracker = (struct conn_tracker_s *)malloc(sizeof(struct conn_tracker_s));
    if (tracker == NULL) {
        return NULL;
    }

    memset(tracker, 0, sizeof(struct conn_tracker_s));
    memcpy(&(tracker->id), id, sizeof(struct tracker_id_s));
    (void)init_data_stream(&(tracker->send_stream));
    (void)init_data_stream(&(tracker->recv_stream));

    tracker->l4_role = L4_ROLE_MAX; // init

    init_latency_buckets(tracker->latency_buckets, __MAX_LT_RANGE);
    return tracker;
}

static struct conn_tracker_s* lkup_conn_tracker(struct l7_mng_s *l7_mng, const struct tracker_id_s *id)
{
    struct conn_tracker_s* tracker = NULL;

    H_FIND(l7_mng->trackers, id, sizeof(struct tracker_id_s), tracker);
    return tracker;
}

static struct conn_tracker_s* add_conn_tracker(struct l7_mng_s *l7_mng, const struct tracker_id_s *id)
{
    struct conn_tracker_s* tracker = lkup_conn_tracker(l7_mng, id);
    if (tracker) {
        return tracker;
    }

    struct conn_tracker_s* new_tracker = create_conn_tracker(id);
    if (new_tracker == NULL) {
        return NULL;
    }

    H_ADD_KEYPTR(l7_mng->trackers, &new_tracker->id, sizeof(struct tracker_id_s), new_tracker);
    return new_tracker;
}

static void try_del_conn_tracker(struct l7_mng_s *l7_mng, const struct tracker_id_s *id)
{
    struct conn_tracker_s* tracker = lkup_conn_tracker(l7_mng, id);
    if (tracker == NULL) {
        return;
    }
    if (tracker->inactive == 1) {
        H_DEL(l7_mng->trackers, tracker);
        destroy_conn_tracker(tracker);
    }
    return;
}

#if 0
static struct conn_tracker_s* find_conn_tracker(struct l7_mng_s *l7_mng, const struct l7_link_id_s *l7_link_id)
{
    struct conn_tracker_s *tracker, *tmp;

    H_ITER(l7_mng->trackers, tracker, tmp) {
        if ((tracker->id.tgid == l7_link_id->tgid)
            && (tracker->l4_role == l7_link_id->l4_role)
            && (tracker->l7_role == l7_link_id->l7_role)
            && (tracker->protocol == l7_link_id->protocol)
            && (memcmp(&(l7_link_id->remote_addr), &(tracker->open_info.remote_addr), sizeof(struct conn_addr_s)) == 0)) {
            return tracker;
        }
    }

    return NULL;
}
#endif

static struct frame_buf_s* get_req_frames(struct conn_tracker_s* tracker)
{
    if (tracker->l7_role == L7_CLIENT) {
        return &(tracker->send_stream.frame_bufs);
    }

    if (tracker->l7_role == L7_SERVER) {
        return &(tracker->recv_stream.frame_bufs);
    }
    return NULL;
}

static struct frame_buf_s* get_resp_frames(struct conn_tracker_s* tracker)
{
    if (tracker->l7_role == L7_CLIENT) {
        return &(tracker->recv_stream.frame_bufs);
    }

    if (tracker->l7_role == L7_SERVER) {
        return &(tracker->send_stream.frame_bufs);
    }
    return NULL;
}



#endif

#if 1
static void destroy_l7_link(struct l7_link_s* link)
{
    free(link);
    return;
}

static struct l7_link_s* create_l7_link(const struct l7_link_id_s *id)
{
    struct l7_link_s* link = (struct l7_link_s *)malloc(sizeof(struct l7_link_s));
    if (link == NULL) {
        return NULL;
    }

    memset(link, 0, sizeof(struct l7_link_s));
    memcpy(&(link->id), id, sizeof(struct l7_link_id_s));
    init_latency_buckets(link->latency_buckets, __MAX_LT_RANGE);
    return link;
}

static struct l7_link_s* lkup_l7_link(struct l7_mng_s *l7_mng, const struct l7_link_id_s *id)
{
    struct l7_link_s* link = NULL;

    H_FIND(l7_mng->l7_links, id, sizeof(struct l7_link_id_s), link);
    return link;
}

static void __init_l7_link_info(struct l7_mng_s *l7_mng, struct l7_link_s* link, const struct conn_tracker_s* tracker)
{
    struct l7_info_s *l7_info = &(link->l7_info);
    char pid_str[INT_LEN + 1];

    pid_str[0] = 0;
    (void)snprintf(pid_str, INT_LEN + 1, "%u", link->id.tgid);

    (void)get_proc_comm(link->id.tgid, l7_info->comm, TASK_COMM_LEN);
    (void)get_container_id_by_pid_cpuset((const char *)pid_str, l7_info->container_id, CONTAINER_ABBR_ID_LEN + 1);
    (void)get_container_pod_id((const char *)l7_info->container_id, l7_info->pod_id, POD_ID_LEN + 1);
    (void)get_pod_ip((const char *)l7_info->container_id, l7_info->pod_ip, INET6_ADDRSTRLEN);

    l7_info->is_ssl = tracker->is_ssl;
    return;
}

static struct l7_link_s* add_l7_link(struct l7_mng_s *l7_mng, const struct conn_tracker_s* tracker)
{
    struct l7_link_id_s l7_link_id = {0};

    l7_link_id.l4_role = tracker->l4_role;
    l7_link_id.l7_role = tracker->l7_role;
    l7_link_id.protocol = tracker->protocol;
    l7_link_id.tgid = tracker->id.tgid;
    (void)memcpy(&(l7_link_id.remote_addr), &(tracker->open_info.remote_addr), sizeof(struct conn_addr_s));

    struct l7_link_s* link = lkup_l7_link(l7_mng, (const struct l7_link_id_s *)&l7_link_id);
    if (link) {
        link->stats[OPEN_EVT]++;
        return link;
    }

#define __L7_LINK_MAX (4 * 1024)
    if (l7_mng->l7_links_capability >= __L7_LINK_MAX) {
        ERROR("[L7PROBE]: Create 'l7_link' failed(upper to limited).\n");
        return NULL;
    }

    struct l7_link_s* new_link = create_l7_link((const struct l7_link_id_s *)&l7_link_id);
    if (new_link == NULL) {
        return NULL;
    }

    new_link->stats[OPEN_EVT] = 1;
    __init_l7_link_info(l7_mng, new_link, tracker);
    new_link->last_rcv_data = time(NULL);

    H_ADD_KEYPTR(l7_mng->l7_links, &new_link->id, sizeof(struct l7_link_id_s), new_link);
    return new_link;
}

static struct l7_link_s* find_l7_link(struct l7_mng_s *l7_mng, const struct conn_tracker_s* tracker)
{
    struct l7_link_id_s l7_link_id = {0};

    l7_link_id.tgid = tracker->id.tgid;
    (void)memcpy(&(l7_link_id.remote_addr), &(tracker->open_info.remote_addr), sizeof(struct conn_addr_s));
    l7_link_id.l4_role = tracker->l4_role;
    l7_link_id.l7_role = tracker->l7_role;
    l7_link_id.protocol = tracker->protocol;

    return lkup_l7_link(l7_mng, (const struct l7_link_id_s *)&l7_link_id);
}

#endif

#if 1
static int proc_conn_ctl_msg(struct l7_mng_s *l7_mng, struct conn_ctl_s *conn_ctl_msg)
{
    struct conn_tracker_s* tracker;
    struct tracker_id_s tracker_id = {0};

    tracker_id.fd = conn_ctl_msg->conn_id.fd;
    tracker_id.tgid = conn_ctl_msg->conn_id.tgid;

    switch(conn_ctl_msg->type) {
        case CONN_EVT_OPEN:
        {
            tracker = add_conn_tracker(l7_mng, (const struct tracker_id_s *)&tracker_id);
            if (tracker) {
                tracker->inactive = 0;
                tracker->is_ssl = conn_ctl_msg->open.is_ssl;
                if (tracker->l4_role == L4_ROLE_MAX) {
                    tracker->l4_role = conn_ctl_msg->open.l4_role;
                }
                tracker->open_info.timestamp_ns = conn_ctl_msg->timestamp_ns;
                if (tracker->open_info.remote_addr.port == 0 && tracker->open_info.remote_addr.family == 0) {
                    (void)memcpy(&(tracker->open_info.remote_addr),
                            &(conn_ctl_msg->open.addr), sizeof(struct conn_addr_s));
                }
            }
            break;
        }
        case CONN_EVT_CLOSE:
        {
            tracker = lkup_conn_tracker(l7_mng, (const struct tracker_id_s *)&tracker_id);
            if (tracker) {
                tracker->inactive = 1;
            }
            break;
        }
        default:
        {
            ERROR("[L7PROBE]: Recv unknow ctrl msg.\n");
            return -1;
        }
    }
    return 0;
}

static int proc_conn_stats_msg(struct l7_mng_s *l7_mng, struct conn_stats_s *conn_stats_msg)
{
    struct conn_tracker_s* tracker;
    struct l7_link_s* link;
    struct tracker_id_s tracker_id = {0};

    tracker_id.fd = conn_stats_msg->conn_id.fd;
    tracker_id.tgid = conn_stats_msg->conn_id.tgid;

    tracker = lkup_conn_tracker(l7_mng, (const struct tracker_id_s *)&tracker_id);
    if (tracker == NULL) {
        return 0;
    }

    tracker->stats[BYTES_SENT] += conn_stats_msg->wr_bytes;
    tracker->stats[BYTES_RECV] += conn_stats_msg->rd_bytes;

    tracker->stats[LAST_BYTES_SENT] = conn_stats_msg->wr_bytes;
    tracker->stats[LAST_BYTES_RECV] = conn_stats_msg->rd_bytes;

    link = find_l7_link(l7_mng, (const struct conn_tracker_s *)tracker);
    if (link) {
        link->stats[BYTES_SENT] += conn_stats_msg->wr_bytes;
        link->stats[BYTES_RECV] += conn_stats_msg->rd_bytes;

        link->stats[LAST_BYTES_SENT] = conn_stats_msg->wr_bytes;
        link->stats[LAST_BYTES_RECV] = conn_stats_msg->rd_bytes;
        link->last_rcv_data = time(NULL);
    }

    /*
        MUST be deleted here to inactive TCP tracker.

        eBPF Sequence of events:   ctrl msg  -->  stats msg  -->  data msg
        perf buffer poll sequence:   ctrl msg  -->  data msg  -->  stats msg
    */
    try_del_conn_tracker(l7_mng, (const struct tracker_id_s *)&tracker_id);
    return 0;
}

static int proc_conn_data_msg(struct l7_mng_s *l7_mng, struct conn_data_s *conn_data_msg)
{
    int ret = 0;
    struct conn_tracker_s* tracker;
    struct tracker_id_s tracker_id = {0};
    struct l7_link_s* link;

    tracker_id.fd = conn_data_msg->conn_id.fd;
    tracker_id.tgid = conn_data_msg->conn_id.tgid;
    tracker = lkup_conn_tracker(l7_mng, (const struct tracker_id_s *)&tracker_id);
    if (tracker == NULL) {
        return 0;
    }
    if (tracker->protocol == PROTO_UNKNOW) {
        tracker->protocol = conn_data_msg->proto;
        tracker->send_stream.type = tracker->protocol;
        tracker->recv_stream.type = tracker->protocol;
    }

    if (tracker->l7_role == L7_UNKNOW) {
        tracker->l7_role = conn_data_msg->l7_role;
    }

    link = add_l7_link(l7_mng, (const struct conn_tracker_s *)tracker);
    if (link == NULL) {
        return -1;
    }
    link->last_rcv_data = time(NULL);

    switch (conn_data_msg->direction) {
        case L7_EGRESS:
        {
            link->stats[DATA_EVT_SENT]++;
            ret = data_stream_add_raw_data(&(tracker->send_stream),
                                            (const char *)conn_data_msg->data,
                                            conn_data_msg->data_size,
                                            conn_data_msg->timestamp_ns);
            break;
        }
        case L7_INGRESS:
        {
            link->stats[DATA_EVT_RECV]++;
            ret = data_stream_add_raw_data(&(tracker->recv_stream),
                                            (const char *)conn_data_msg->data,
                                            conn_data_msg->data_size,
                                            conn_data_msg->timestamp_ns);
            break;
        }
        default:
        {
            ERROR("[L7PROBE] Recv unknow data msg.\n");
            return -1;
        }
    }
    return ret;
}

static void add_tracker_stats(struct l7_mng_s *l7_mng, struct conn_tracker_s* tracker)
{
    int ret;
    struct l7_link_s* link;
    tracker->stats[REQ_COUNT] += tracker->records.req_count;
    tracker->stats[RSP_COUNT] += tracker->records.resp_count;
    tracker->stats[ERR_COUNT] += tracker->records.err_count;

    link = find_l7_link(l7_mng, (const struct conn_tracker_s *)tracker);
    if (link) {
        link->stats[REQ_COUNT] += tracker->records.req_count;
        link->stats[RSP_COUNT] += tracker->records.resp_count;
        link->stats[ERR_COUNT] += tracker->records.err_count;
    }

    for (int i = 0; i < tracker->records.record_buf_size && i < RECORD_BUF_SIZE; i++) {
        if (tracker->records.records[i]) {
            tracker->latency_sum += tracker->records.records[i]->latency;
            ret = histo_bucket_add_value(tracker->latency_buckets,
                            __MAX_LT_RANGE, tracker->records.records[i]->latency);
            if (link) {
                link->latency_sum += tracker->records.records[i]->latency;
                ret = histo_bucket_add_value(link->latency_buckets,
                                __MAX_LT_RANGE, tracker->records.records[i]->latency);
            }

            if (ret) {
                // TODO: debuging
            }
        }
    }
    return;
}

static void l7_parser_tracker(struct l7_mng_s *l7_mng, struct conn_tracker_s* tracker)
{
    enum message_type_t msg_type;

    msg_type = get_message_type(tracker->l7_role, L7_EGRESS);
    data_stream_parse_frames(msg_type, &(tracker->send_stream));

    msg_type = get_message_type(tracker->l7_role, L7_INGRESS);
    data_stream_parse_frames(msg_type, &(tracker->recv_stream));

    // TODO: match frames
    proto_match_frames(tracker->protocol,
                       get_req_frames(tracker),
                       get_resp_frames(tracker),
                       &tracker->records);

    // add stats
    add_tracker_stats(l7_mng, tracker);
    destroy_tracker_record(tracker);

    // pop frames
    data_stream_pop_frames(&(tracker->send_stream));
    data_stream_pop_frames(&(tracker->recv_stream));
    return;
}

#endif


#if 1

static void reset_tracker_stats(struct conn_tracker_s* tracker)
{
    histo_bucket_reset(tracker->latency_buckets, __MAX_LT_RANGE);
    tracker->latency_sum = 0;
    tracker->err_ratio = 0.0;

    memset(&(tracker->stats), 0, sizeof(u64) * __MAX_STATS);
    memset(&(tracker->throughput), 0, sizeof(float) * __MAX_THROUGHPUT);
    memset(&(tracker->latency), 0, sizeof(float) * __MAX_LATENCY);
    return;
}

static void reset_link_stats(struct l7_link_s *link)
{
    histo_bucket_reset(link->latency_buckets, __MAX_LT_RANGE);
    link->latency_sum = 0;
    link->err_ratio = 0.0;

    memset(&(link->stats), 0, sizeof(u64) * __MAX_STATS);
    memset(&(link->throughput), 0, sizeof(float) * __MAX_THROUGHPUT);
    memset(&(link->latency), 0, sizeof(float) * __MAX_LATENCY);

    return;
}

static void reset_l7_stats(struct l7_mng_s *l7_mng)
{
    struct conn_tracker_s *tracker, *tmp_tracker;
    struct l7_link_s *link, *tmp;

    H_ITER(l7_mng->trackers, tracker, tmp_tracker) {
        reset_tracker_stats(tracker);
    }
    H_ITER(l7_mng->l7_links, link, tmp) {
        reset_link_stats(link);
    }

    return;
}

static char is_l7link_inactive(struct l7_link_s *link)
{
#define __INACTIVE_TIME_SECS     (5 * 60)       // 5min
    time_t current = time(NULL);
    time_t secs;

    if (current > link->last_rcv_data) {
        secs = current - link->last_rcv_data;
        if (secs >= __INACTIVE_TIME_SECS) {
            return 1;
        }
    }

    return 0;
}

void aging_l7_links(struct l7_mng_s *l7_mng)
{
    struct l7_link_s *link, *tmp;

    H_ITER(l7_mng->l7_links, link, tmp) {
        if (is_l7link_inactive(link)) {
            H_DEL(l7_mng->l7_links, link);
            destroy_l7_link(link);
            l7_mng->l7_links_capability--;
        }
    }
}

static void calc_tracker_stats(struct conn_tracker_s* tracker, struct probe_params *probe_param)
{
    tracker->err_ratio = (float)((float)tracker->stats[ERR_COUNT] / (float)tracker->stats[REQ_COUNT]);

    tracker->throughput[THROUGHPUT_REQ] = (float)((float)tracker->stats[REQ_COUNT] / (float)probe_param->period);
    tracker->throughput[THROUGHPUT_RESP] = (float)((float)tracker->stats[REQ_COUNT] / (float)probe_param->period);

    (void)histo_bucket_value(tracker->latency_buckets, __MAX_LT_RANGE, HISTO_P50, &(tracker->latency[LATENCY_P50]));
    (void)histo_bucket_value(tracker->latency_buckets, __MAX_LT_RANGE, HISTO_P90, &(tracker->latency[LATENCY_P90]));
    (void)histo_bucket_value(tracker->latency_buckets, __MAX_LT_RANGE, HISTO_P99, &(tracker->latency[LATENCY_P99]));
}

static void calc_link_stats(struct l7_link_s *link, struct probe_params *probe_param)
{
    link->err_ratio = (float)((float)link->stats[ERR_COUNT] / (float)link->stats[REQ_COUNT]);

    link->throughput[THROUGHPUT_REQ] = (float)((float)link->stats[REQ_COUNT] / (float)probe_param->period);
    link->throughput[THROUGHPUT_RESP] = (float)((float)link->stats[REQ_COUNT] / (float)probe_param->period);

    (void)histo_bucket_value(link->latency_buckets, __MAX_LT_RANGE, HISTO_P50, &(link->latency[LATENCY_P50]));
    (void)histo_bucket_value(link->latency_buckets, __MAX_LT_RANGE, HISTO_P90, &(link->latency[LATENCY_P90]));
    (void)histo_bucket_value(link->latency_buckets, __MAX_LT_RANGE, HISTO_P99, &(link->latency[LATENCY_P99]));

    return;
}

static void calc_l7_stats(struct l7_mng_s *l7_mng)
{
    struct conn_tracker_s *tracker, *tmp_tracker;
    struct l7_link_s *link, *tmp;

    H_ITER(l7_mng->trackers, tracker, tmp_tracker) {
        calc_tracker_stats(tracker, &(l7_mng->ipc_body.probe_param));
    }
    H_ITER(l7_mng->l7_links, link, tmp) {
        calc_link_stats(link, &(l7_mng->ipc_body.probe_param));
    }

    return;
}


static void reprot_l7_link(struct l7_link_s *link)
{
    unsigned char remote_ip[INET6_ADDRSTRLEN];

    ip_str(link->id.remote_addr.family, (unsigned char *)&(link->id.remote_addr.ip), remote_ip, INET6_ADDRSTRLEN);

    (void)fprintf(stdout, "|%s|%u|%s|%u|%s|%s"
        "|%s|%s|%s"
        "|%llu|%llu|\n",

        L7_TBL_LINK,
        link->id.tgid,
        remote_ip,
        link->id.remote_addr.port,
        l4_role_name[link->id.l4_role],
        l7_role_name[link->id.l7_role],
        proto_name[link->id.protocol],

        link->l7_info.pod_ip,
        link->l7_info.is_ssl ? "ssl" : "no_ssl",

        link->stats[BYTES_SENT],
        link->stats[BYTES_RECV]);
}

static void reprot_l7_rpc(struct l7_link_s *link)
{
    unsigned char remote_ip[INET6_ADDRSTRLEN];

    ip_str(link->id.remote_addr.family, (unsigned char *)&(link->id.remote_addr.ip), remote_ip, INET6_ADDRSTRLEN);

    (void)fprintf(stdout, "|%s|%u|%s|%u|%s|%s"
        "|%s|%s|%s"
        "|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|\n",

        L7_TBL_RPC,
        link->id.tgid,
        remote_ip,
        link->id.remote_addr.port,
        l4_role_name[link->id.l4_role],
        l7_role_name[link->id.l7_role],
        proto_name[link->id.protocol],

        link->l7_info.pod_ip,
        link->l7_info.is_ssl ? "ssl" : "no_ssl",

        link->throughput[THROUGHPUT_REQ],
        link->throughput[THROUGHPUT_RESP],
        (float)((float)link->latency_sum / (float)link->stats[REQ_COUNT]),
        link->latency[LATENCY_P50],
        link->latency[LATENCY_P90],
        link->latency[LATENCY_P99],
        link->err_ratio);
}

static void report_l7_stats(struct l7_mng_s *l7_mng)
{
    struct l7_link_s *link, *tmp;

    H_ITER(l7_mng->l7_links, link, tmp) {
        reprot_l7_link(link);
        reprot_l7_rpc(link);
    }

    return;
}

static char is_report_tmout(struct l7_mng_s *l7_mng)
{
    time_t current = (time_t)time(NULL);
    time_t secs;

    if (current > l7_mng->last_report) {
        secs = current - l7_mng->last_report;
        if (secs >= l7_mng->ipc_body.probe_param.period) {
            l7_mng->last_report = current;
            return 1;
        }
    }

    return 0;
}

void report_l7(void *ctx)
{
    struct l7_mng_s *l7_mng = ctx;

    if (!is_report_tmout(l7_mng)) {
        return;
    }

    calc_l7_stats(l7_mng);
    report_l7_stats(l7_mng);
    reset_l7_stats(l7_mng);
    aging_l7_links(l7_mng);
    return;
}


#endif

void destroy_trackers(void *ctx)
{
    struct l7_mng_s *l7_mng = ctx;
    struct conn_tracker_s *tracker, *tmp;

    H_ITER(l7_mng->trackers, tracker, tmp) {
        H_DEL(l7_mng->trackers, tracker);
        destroy_conn_tracker(tracker);
    }
}

void destroy_links(void *ctx)
{
    struct l7_mng_s *l7_mng = ctx;
    struct l7_link_s *link, *tmp;

    H_ITER(l7_mng->l7_links, link, tmp) {
        H_DEL(l7_mng->l7_links, link);
        destroy_l7_link(link);
    }
}

void l7_parser(void *ctx)
{
    struct l7_mng_s *l7_mng = ctx;
    struct conn_tracker_s *tracker, *tmp;

    H_ITER(l7_mng->trackers, tracker, tmp) {
        l7_parser_tracker(l7_mng, tracker);
    }
}

void trakcer_data_msg_pb(void *ctx, int cpu, void *data, unsigned int size)
{
    (void)proc_conn_data_msg((struct l7_mng_s *)ctx, (struct conn_data_s *)data);
}

void trakcer_ctrl_msg_pb(void *ctx, int cpu, void *data, unsigned int size)
{
    (void)proc_conn_ctl_msg((struct l7_mng_s *)ctx, (struct conn_ctl_s *)data);
}

void trakcer_stats_msg_pb(void *ctx, int cpu, void *data, unsigned int size)
{
    (void)proc_conn_stats_msg((struct l7_mng_s *)ctx, (struct conn_stats_s *)data);
}

int trakcer_data_msg_rb(void *ctx, void *data, unsigned int size)
{
    return proc_conn_data_msg((struct l7_mng_s *)ctx, (struct conn_data_s *)data);
}

int trakcer_ctrl_msg_rb(void *ctx, void *data, unsigned int size)
{
    return proc_conn_ctl_msg((struct l7_mng_s *)ctx, (struct conn_ctl_s *)data);
}

int trakcer_stats_msg_rb(void *ctx, void *data, unsigned int size)
{
    return proc_conn_stats_msg((struct l7_mng_s *)ctx, (struct conn_stats_s *)data);
}


