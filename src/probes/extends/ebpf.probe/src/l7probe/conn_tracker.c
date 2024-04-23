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
#include <string.h>
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
#include "conntrack.h"
#include "include/connect.h"
#include "protocol/expose/protocol_parser.h"
#include "include/data_stream.h"
#include "l7_common.h"
#include "include/conn_tracker.h"

#define OO_NAME         "l7"
#define L7_TBL_LINK     "l7_link"
#define L7_TBL_RPC      "l7_rpc"
#define L7_TBL_RPC_API  "l7_rpc_api"

struct latency_histo_s {
    enum latency_range_t range;
    u64 min, max;
};

// unit: ns
struct latency_histo_s latency_histios[__MAX_LT_RANGE] = {
    {LT_RANGE_1, 0,          10000000},
    {LT_RANGE_2, 10000000,   50000000},
    {LT_RANGE_3, 50000000,   100000000},
    {LT_RANGE_4, 100000000,  500000000},
    {LT_RANGE_5, 500000000,  1000000000},
    {LT_RANGE_6, 1000000000, 3000000000},
    {LT_RANGE_7, 3000000000, 10000000000}
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
    if (tracker->records.api_stats != NULL) {
        destroy_api_stats(tracker->records.api_stats);
        tracker->records.api_stats = NULL;
    }

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
    tracker->records.msg_error_count = 0;
    tracker->records.msg_total_count = 0;
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

static void destroy_l7_api_statistic(struct l7_api_statistic_s* l7_api_statistic)
{
    struct l7_api_statistic_s *item, *tmp;
    H_ITER(l7_api_statistic, item, tmp) {
        H_DEL(l7_api_statistic, item);
        free(item);
    }
}

static void destroy_l7_link(struct l7_link_s* link)
{
    if (link->client_ip) {
        free(link->client_ip);
    }
    if (link->server_ip) {
        free(link->server_ip);
    }

    // Free l7_statistic
    if (link->l7_statistic) {
        destroy_l7_api_statistic(link->l7_statistic);
    }

    free(link);
    return;
}

static struct l7_link_s* create_l7_link(const struct l7_link_id_s *id)
{
    unsigned char ip[INET6_ADDRSTRLEN];

    struct l7_link_s* link = (struct l7_link_s *)malloc(sizeof(struct l7_link_s));
    if (link == NULL) {
        return NULL;
    }

    memset(link, 0, sizeof(struct l7_link_s));
    memcpy(&(link->id), id, sizeof(struct l7_link_id_s));

    ip[0] = 0;
    if (link->id.client_addr.family != 0) {
        ip_str(link->id.client_addr.family, (unsigned char *)&(link->id.client_addr.ip), ip, INET6_ADDRSTRLEN);
        if (ip[0] != 0) {
            link->client_ip = strdup((const char *)ip);
        }
    }

    ip[0] = 0;
    if (link->id.server_addr.family != 0) {
        ip_str(link->id.server_addr.family, (unsigned char *)&(link->id.server_addr.ip), ip, INET6_ADDRSTRLEN);
        if (ip[0] != 0) {
            link->server_ip = strdup((const char *)ip);
        }
    }

    init_latency_buckets(link->latency_buckets, __MAX_LT_RANGE);
    return link;
}

static struct l7_link_s* lkup_l7_link(struct l7_mng_s *l7_mng, const struct l7_link_id_s *id)
{
    struct l7_link_s* link = NULL;

    H_FIND(l7_mng->l7_links, id, sizeof(struct l7_link_id_s), link);
    return link;
}

static void __init_l7_link_info(struct l7_link_s* link, const struct conn_tracker_s* tracker)
{
    struct l7_info_s *l7_info = &(link->l7_info);
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
    (void)memcpy(&(l7_link_id.client_addr), &(tracker->open_info.client_addr), sizeof(struct conn_addr_s));
    (void)memcpy(&(l7_link_id.server_addr), &(tracker->open_info.server_addr), sizeof(struct conn_addr_s));

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
    __init_l7_link_info(new_link, tracker);
    new_link->last_rcv_data = time(NULL);

    H_ADD_KEYPTR(l7_mng->l7_links, &new_link->id, sizeof(struct l7_link_id_s), new_link);
    l7_mng->l7_links_capability++;
    return new_link;
}

static struct l7_link_s* find_l7_link(struct l7_mng_s *l7_mng, const struct conn_tracker_s* tracker)
{
    struct l7_link_id_s l7_link_id = {0};

    l7_link_id.tgid = tracker->id.tgid;
    (void)memcpy(&(l7_link_id.client_addr), &(tracker->open_info.client_addr), sizeof(struct conn_addr_s));
    (void)memcpy(&(l7_link_id.server_addr), &(tracker->open_info.server_addr), sizeof(struct conn_addr_s));
    l7_link_id.l4_role = tracker->l4_role;
    l7_link_id.l7_role = tracker->l7_role;
    l7_link_id.protocol = tracker->protocol;

    return lkup_l7_link(l7_mng, (const struct l7_link_id_s *)&l7_link_id);
}

static struct l7_api_statistic_s* create_l7_api_statistic(const struct api_stats_id id)
{
    struct l7_api_statistic_s *l7_api_statistic = (struct l7_api_statistic_s *) malloc(sizeof(struct l7_api_statistic_s));
    if (l7_api_statistic == NULL) {
        ERROR("Failed to malloc struct l7_api_statistics_s.\n");
        return NULL;
    }
    memset(l7_api_statistic, 0, sizeof(struct l7_api_statistic_s));
    (void) snprintf(l7_api_statistic->id.api, MAX_API_LEN, "%s", id.api);

    // Initialize latency buckets
    init_latency_buckets(l7_api_statistic->latency_buckets, __MAX_LT_RANGE);
    return l7_api_statistic;
}

#endif

#if 1

static void transform_cluster_ip(struct l7_mng_s *l7_mng, struct conn_tracker_s* tracker)
{
    int transform = 0;

    if (l7_mng->ipc_body.probe_param.cluster_ip_backend == 0) {
        return;
    }

    // Only transform Kubernetes cluster IP backend for the client TCP connection.
    if (tracker->l4_role != L4_CLIENT) {
        return;
    }

    struct tcp_connect_s connect;

    connect.role = (tracker->l4_role == L4_CLIENT) ? 1 : 0;
    connect.family = tracker->open_info.client_addr.family;

    if (connect.family == AF_INET) {
        connect.cip_addr.c_ip = tracker->open_info.client_addr.ip;
        connect.sip_addr.s_ip = tracker->open_info.server_addr.ip;
    } else {
        memcpy(&(connect.cip_addr), tracker->open_info.client_addr.ip6, IP6_LEN);
        memcpy(&(connect.sip_addr), tracker->open_info.server_addr.ip6, IP6_LEN);
    }
    connect.c_port = tracker->open_info.client_addr.port;
    connect.s_port = tracker->open_info.server_addr.port;

    (void)get_cluster_ip_backend(&connect, &transform);
    if (!transform) {
        return;
    }

    if (connect.family == AF_INET) {
        tracker->open_info.server_addr.ip = connect.sip_addr.s_ip;
    } else {
        memcpy(tracker->open_info.server_addr.ip6, &(connect.sip_addr), IP6_LEN);
    }
    tracker->open_info.server_addr.port = connect.s_port;
    return;
}

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
                /* Reinit conn_tracker when it is reused */
                if (tracker->inactive) {
                    tracker->inactive = 0;
                    tracker->l4_role = L4_ROLE_MAX;
                    tracker->l7_role = L7_UNKNOW;
                    memset(&(tracker->open_info), 0, sizeof(struct tracker_open_s));
                    memset(&(tracker->close_info), 0, sizeof(struct tracker_close_s));
                }
                tracker->is_ssl = conn_ctl_msg->open.is_ssl;
                if (tracker->l4_role == L4_ROLE_MAX) {
                    tracker->l4_role = conn_ctl_msg->open.l4_role;
                }
                tracker->open_info.timestamp_ns = conn_ctl_msg->timestamp_ns;
                if (tracker->open_info.server_addr.port == 0 && tracker->open_info.server_addr.family == 0) {
                    (void)memcpy(&(tracker->open_info.server_addr),
                            &(conn_ctl_msg->open.server_addr), sizeof(struct conn_addr_s));
                    (void)memcpy(&(tracker->open_info.client_addr),
                            &(conn_ctl_msg->open.client_addr), sizeof(struct conn_addr_s));

                    // Transform K8S cluster IP to backend IP.
                    transform_cluster_ip(l7_mng, tracker);

                    // Client port just used for cluster IP address translation. Here, client port MUST set 0.
                    tracker->open_info.client_addr.port = 0;
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
        ERROR("[L7Probe]: Conn tracker[%d:%d] is not found when proc stats msg.\n", tracker_id.tgid, tracker_id.fd);
        return -1;
    }

    link = find_l7_link(l7_mng, (const struct conn_tracker_s *)tracker);
    if (link == NULL) {
        ERROR("[L7Probe]: Conn link[%d:%d] is not found when proc stats msg.\n", tracker_id.tgid, tracker_id.fd);
        return -1;
    }

    link->stats[BYTES_SENT] += conn_stats_msg->wr_bytes;
    link->stats[BYTES_RECV] += conn_stats_msg->rd_bytes;

    link->stats[LAST_BYTES_SENT] = conn_stats_msg->wr_bytes;
    link->stats[LAST_BYTES_RECV] = conn_stats_msg->rd_bytes;
    link->last_rcv_data = time(NULL);

    return 0;
}

static int proc_conn_data_msg(struct l7_mng_s *l7_mng, struct conn_data_msg_s *conn_data_msg, char *conn_data_buf)
{
    int ret = 0;
    struct conn_tracker_s* tracker;
    struct tracker_id_s tracker_id = {0};
    struct l7_link_s* link;

    tracker_id.fd = conn_data_msg->conn_id.fd;
    tracker_id.tgid = conn_data_msg->conn_id.tgid;
    tracker = lkup_conn_tracker(l7_mng, (const struct tracker_id_s *)&tracker_id);
    if (tracker == NULL) {
        ERROR("[L7Probe]: Conn tracker[%d:%d] is not found when proc data msg.\n", tracker_id.tgid, tracker_id.fd);
        return -1;
    }

    tracker->is_ssl = conn_data_msg->is_ssl;
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
                                            (const char *)conn_data_buf,
                                            (size_t)conn_data_msg->data_size,
                                            conn_data_msg->timestamp_ns);
            break;
        }
        case L7_INGRESS:
        {
            link->stats[DATA_EVT_RECV]++;
            ret = data_stream_add_raw_data(&(tracker->recv_stream),
                                            (const char *)conn_data_buf,
                                            (size_t)conn_data_msg->data_size,
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

// Calculate api-level metrics for l7_statistics
static void add_tracker_l7_stats(struct conn_tracker_s* tracker, struct l7_link_s* link)
{
    int ret;
    struct api_stats *item, *tmp;
    H_ITER(tracker->records.api_stats, item, tmp) {

        // Find a item from link_statistics by item.id
        struct l7_api_statistic_s *statistic;
        H_FIND(link->l7_statistic, &(item->id), sizeof(struct api_stats_id), statistic);
        if (statistic == NULL) {
            statistic = create_l7_api_statistic(item->id);
            if (statistic == NULL) {
                return;
            }
            H_ADD_KEYPTR(link->l7_statistic, &(statistic->id), sizeof(struct api_stats_id), statistic);
        }

        // Add counts into stats
        statistic->stats[REQ_COUNT] += item->req_count;
        statistic->stats[RSP_COUNT] += item->resp_count;
        statistic->stats[ERR_COUNT] += item->err_count;
        statistic->stats[CLIENT_ERR_COUNT] += item->client_err_count;
        statistic->stats[SERVER_ERR_COUNT] += item->server_err_count;

        // Put latency into buckets
        for (int i = 0; i < item->record_buf_size && i < RECORD_BUF_SIZE; i++) {
            if (item->records[i]) {
                statistic->latency_sum += item->records[i]->latency;
                ret = histo_bucket_add_value(statistic->latency_buckets, __MAX_LT_RANGE, item->records[i]->latency);
                if (ret) {
                    ERROR("[L7PROBE] Failed to add latency to histogram bucket, value: %lu\n", item->records[i]->latency);
                }
            }
        }
    }
}

static void add_tracker_stats(struct l7_mng_s *l7_mng, struct conn_tracker_s* tracker)
{
    int ret;
    struct l7_link_s* link;

    if (tracker->records.record_buf_size == 0 && tracker->records.req_count == 0 && tracker->records.resp_count == 0) {
        return;
    }
    link = find_l7_link(l7_mng, (const struct conn_tracker_s *)tracker);
    if (link == NULL) {
        return;
    }

    link->stats[REQ_COUNT] += tracker->records.req_count;
    link->stats[RSP_COUNT] += tracker->records.resp_count;
    link->stats[ERR_COUNT] += tracker->records.err_count;

    for (int i = 0; i < tracker->records.record_buf_size && i < RECORD_BUF_SIZE; i++) {
        if (tracker->records.records[i]) {
            link->latency_sum += tracker->records.records[i]->latency;
            ret = histo_bucket_add_value(link->latency_buckets,
                            __MAX_LT_RANGE, tracker->records.records[i]->latency);
            if (ret) {
                ERROR("[L7PROBE] Failed to add latency to histo bucket, value: %lu\n", tracker->records.records[i]->latency);
            }
        }
    }

    // add l7 api statistics
    add_tracker_l7_stats(tracker, link);
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

static void reset_api_stats(struct l7_api_statistic_s *statistic)
{
    histo_bucket_reset(statistic->latency_buckets, __MAX_LT_RANGE);
    statistic->latency_sum = 0;
    statistic->err_ratio = 0.0;

    memset(&(statistic->stats), 0, sizeof(u64) * __MAX_STATS);
    memset(&(statistic->throughput), 0, sizeof(float) * __MAX_THROUGHPUT);
    memset(&(statistic->latency), 0, sizeof(float) * __MAX_LATENCY);
}

static void reset_link_stats(struct l7_link_s *link)
{
    struct l7_api_statistic_s *item, *tmp;
    H_ITER(link->l7_statistic, item, tmp) {
        reset_api_stats(item);
    }

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
    struct l7_link_s *link, *tmp;

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

static void aging_l7_stats(struct l7_mng_s *l7_mng)
{
    struct conn_tracker_s *tracker, *tmp_tracker;
    struct l7_link_s *link, *tmp;

    H_ITER(l7_mng->trackers, tracker, tmp_tracker) {
        if (tracker->inactive) {
            H_DEL(l7_mng->trackers, tracker);
            destroy_conn_tracker(tracker);
        }
    }

    H_ITER(l7_mng->l7_links, link, tmp) {
        if (is_l7link_inactive(link)) {
            H_DEL(l7_mng->l7_links, link);
            destroy_l7_link(link);
            l7_mng->l7_links_capability--;
        }
    }
}

static void calc_link_stats(struct l7_link_s *link, struct probe_params *probe_param)
{
    link->err_ratio = link->stats[REQ_COUNT] == 0 ? 0.00f : (float)((float)link->stats[ERR_COUNT] / (float)link->stats[REQ_COUNT]);

    link->throughput[THROUGHPUT_REQ] = (float)((float)link->stats[REQ_COUNT] / (float)probe_param->period);
    link->throughput[THROUGHPUT_RESP] = (float)((float)link->stats[RSP_COUNT] / (float)probe_param->period);

    return;
}

static void calc_l7_api_statistics(struct l7_api_statistic_s *statistic, struct probe_params *probe_param)
{
    statistic->err_ratio = statistic->stats[ERR_COUNT] == 0 ? 0.00f : (float)((float)statistic->stats[ERR_COUNT] / (float)statistic->stats[REQ_COUNT]);
    statistic->client_err_ratio = statistic->stats[CLIENT_ERR_COUNT] == 0 ? 0.00f : (float)((float)statistic->stats[CLIENT_ERR_COUNT] / (float)statistic->stats[REQ_COUNT]);
    statistic->server_err_ratio = statistic->stats[SERVER_ERR_COUNT] == 0 ? 0.00f : (float)((float)statistic->stats[SERVER_ERR_COUNT] / (float)statistic->stats[REQ_COUNT]);

    statistic->throughput[THROUGHPUT_REQ] = (float)((float)statistic->stats[REQ_COUNT] / (float)probe_param->period);
    statistic->throughput[THROUGHPUT_RESP] = (float)((float)statistic->stats[REQ_COUNT] / (float)probe_param->period);

    (void)histo_bucket_value(statistic->latency_buckets, __MAX_LT_RANGE, HISTO_P50, &(statistic->latency[LATENCY_P50]));
    (void)histo_bucket_value(statistic->latency_buckets, __MAX_LT_RANGE, HISTO_P90, &(statistic->latency[LATENCY_P90]));
    (void)histo_bucket_value(statistic->latency_buckets, __MAX_LT_RANGE, HISTO_P99, &(statistic->latency[LATENCY_P99]));

    return;
}

static void calc_l7_stats(struct l7_mng_s *l7_mng)
{
    struct l7_link_s *link, *tmp;
    struct l7_api_statistic_s *statistic, *tmp_stat;

    H_ITER(l7_mng->l7_links, link, tmp) {
        calc_link_stats(link, &(l7_mng->ipc_body.probe_param));

        H_ITER(link->l7_statistic, statistic, tmp_stat) {
            calc_l7_api_statistics(statistic, &(l7_mng->ipc_body.probe_param));
        }
    }

    return;
}


static void report_l7_link(struct l7_link_s *link)
{
    (void)fprintf(stdout, "|%s|%d|%s|%s|%u"
        "|%s|%s|%s|%s"
        "|%llu|%llu|%llu|%llu|\n",

        L7_TBL_LINK,
        link->id.tgid,
        (link->client_ip == NULL) ? "no_ip" : link->client_ip,
        (link->server_ip == NULL) ? "no_ip" : link->server_ip,
        link->id.server_addr.port,

        l4_role_name[link->id.l4_role],
        l7_role_name[link->id.l7_role],
        proto_name[link->id.protocol],
        link->l7_info.is_ssl ? "ssl" : "no_ssl",

        link->stats[BYTES_SENT],
        link->stats[BYTES_RECV],
        link->stats[DATA_EVT_SENT],
        link->stats[DATA_EVT_RECV]);

    (void)fflush(stdout);
}

// eg: gala_gopher_l7_throughput_req{
// tgid="120407",client_ip="0:0:0:0:0:0:.0.0.1",server_ip="0:0:0:0:0:0:.0.0.1",server_port="7654",
// l4_role="tcp_server",l7_role="server",protocol="pgsql",ssl="no_ssl",api="/rest/api/example",
// comm="gaussdb",machine_id="61d09cf3-3806-469e-9afd-770cd09076fe-71.76.51.175"}
// 0.00 1692352573000
static void report_l7_rpc_api(struct l7_link_s *link, struct l7_api_statistic_s *l7_api_statistic)
{
    char latency_historm[MAX_HISTO_SERIALIZE_SIZE];

    latency_historm[0] = 0;
    if (serialize_histo(l7_api_statistic->latency_buckets, __MAX_LT_RANGE, latency_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }

    (void)fprintf(stdout, "|%s|%d|%s|%s|%u"
                          "|%s|%s|%s|%s|%s"
                          "|%.2f|%.2f|%llu|%llu"
                          "|%.2f|%s|%llu"
                          "|%.2f|%.2f|%.2f|%llu|%llu|%llu|\n",

                  L7_TBL_RPC_API,
                  link->id.tgid,
                  (link->client_ip == NULL) ? "no_ip" : link->client_ip,
                  (link->server_ip == NULL) ? "no_ip" : link->server_ip,
                  link->id.server_addr.port,

                  l4_role_name[link->id.l4_role],
                  l7_role_name[link->id.l7_role],
                  proto_name[link->id.protocol],
                  l7_api_statistic->id.api,
                  link->l7_info.is_ssl ? "ssl" : "no_ssl",

                  l7_api_statistic->throughput[THROUGHPUT_REQ],
                  l7_api_statistic->throughput[THROUGHPUT_RESP],
                  l7_api_statistic->stats[REQ_COUNT],
                  l7_api_statistic->stats[RSP_COUNT],

                  l7_api_statistic->stats[REQ_COUNT] == 0 ? 0.00f : (float)((float)l7_api_statistic->latency_sum / (float)l7_api_statistic->stats[REQ_COUNT]),
                  latency_historm,
                  l7_api_statistic->latency_sum,

                  l7_api_statistic->err_ratio,
                  l7_api_statistic->client_err_ratio,
                  l7_api_statistic->server_err_ratio,
                  l7_api_statistic->stats[ERR_COUNT],
                  l7_api_statistic->stats[CLIENT_ERR_COUNT],
                  l7_api_statistic->stats[SERVER_ERR_COUNT]
                  );

    (void)fflush(stdout);
}

// eg: gala_gopher_l7_throughput_req{
// tgid="120407",client_ip="0:0:0:0:0:0:.0.0.1",server_ip="0:0:0:0:0:0:.0.0.1",server_port="7654",
// l4_role="tcp_server",l7_role="server",protocol="pgsql",ssl="no_ssl",
// comm="gaussdb",machine_id="61d09cf3-3806-469e-9afd-770cd09076fe-71.76.51.175"}
// 0.00 1692352573000
static void report_l7_rpc(struct l7_link_s *link)
{
    char latency_historm[MAX_HISTO_SERIALIZE_SIZE];

    latency_historm[0] = 0;
    if (serialize_histo(link->latency_buckets, __MAX_LT_RANGE, latency_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }

    (void)fprintf(stdout, "|%s|%d|%s|%s|%u"
        "|%s|%s|%s|%s"
        "|%.2f|%.2f|%llu|%llu"
        "|%.2f|%s|%llu"
        "|%.2f|%llu|\n",

        L7_TBL_RPC,
        link->id.tgid,
        (link->client_ip == NULL) ? "no_ip" : link->client_ip,
        (link->server_ip == NULL) ? "no_ip" : link->server_ip,
        link->id.server_addr.port,

        l4_role_name[link->id.l4_role],
        l7_role_name[link->id.l7_role],
        proto_name[link->id.protocol],
        link->l7_info.is_ssl ? "ssl" : "no_ssl",

        link->throughput[THROUGHPUT_REQ],
        link->throughput[THROUGHPUT_RESP],
        link->stats[REQ_COUNT],
        link->stats[RSP_COUNT],

        link->stats[REQ_COUNT] == 0 ? 0.00f : (float)((float)link->latency_sum / (float)link->stats[REQ_COUNT]),
        latency_historm,
        link->latency_sum,

        link->err_ratio,
        link->stats[ERR_COUNT]);

    (void)fflush(stdout);
}

static void report_l7_stats(struct l7_mng_s *l7_mng)
{
    struct l7_link_s *link, *tmp;

    u32 probe_range_flags = l7_mng->ipc_body.probe_range_flags;

    // Traverse map l7_links
    H_ITER(l7_mng->l7_links, link, tmp) {
        if(probe_range_flags & PROBE_RANGE_L7BYTES_METRICS) {
            report_l7_link(link);
        }

        if(probe_range_flags & PROBE_RANGE_L7RPC_METRICS) {
            report_l7_rpc(link);
        }

        // Traverse map l7_statistic
        if(probe_range_flags & PROBE_RANGE_L7RPC_METRICS) {
            struct l7_api_statistic_s *l7_statistic, *tmp_statistic;
            H_ITER(link->l7_statistic, l7_statistic, tmp_statistic) {
                report_l7_rpc_api(link, l7_statistic);
            }
        }
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
    aging_l7_stats(l7_mng);
    reset_l7_stats(l7_mng);
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

void destroy_unprobed_trackers_links(void *ctx)
{
    struct l7_mng_s *l7_mng = ctx;
    struct conn_tracker_s *tracker, *tmp_tracker;
    struct l7_link_s *link, *tmp_link;
    struct obj_ref_s val = {0};
    struct proc_s proc = {0};
    int proc_map_fd = l7_mng->bpf_progs.proc_obj_map_fd;

    if (proc_map_fd < 0) {
        return;
    }

    H_ITER(l7_mng->trackers, tracker, tmp_tracker) {
        proc.proc_id = tracker->id.tgid;
        if (bpf_map_lookup_elem(proc_map_fd, &proc, &val) < 0) {
            H_DEL(l7_mng->trackers, tracker);
            destroy_conn_tracker(tracker);
        }
    }

    H_ITER(l7_mng->l7_links, link, tmp_link) {
        proc.proc_id = link->id.tgid;
        if (bpf_map_lookup_elem(proc_map_fd, &proc, &val) < 0) {
            H_DEL(l7_mng->l7_links, link);
            destroy_l7_link(link);
            l7_mng->l7_links_capability--;
        }
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

int tracker_msg(void *ctx, void *data, u32 size)
{
    char *p = data;
    struct l7_mng_s *l7_mng  = ctx;
    int remain_size = (int)size, step_size = 0, offset = 0;
    size_t walk_size = 0;
    enum tracker_evt_e *evt;
    struct conn_data_msg_s *conn_data_msg;
    char *conn_data_buf;

    step_size = min(sizeof(struct conn_stats_s), sizeof(struct conn_ctl_s));
    step_size = min(step_size, sizeof(struct conn_data_msg_s));

    do {
        if (remain_size < step_size) {
            break;
        }

        p = (char *)data + offset;

        evt = (enum tracker_evt_e *)p;
        switch (*evt) {
            case TRACKER_EVT_STATS:
            {
                if (remain_size < sizeof(struct conn_stats_s)) {
                    ERROR("[L7Probe]: Invalid conn tracker stats msg.\n");
                    return 0;
                }
                (void)proc_conn_stats_msg(l7_mng, (struct conn_stats_s *)p);
                walk_size = sizeof(struct conn_stats_s);
                break;
            }
            case TRACKER_EVT_CTRL:
            {
                if (remain_size < sizeof(struct conn_ctl_s)) {
                    ERROR("[L7Probe]: Invalid conn tracker ctrl msg.\n");
                    return 0;
                }
                (void)proc_conn_ctl_msg(l7_mng, (struct conn_ctl_s *)p);
                walk_size = sizeof(struct conn_ctl_s);
                break;
            }
            case TRACKER_EVT_DATA:
            {
                if (remain_size < sizeof(struct conn_data_msg_s)) {
                    ERROR("[L7Probe]: Invalid conn tracker data msg.\n");
                    return 0;
                }
                conn_data_msg = (struct conn_data_msg_s *)p;
                conn_data_buf = p + sizeof(struct conn_data_msg_s);
                (void)proc_conn_data_msg(l7_mng, conn_data_msg, conn_data_buf);
                walk_size = sizeof(struct conn_data_msg_s) + conn_data_msg->payload_size;
                break;
            }
            default:
            {
                ERROR("[L7Probe]: Unknown conn tracker msg.\n");
                return 0;
            }
        }

        offset += walk_size;
        remain_size -= walk_size;
    } while (1);
    return 0;
}
