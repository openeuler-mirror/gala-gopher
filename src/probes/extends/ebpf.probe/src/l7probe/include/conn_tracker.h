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
 * Create: 2023-03-17
 * Description: connect tracker define
 ******************************************************************************/
#ifndef __CONN_TRACKER_H__
#define __CONN_TRACKER_H__

#pragma once

#include "include/connect.h"
#include "include/data_stream.h"
#include "histogram.h"
#include "hash.h"

#define MAX_MSG_LEN_SSL 1024

enum l7_stats_t {
    BYTES_SENT,
    BYTES_RECV,

    LAST_BYTES_SENT,
    LAST_BYTES_RECV,

    DATA_EVT_SENT,
    DATA_EVT_RECV,

    OPEN_EVT,
    CLOSE_EVT,

    REQ_COUNT,
    RSP_COUNT,
    ERR_COUNT,

    __MAX_STATS
};


enum tracker_state_t {
    TRACK_METRICS,
    TRACK_TRACING,
    TRACK_SILENT
};

enum msg_event_rw_t {
    MSG_READ,
    MSG_WRITE,
};

struct tracker_id_s {
    int tgid;
    int fd;
};

struct tracker_open_s {
    u64 timestamp_ns;
    struct conn_addr_s remote_addr;
};

struct tracker_close_s {
    u64 timestamp_ns;

    u64 bytes_sent;
    u64 bytes_recv;
};


enum latency_range_t {
    LT_RANGE_1 = 0,         // (0 ~ 1]ms
    LT_RANGE_2,             // (1 ~ 3]ms
    LT_RANGE_3,             // (3 ~ 10]ms
    LT_RANGE_4,             // (10 ~ 20]ms
    LT_RANGE_5,             // (20 ~ 50]ms
    LT_RANGE_6,             // (50 ~ 100]ms
    LT_RANGE_7,             // (100 ~ 300]ms
    LT_RANGE_8,             // (300 ~ 500]ms
    LT_RANGE_9,             // (500 ~ 1000]ms
    LT_RANGE_10,            // (1000 ~ 10000]ms

    __MAX_LT_RANGE
};

enum latency_t {
    LATENCY_P50 = 0,
    LATENCY_P90,
    LATENCY_P99,

    __MAX_LATENCY
};

enum throughput_t {
    THROUGHPUT_REQ = 0,
    THROUGHPUT_RESP,

    __MAX_THROUGHPUT
};

struct conn_tracker_s {
    H_HANDLE;
    struct tracker_id_s id;
    char is_ssl;
    char pad[3];
    enum l4_role_t l4_role;     // TCP client or server; udp unknow
    enum l7_role_t l7_role;     // RPC client or server
    enum proto_type_t protocol; // L7 protocol type
    // Keep the state of tracker
    // TRACK_METRICS: Only report metrics(eg.. tx/rx) and metadata(metrics label);
    // TRACK_TRACING: Report metrics, RPC tracing and metadata(metrics label);
    // TRACK_SILENT: Only report connection(eg.. open/close event) and metadata(metrics label);
    enum tracker_state_t tacker_state;
    struct tracker_open_s open_info;
    struct tracker_close_s close_info;
    u64 stats[__MAX_STATS];

    struct histo_bucket_s latency_buckets[__MAX_LT_RANGE];
    u64 latency_sum;

    float throughput[__MAX_THROUGHPUT];
    float latency[__MAX_LATENCY];
    float err_ratio;

    struct data_stream_s send_stream;
    struct data_stream_s recv_stream;

    struct record_buf_s records;
};

struct l7_info_s {
    char comm[TASK_COMM_LEN];
    char container_id[CONTAINER_ABBR_ID_LEN + 1];
    char pod_id[POD_ID_LEN + 1];
    char pod_ip[INET6_ADDRSTRLEN];
    char is_ssl;
    char pad[3];
};

struct l7_link_id_s {
    int tgid;
    struct conn_addr_s remote_addr;
    enum l4_role_t l4_role;     // TCP client or server; udp unknow
    enum l7_role_t l7_role;     // RPC client or server
    enum proto_type_t protocol; // L7 protocol type
};

struct l7_link_s {
    H_HANDLE;
    struct l7_link_id_s id;
    struct l7_info_s l7_info;
    u64 stats[__MAX_STATS];
    struct histo_bucket_s latency_buckets[__MAX_LT_RANGE];
    float throughput[__MAX_THROUGHPUT];
    float latency[__MAX_LATENCY];
    float err_ratio;
    u64 latency_sum;
    time_t last_rcv_data;
};

void destroy_trackers(void *ctx);
void destroy_links(void *ctx);
void l7_parser(void *ctx);
void report_l7(void *ctx);
void trakcer_data_msg_pb(void *ctx, int cpu, void *data, unsigned int size);
void trakcer_ctrl_msg_pb(void *ctx, int cpu, void *data, unsigned int size);
void trakcer_stats_msg_pb(void *ctx, int cpu, void *data, unsigned int size);
int trakcer_data_msg_rb(void *ctx, void *data, unsigned int size);
int trakcer_ctrl_msg_rb(void *ctx, void *data, unsigned int size);
int trakcer_stats_msg_rb(void *ctx, void *data, unsigned int size);

#endif

