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

#include "connect.h"
#include "data_stream.h"
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
    CLIENT_ERR_COUNT,
    SERVER_ERR_COUNT,

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
    struct conn_addr_s client_addr;
    struct conn_addr_s server_addr;
};

struct tracker_close_s {
    u64 timestamp_ns;

    u64 bytes_sent;
    u64 bytes_recv;
};


enum latency_range_t {
    LT_RANGE_1 = 0,         // (0 ~ 10]ms
    LT_RANGE_2,             // (10 ~ 50]ms
    LT_RANGE_3,             // (50 ~ 100]ms
    LT_RANGE_4,             // (100 ~ 500]ms
    LT_RANGE_5,             // (500 ~ 1000]ms
    LT_RANGE_6,             // (1000 ~ 3000]ms
    LT_RANGE_7,             // (3000 ~ 10000]ms

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
    char inactive;
    char pad[2];
    enum l4_role_t l4_role;     // TCP client or server; udp unknown
    enum l7_role_t l7_role;     // RPC client or server
    enum proto_type_t protocol; // L7 protocol type
    // Keep the state of tracker
    // TRACK_METRICS: Only report metrics(eg.. tx/rx) and metadata(metrics label);
    // TRACK_TRACING: Report metrics, RPC tracing and metadata(metrics label);
    // TRACK_SILENT: Only report connection(eg.. open/close event) and metadata(metrics label);
    enum tracker_state_t tacker_state;
    struct tracker_open_s open_info;
    struct tracker_close_s close_info;

    struct data_stream_s send_stream;
    struct data_stream_s recv_stream;

    struct record_buf_s records;
};

struct l7_info_s {
    char is_ssl;
    char pad[3];
};

struct l7_link_id_s {
    int tgid;
    struct conn_addr_s client_addr; // TCP client IP address;
    struct conn_addr_s server_addr; // TCP server IP address; UDP remote address;
    enum l4_role_t l4_role;     // TCP client or server; udp unknown
    enum l7_role_t l7_role;     // RPC client or server
    enum proto_type_t protocol; // L7 protocol type
};

/**
 * l7 api statistic
 */
struct l7_api_statistic_s {
    H_HANDLE;
    struct api_stats_id id;

    u64 stats[__MAX_STATS];
    struct histo_bucket_array_s latency_buckets;

    float throughput[__MAX_THROUGHPUT];
    float latency[__MAX_LATENCY];
    float err_ratio;
    u64 latency_sum;
    time_t last_rcv_data;

    float client_err_ratio;
    float server_err_ratio;
};

struct l7_latency_buckets_range {
    struct bucket_range_s latency_buckets[__MAX_LT_RANGE];
};

struct l7_link_s {
    H_HANDLE;
    struct l7_link_id_s id;
    struct l7_info_s l7_info;
    char *client_ip;
    char *server_ip;

    struct l7_api_statistic_s *l7_statistic;

    u64 stats[__MAX_STATS];
    struct histo_bucket_array_s latency_buckets;
    float throughput[__MAX_THROUGHPUT];
    float latency[__MAX_LATENCY];
    float err_ratio;
    u64 latency_sum;
    time_t last_rcv_data;
};

struct java_proc_s {
    H_HANDLE;
    int proc_id;
};

void destroy_trackers(void *ctx);
void destroy_links(void *ctx);
void destroy_unprobed_trackers_links(void *ctx);
void l7_parser(void *ctx);
void report_l7(void *ctx);

int tracker_msg(void *ctx, void *data, u32 size);
int tracker_msg_continue(void *ctx, void *data, u32 size);

#endif

