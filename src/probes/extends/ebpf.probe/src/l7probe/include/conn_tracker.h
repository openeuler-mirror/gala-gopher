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

#define MAX_MSG_LEN_SSL 1024

enum tracker_stats_t {
    BYTES_SENT,
    BYTES_RECV,

    DATA_EVT_SENT,
    DATA_EVT_RECV,

    INVALID_RECORDS,
    VALID_RECORDS,

    LAST_REPORTED_BYTES_SENT,
    LAST_REPORTED_BYTES_RECV,

    __MAX_TRACKER_STATS
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
    u64 timestamp_ns;
};

struct tracker_open_s {
    u64 timestamp_ns;
    union sockaddr_t remote_addr;
};

struct tracker_close_s {
    u64 timestamp_ns;

    u64 bytes_sent;
    u64 bytes_recv;
};

struct conn_tracker_s {
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
    u64 tracker_stats[__MAX_TRACKER_STATS];

    struct data_stream_s send_stream;
    struct data_stream_s recv_stream;
};

enum parse_rslt_e {
    PARSE_RSLT_UNKNOW,
    PARSE_RSLT_INVALID,
    PARSE_RSLT_INCOMPLETE,
    PARSE_RSLT_IGNORED,
    PARSE_RSLT_EOS,
    PARSE_RSLT_SUCCESS
};

struct parse_rslt_s {
    enum parse_rslt_e rslt;
};
struct ssl_msg_t {
    enum msg_event_rw_t msg_type;
    int fd;
    int tgid;
    int count;
    u64 ts_nsec;
    char msg[MAX_MSG_LEN_SSL];
};

void tracker_rcv_raw_evt(struct conn_tracker_s *tracker, struct conn_data_s *evt);
void tracker_rcv_stats_evt(struct conn_tracker_s *tracker, struct conn_stats_s *evt);
void tracker_rcv_ctrl_evt(struct conn_tracker_s *tracker, struct conn_ctl_s *evt);

void l7_sock_data_msg_handler(void *ctx, int cpu, void *data, unsigned int size);
void l7_conn_control_msg_handler(void *ctx, int cpu, void *data, unsigned int size);
void l7_conn_stats_msg_handler(void *ctx, int cpu, void *data, unsigned int size);
#endif

