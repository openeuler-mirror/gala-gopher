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
 * Author: luzhiaho
 * Create: 2023-07-03
 * Description: tcp tracker
 ******************************************************************************/
#ifndef __TCP_TRACKER__H
#define __TCP_TRACKER__H

#include "bpf.h"
#include "histogram.h"
#include "ipc.h"
#include "hash.h"

enum wind_size_t {
    WIND_SIZE_1 = 0,         // (0 ~ 10000]
    WIND_SIZE_2,             // (10000 ~ 50000]
    WIND_SIZE_3,             // (50000 ~ 150000]
    WIND_SIZE_4,             // (150000 ~ 1000000]
    WIND_SIZE_5,             // (1000000 ~ 5000000]
    WIND_SIZE_6,             // (5000000 ~ 10000000]
    WIND_SIZE_7,             // (10000000 ~ 100000000]
    WIND_SIZE_8,             // (100000000 ~ 500000000]
    WIND_SIZE_9,             // (500000000 ~ 1000000000]
    WIND_SIZE_10,            // (1000000000 ~ 4294967295]
    __MAX_WIND_SIZE
};

enum sockbuf_size_t {
    SOCKBUF_SIZE_1 = 0,         // (0 ~ 10000]
    SOCKBUF_SIZE_2,             // (10000 ~ 50000]
    SOCKBUF_SIZE_3,             // (50000 ~ 150000]
    SOCKBUF_SIZE_4,             // (150000 ~ 1000000]
    SOCKBUF_SIZE_5,             // (1000000 ~ 5000000]
    SOCKBUF_SIZE_6,             // (5000000 ~ 10000000]
    SOCKBUF_SIZE_7,             // (10000000 ~ 100000000]
    SOCKBUF_SIZE_8,             // (100000000 ~ 500000000]
    SOCKBUF_SIZE_9,             // (500000000 ~ 1000000000]
    SOCKBUF_SIZE_10,            // (1000000000 ~ 4294967295]
    __MAX_SOCKBUF_SIZE
};

enum rtt_size_t {
    RTT_SIZE_1 = 0,         // (0 ~ 500]
    RTT_SIZE_2,             // (500 ~ 1000]
    RTT_SIZE_3,             // (1000 ~ 5000]
    RTT_SIZE_4,             // (5000 ~ 10000]
    RTT_SIZE_5,             // (10000 ~ 20000]
    RTT_SIZE_6,             // (20000 ~ 50000]
    RTT_SIZE_7,             // (50000 ~ 100000]
    RTT_SIZE_8,             // (100000 ~ 200000]
    RTT_SIZE_9,             // (200000 ~ 500000]
    RTT_SIZE_10,            // (500000 ~ 1000000]
    __MAX_RTT_SIZE
};

enum rto_size_t {
    RTO_SIZE_1 = 0,         // (0 ~ 500]
    RTO_SIZE_2,             // (500 ~ 1000]
    RTO_SIZE_3,             // (1000 ~ 5000]
    RTO_SIZE_4,             // (5000 ~ 10000]
    RTO_SIZE_5,             // (10000 ~ 20000]
    RTO_SIZE_6,             // (20000 ~ 50000]
    RTO_SIZE_7,             // (50000 ~ 100000]
    RTO_SIZE_8,             // (100000 ~ 200000]
    RTO_SIZE_9,             // (200000 ~ 500000]
    RTO_SIZE_10,            // (500000 ~ 1000000]
    __MAX_RTO_SIZE
};

enum delay_size_t {
    DELAY_SIZE_1 = 0,       // (0, 1]
    DELAY_SIZE_2,           // (1, 10]
    DELAY_SIZE_3,           // (10, 100]
    DELAY_SIZE_4,           // (100, 1000]
    DELAY_SIZE_5,           // (1000, 10000]
    DELAY_SIZE_6,           // (10000, 100000]
    DELAY_SIZE_7,           // (100000, 1000000]
    __MAX_DELAY_SIZE
};

enum tcp_stats_t {
    BYTES_SENT = 0,
    BYTES_RECV,

    SEGS_SENT,
    SEGS_RECV,

    RETRANS,
    BACKLOG_DROPS,
    FILTER_DROPS,
    SK_DROPS,
    LOST_OUT,
    SACKED_OUT,

    TIME_OUT,
    SNDBUF_LIMIT,
    RMEM_SCHEDULES,
    TCP_OOM,
    SEND_RSTS,
    RECEIVE_RSTS,

    SYN_SRTT,

    ZERO_WIN_TX,
    ZERO_WIN_RX,

    __MAX_STATS
};

struct tcp_tracker_id_s {
    u32 tgid;     // process id
    char comm[TASK_COMM_LEN];
    union {
        u32 c_ip;
        unsigned char c_ip6[IP6_LEN];
    };
    union {
        u32 s_ip;
        unsigned char s_ip6[IP6_LEN];
    };
    u16 port;
    u16 family;
    u32 role;     // role: client:1/server:0
};

struct tcp_tracker_s {
    H_HANDLE;
    struct tcp_tracker_id_s id;
    u32 report_flags;
    char *src_ip;
    char *dst_ip;
    time_t last_report;
    time_t last_rcv_data;
    struct histo_bucket_s snd_wnd_buckets[__MAX_WIND_SIZE];
    struct histo_bucket_s rcv_wnd_buckets[__MAX_WIND_SIZE];
    struct histo_bucket_s avl_snd_wnd_buckets[__MAX_WIND_SIZE];
    struct histo_bucket_s snd_cwnd_buckets[__MAX_WIND_SIZE];

    struct histo_bucket_s not_sent_buckets[__MAX_WIND_SIZE];
    struct histo_bucket_s not_acked_buckets[__MAX_WIND_SIZE];
    struct histo_bucket_s reordering_buckets[__MAX_WIND_SIZE];

    struct histo_bucket_s srtt_buckets[__MAX_RTT_SIZE];
    struct histo_bucket_s rcv_rtt_buckets[__MAX_RTT_SIZE];
    struct histo_bucket_s syn_srtt_buckets[__MAX_RTT_SIZE];

    struct histo_bucket_s rto_buckets[__MAX_RTO_SIZE];
    struct histo_bucket_s ato_buckets[__MAX_RTO_SIZE];

    struct histo_bucket_s snd_buf_buckets[__MAX_SOCKBUF_SIZE];
    struct histo_bucket_s rcv_buf_buckets[__MAX_SOCKBUF_SIZE];

    u64 stats[__MAX_STATS];
    
    float zero_win_rx_ratio;
    float zero_win_tx_ratio;
};

struct tcp_flow_tracker_id_s {
    u32 tgid;     // process id
    char remote_ip[INET6_ADDRSTRLEN];
    u16 port;
    u32 role;     // role: client:1/server:0
};

struct tcp_flow_tracker_s {
    H_HANDLE;
    struct tcp_flow_tracker_id_s id;
    u32 report_flags;
    time_t last_report;
    time_t last_rcv_data;

    struct histo_bucket_s send_delay_buckets[__MAX_DELAY_SIZE];
    struct histo_bucket_s recv_delay_buckets[__MAX_DELAY_SIZE];
};

struct tcp_mng_s {
    u32 tcp_tracker_count;
    u32 tcp_flow_tracker_count;
    time_t last_scan;
    struct ipc_body_s ipc_body;
    struct bpf_prog_s *tcp_progs;
    struct tcp_tracker_s *trackers;
    struct tcp_flow_tracker_s *flow_trackers;
};

struct tcp_tracker_s* get_tcp_tracker(struct tcp_mng_s *tcp_mng, const void *link);
void destroy_tcp_tracker(struct tcp_tracker_s* tracker);
void destroy_tcp_trackers(struct tcp_mng_s *tcp_mng);

struct tcp_flow_tracker_s* get_tcp_flow_tracker(struct tcp_mng_s *tcp_mng, const void *link);
void destroy_tcp_flow_tracker(struct tcp_flow_tracker_s* tracker);
void destroy_tcp_flow_trackers(struct tcp_mng_s *tcp_mng);

#endif
