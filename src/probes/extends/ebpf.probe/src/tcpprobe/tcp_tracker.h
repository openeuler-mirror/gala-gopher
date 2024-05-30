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
    WIND_SIZE_1 = 0,         // (0 ~ 1000]
    WIND_SIZE_2,             // (1000 ~ 10000]
    WIND_SIZE_3,             // (10000 ~ 100000]
    WIND_SIZE_4,             // (100000 ~ 1000000]
    WIND_SIZE_5,             // (1000000 ~ 10000000]
    __MAX_WIND_SIZE
};

enum sockbuf_size_t {
    SOCKBUF_SIZE_1 = 0,         // (0 ~ 131072]
    SOCKBUF_SIZE_2,             // (131072 ~ 262144]
    SOCKBUF_SIZE_3,             // (262144 ~ 524288]
    SOCKBUF_SIZE_4,             // (524288 ~ 1048576]
    SOCKBUF_SIZE_5,             // (1048576 ~ 2097152]
    SOCKBUF_SIZE_6,             // (2097152 ~ 4194304]
    SOCKBUF_SIZE_7,             // (4194304 ~ 8388608]
    SOCKBUF_SIZE_8,             // (8388608 ~ 16777216]
    __MAX_SOCKBUF_SIZE
};

// unit: millisecond
enum rtt_size_t {
    RTT_SIZE_1 = 0,         // (0 ~ 50]
    RTT_SIZE_2,             // (50 ~ 100]
    RTT_SIZE_3,             // (100 ~ 200]
    RTT_SIZE_4,             // (200 ~ 500]
    RTT_SIZE_5,             // (500 ~ 1000]
    __MAX_RTT_SIZE
};

// unit: millisecond
enum rto_size_t {
    RTO_SIZE_1 = 0,         // (0 ~ 1000]
    RTO_SIZE_2,             // (1000 ~ 10000]
    RTO_SIZE_3,             // (10000 ~ 20000]
    RTO_SIZE_4,             // (20000 ~ 40000]
    RTO_SIZE_5,             // (40000 ~ 80000]
    __MAX_RTO_SIZE
};

// unit: nanosecond
enum delay_size_t {
    DELAY_SIZE_1 = 0,       // (0, 1000000]
    DELAY_SIZE_2,           // (1000000, 10000000]
    DELAY_SIZE_3,           // (10000000, 100000000]
    DELAY_SIZE_4,           // (100000000, 1000000000]
    DELAY_SIZE_5,           // (1000000000, 10000000000]
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

    SYN_SRTT_MAX,

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

enum tcp_historm_e {
    TCP_HISTORM_WIND_SND = 0,
    TCP_HISTORM_WIND_RCV,
    TCP_HISTORM_WIND_AVL_SND,
    TCP_HISTORM_WIND_SND_CWND,
    TCP_HISTORM_WIND_NOT_SENT,
    TCP_HISTORM_WIND_ACKED,
    TCP_HISTORM_WIND_REORDERING,

    TCP_HISTORM_SOCKBUF_SND,
    TCP_HISTORM_SOCKBUF_RCV,

    TCP_HISTORM_RTT_SRTT,
    TCP_HISTORM_RTT_RCV_RTT,
    TCP_HISTORM_RTT_SYN_SRTT,

    TCP_HISTORM_RTO,
    TCP_HISTORM_ATO,

    TCP_HISTORM_DELAY_TX,
    TCP_HISTORM_DELAY_RX,

    TCP_HISTORM_MAX
};

struct tcp_tracker_s {
    H_HANDLE;
    struct tcp_tracker_id_s id;
    u32 report_flags;
    char *src_ip;
    char *dst_ip;
    time_t last_report;
    time_t last_rcv_data;
    struct histo_bucket_s snd_cwnd_buckets[__MAX_WIND_SIZE];
    struct histo_bucket_s not_sent_buckets[__MAX_WIND_SIZE];
    struct histo_bucket_s not_acked_buckets[__MAX_WIND_SIZE];
    struct histo_bucket_s reordering_buckets[__MAX_WIND_SIZE];

    struct histo_bucket_s snd_wnd_buckets[__MAX_WIND_SIZE];
    struct histo_bucket_s rcv_wnd_buckets[__MAX_WIND_SIZE];
    struct histo_bucket_s avl_snd_wnd_buckets[__MAX_WIND_SIZE];

    struct histo_bucket_s srtt_buckets[__MAX_RTT_SIZE];
    struct histo_bucket_s rcv_rtt_buckets[__MAX_RTT_SIZE];
    struct histo_bucket_s syn_srtt_buckets[__MAX_RTT_SIZE];

    struct histo_bucket_s rto_buckets[__MAX_RTO_SIZE];
    struct histo_bucket_s ato_buckets[__MAX_RTO_SIZE];

    struct histo_bucket_s rcv_buf_buckets[__MAX_SOCKBUF_SIZE];
    struct histo_bucket_s snd_buf_buckets[__MAX_SOCKBUF_SIZE];

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
    time_t last_aging;
    struct ipc_body_s ipc_body;
    struct bpf_prog_s *tcp_progs;
    struct tcp_tracker_s *trackers;
    struct tcp_flow_tracker_s *flow_trackers;

    char *historms[TCP_HISTORM_MAX];
};

struct tcp_tracker_s* get_tcp_tracker(struct tcp_mng_s *tcp_mng, const void *link);
void destroy_tcp_tracker(struct tcp_tracker_s* tracker);
void destroy_tcp_trackers(struct tcp_mng_s *tcp_mng);

struct tcp_flow_tracker_s* get_tcp_flow_tracker(struct tcp_mng_s *tcp_mng, const void *link);
void destroy_tcp_flow_tracker(struct tcp_flow_tracker_s* tracker);
void destroy_tcp_flow_trackers(struct tcp_mng_s *tcp_mng);

#endif
