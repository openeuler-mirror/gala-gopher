/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2022-07-13
 * Description: tcp link defined
 ******************************************************************************/
#ifndef __TCP_LINK_H__
#define __TCP_LINK_H__

#pragma once

#ifdef BPF_PROG_KERN

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "tcpprobe.h"

#define HIST_SAMPLE_PERIOD NS(1)

#define __TCP_LINK_MAX (10 * 1024)
// Used to identifies the TCP link(including multiple establish tcp connection)
// and save TCP statistics.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct sock *));
    __uint(value_size, sizeof(struct sock_stats_s));
    __uint(max_entries, __TCP_LINK_MAX);
} tcp_link_map SEC(".maps");


#define __TCP_TUPLE_MAX (10 * 1024)
// Used to identifies the TCP sock object, and role of the SOCK object.
// Equivalent to TCP 5-tuple objects.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct sock *));
    __uint(value_size, sizeof(struct sock_info_s));
    __uint(max_entries, __TCP_TUPLE_MAX);
} sock_map SEC(".maps");

// args
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));  // const value 0
    __uint(value_size, sizeof(struct tcp_args_s)); // tcp probe args
    __uint(max_entries, 1);
} args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 64);
} tcp_output SEC(".maps");

#define __PERIOD    NS(30)
static __always_inline __maybe_unused u64 get_period()
{
    u32 key = 0;
    u64 period = __PERIOD;
    struct tcp_args_s *args;

    args = (struct tcp_args_s *)bpf_map_lookup_elem(&args_map, &key);
    if (args) {
        period = args->sample_period;
    }
    return period; // units from second to nanosecond
}

static __always_inline __maybe_unused int is_gopher_comm(void)
{
    char comm[TASK_COMM_LEN] = {0};

    (void)bpf_get_current_comm(&comm, sizeof(comm));

    if (comm[0] == 'M' && comm[1] == 'H' && comm[2] == 'D' && comm[3] == '-') {
        return 1;
    }
    return 0;
}

static __always_inline __maybe_unused char is_valid_tgid(u32 tgid)
{
    struct proc_s obj = {.proc_id = tgid};

    return is_proc_exist(&obj);
}

#define REPORT_START_DELAY_2    2
#define REPORT_START_DELAY_4    4
#define REPORT_START_DELAY_6    6
#define REPORT_START_DELAY_8    8
#define REPORT_START_DELAY_10   10
static __always_inline __maybe_unused int create_tcp_link(struct sock *sk, struct tcp_link_s *link, u32 syn_srtt)
{
    struct sock_stats_s sock_stats = {0};

    sock_stats.metrics.srtt_stats.syn_srtt = syn_srtt;
    __builtin_memcpy(&(sock_stats.metrics.link), link, sizeof(struct tcp_link_s));
    u64 ts = bpf_ktime_get_ns();
    sock_stats.ts_stats.abn_ts = ts;
    sock_stats.ts_stats.win_ts = ts + NS(REPORT_START_DELAY_2);
    sock_stats.ts_stats.rtt_ts = ts + NS(REPORT_START_DELAY_4);
    sock_stats.ts_stats.txrx_ts = ts + NS(REPORT_START_DELAY_6);
    sock_stats.ts_stats.sockbuf_ts = ts + NS(REPORT_START_DELAY_8);
    sock_stats.ts_stats.rate_ts = ts + NS(REPORT_START_DELAY_10);

    return bpf_map_update_elem(&tcp_link_map, &sk, &sock_stats, BPF_ANY);
}

static __always_inline __maybe_unused int delete_tcp_link(struct sock *sk)
{
    return bpf_map_delete_elem(&tcp_link_map, &sk);
}

static __always_inline __maybe_unused struct tcp_metrics_s *get_tcp_metrics(struct sock *sk) 
{
    struct sock_stats_s *sock_stats;

    sock_stats = (struct sock_stats_s *)bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (sock_stats) {
        return &(sock_stats->metrics);
    }
    return NULL;
}

static __always_inline __maybe_unused int create_sock_obj(u32 tgid, struct sock *sk, struct sock_info_s *info)
{
    if (is_gopher_comm()) {
        return 0;
    }

    info->proc_id = tgid;
    return bpf_map_update_elem(&sock_map, &sk, info, BPF_ANY);
}

static __always_inline __maybe_unused void delete_sock_obj(struct sock *sk)
{
    (void)bpf_map_delete_elem(&sock_map, &sk);
}

#endif

#endif
