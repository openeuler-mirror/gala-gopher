/*
 * bpf code runs in the Linux kernel
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

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

#ifndef TCP_FD_BPF
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} tcp_output SEC(".maps");
#endif

#define __TCP_FD_MAX (50)
// Used to identifies the TCP pid and fd.
// Temporary MAP. Data exists only in the startup phase.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32)); // tgid
    __uint(value_size, sizeof(struct tcp_fd_info));
    __uint(max_entries, __TCP_FD_MAX);
} tcp_fd_map SEC(".maps");

#define __PERIOD    NS(30)
static __always_inline __maybe_unused u64 get_period(void)
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

static __always_inline __maybe_unused u32 get_probe_flags(void)
{
    u32 key = 0;
    struct tcp_args_s *args;

    args = (struct tcp_args_s *)bpf_map_lookup_elem(&args_map, &key);
    if (args) {
        return args->probe_flags;
    }

    return 0;
}

static __always_inline __maybe_unused char is_valid_tgid(u32 tgid)
{
    struct proc_s obj = {.proc_id = tgid};

    return is_proc_exist(&obj);
}

static __always_inline __maybe_unused int create_tcp_link(struct sock *sk, struct tcp_link_s *link, u32 syn_srtt)
{
    struct sock_stats_s sock_stats = {0};

    sock_stats.metrics.srtt_stats.syn_srtt = syn_srtt;
    __builtin_memcpy(&(sock_stats.metrics.link), link, sizeof(struct tcp_link_s));
    u64 ts = bpf_ktime_get_ns();
    sock_stats.ts.abn_ts = ts;
    sock_stats.ts.txrx_ts = ts;

    return bpf_map_update_elem(&tcp_link_map, &sk, &sock_stats, BPF_ANY);
}

static __always_inline __maybe_unused int delete_tcp_link(struct sock *sk)
{
    return bpf_map_delete_elem(&tcp_link_map, &sk);
}

static __always_inline __maybe_unused void reset_sock_obj_link_state(struct sock *sk)
{
    struct sock_info_s *sock_info = bpf_map_lookup_elem(&sock_map, &sk);
    if (sock_info) {
        sock_info->tcp_link_ok = 0;
    }
}

static __always_inline __maybe_unused struct tcp_metrics_s *get_tcp_metrics(struct sock *sk)
{
    struct sock_stats_s *sock_stats;

    sock_stats = (struct sock_stats_s *)bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (sock_stats == NULL) {
        return NULL;
    }

    if (is_valid_tgid(sock_stats->metrics.link.tgid)) {
        return &(sock_stats->metrics);
    }
    (void)delete_tcp_link(sk);
    reset_sock_obj_link_state(sk);
    return NULL;
}

static __always_inline __maybe_unused int create_sock_obj(u32 tgid, struct sock *sk, struct sock_info_s *info)
{
    info->proc_id = tgid;
    return bpf_map_update_elem(&sock_map, &sk, info, BPF_ANY);
}

static __always_inline __maybe_unused void delete_sock_obj(struct sock *sk)
{
    (void)bpf_map_delete_elem(&sock_map, &sk);
}

#endif

#endif
