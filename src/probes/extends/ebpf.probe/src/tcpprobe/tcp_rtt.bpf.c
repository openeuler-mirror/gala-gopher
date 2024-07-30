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

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include <bpf/bpf_endian.h>
#include "bpf.h"
#include "tcp_link.h"

char g_linsence[] SEC("license") = "GPL";

static __always_inline char is_tmout_rtt(struct sock *sk)
{
    struct sock_stats_s *sock_stats = bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (!sock_stats) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 period = get_period();
    if ((ts > sock_stats->ts_stats.rtt_ts) && ((ts - sock_stats->ts_stats.rtt_ts) >= period)) {
        sock_stats->ts_stats.rtt_ts = ts;
        return 1;
    }
    return 0;
}

static __always_inline void report_rtt(void *ctx, struct tcp_metrics_s *metrics)
{
    metrics->report_flags |= TCP_PROBE_RTT;

    (void)bpfbuf_output(ctx, &tcp_output, metrics, sizeof(struct tcp_metrics_s));

    metrics->report_flags &= ~TCP_PROBE_RTT;
    //__builtin_memset(&(metrics->rtt_stats), 0x0, sizeof(metrics->rtt_stats));
}

static void get_tcp_rtt(struct sock *sk, struct tcp_rtt* stats)
{
    u32 tmp;
    struct tcp_sock *tcp_sk = (struct tcp_sock *)sk;

    tmp = _(tcp_sk->srtt_us) >> 3; // srtt_us is averaged rtt << 3 in usecs
    stats->tcpi_srtt = tmp;

    tmp = _(tcp_sk->rcv_rtt_est.rtt_us);
    tmp = tmp >> 3; // likewise
    stats->tcpi_rcv_rtt = tmp;
    return;
}

static void tcp_rtt_probe_func(void *ctx, struct sock *sk)
{
    struct tcp_metrics_s *metrics;

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        get_tcp_rtt(sk, &(metrics->rtt_stats));

        // Avoid high performance costs
        if (!is_tmout_rtt(sk)) {
            return;
        }

        report_rtt(ctx, metrics);
    }
}

KRAWTRACE(tcp_probe, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock*)ctx->args[0];
    tcp_rtt_probe_func(ctx, sk);
    return 0;
}

KPROBE(tcp_rcv_established, pt_regs)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    tcp_rtt_probe_func(ctx, sk);
    return 0;
}

