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

static __always_inline char is_tmout_sockbuf(struct sock *sk)
{
    struct sock_stats_s *sock_stats = bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (!sock_stats) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 period = get_period();
    if ((ts > sock_stats->ts_stats.sockbuf_ts) && ((ts - sock_stats->ts_stats.sockbuf_ts) >= period)) {
        sock_stats->ts_stats.sockbuf_ts = ts;
        return 1;
    }
    return 0;
}

static __always_inline void report_sockbuf(void *ctx, struct tcp_metrics_s *metrics)
{
    metrics->report_flags |= TCP_PROBE_SOCKBUF;

    (void)bpfbuf_output(ctx, &tcp_output, metrics, sizeof(struct tcp_metrics_s));

    metrics->report_flags &= ~TCP_PROBE_SOCKBUF;
    //__builtin_memset(&(metrics->sockbuf_stats), 0x0, sizeof(metrics->sockbuf_stats));
}

static void get_tcp_sock_buf(struct sock *sk, struct tcp_sockbuf* stats)
{
    stats->sk_rcvbuf    = (int)_(sk->sk_rcvbuf);
    stats->sk_sndbuf    = (int)_(sk->sk_sndbuf);

}

static void set_last_sockbuf_stats(struct tcp_sockbuf* stats, struct tcp_sockbuf* last_stats)
{
    __builtin_memcpy(last_stats, stats, sizeof(struct tcp_sockbuf));
}

static int is_sockbuf_stats_changed(struct tcp_sockbuf* stats, struct tcp_sockbuf* last_stats)
{
    if (last_stats->sk_rcvbuf != stats->sk_rcvbuf) {
        return 1;
    }

    if (last_stats->sk_sndbuf != stats->sk_sndbuf) {
        return 1;
    }
    return 0;
}

static void tcp_sockbuf_probe_func(void *ctx, struct sock *sk)
{
    struct tcp_metrics_s *metrics;
    struct tcp_sockbuf last_sockbuf_stats = {0};

    // Avoid high performance costs
    if (!is_tmout_sockbuf(sk)) {
        return;
    }

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        set_last_sockbuf_stats(&(metrics->sockbuf_stats), &last_sockbuf_stats);
        get_tcp_sock_buf(sk, &(metrics->sockbuf_stats));
        if (is_sockbuf_stats_changed(&(metrics->sockbuf_stats), &last_sockbuf_stats)) {
            report_sockbuf(ctx, metrics);
        }
    }
}

KRAWTRACE(tcp_probe, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock*)ctx->args[0];
    tcp_sockbuf_probe_func(ctx, sk);
    return 0;
}

KPROBE(tcp_rcv_established, pt_regs)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    tcp_sockbuf_probe_func(ctx, sk);
    return 0;
}
