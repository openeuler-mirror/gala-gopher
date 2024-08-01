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

static __always_inline char is_tmout_win(struct sock *sk)
{
    struct sock_stats_s *sock_stats = bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (!sock_stats) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 period = get_period();
    if ((ts > sock_stats->ts_stats.win_ts) && ((ts - sock_stats->ts_stats.win_ts) >= period)) {
        sock_stats->ts_stats.win_ts = ts;
        return 1;
    }
    return 0;
}

static __always_inline void report_windows(void *ctx, struct tcp_metrics_s *metrics)
{
    metrics->report_flags |= TCP_PROBE_WINDOWS;
    (void)bpfbuf_output(ctx, &tcp_output, metrics, sizeof(struct tcp_metrics_s));

    metrics->report_flags &= ~TCP_PROBE_WINDOWS;
    //__builtin_memset(&(metrics->win_stats), 0x0, sizeof(metrics->win_stats));
}

static void get_tcp_wnd(struct sock *sk, struct tcp_windows* stats)
{
    struct tcp_sock *tcp_sk = (struct tcp_sock *)sk;

    u32 write_seq = _(tcp_sk->write_seq);
    u32 snd_nxt = _(tcp_sk->snd_nxt);
    u32 snd_wnd = _(tcp_sk->snd_wnd);
    u32 snd_una = _(tcp_sk->snd_una);
    u32 rcv_wnd = _(tcp_sk->rcv_wnd);

    if (write_seq > snd_nxt) {
        stats->tcpi_notsent_bytes = write_seq - snd_nxt;
    }

    if (snd_nxt > snd_una) {
        stats->tcpi_notack_bytes = snd_nxt - snd_una;
    }

    stats->tcpi_snd_wnd = snd_wnd;
    stats->tcpi_avl_snd_wnd = snd_una + snd_wnd - snd_nxt;
    stats->tcpi_rcv_wnd = rcv_wnd;
    stats->tcpi_reordering = _(tcp_sk->reordering);
    stats->tcpi_snd_cwnd = _(tcp_sk->snd_cwnd);

    return;
}

static void set_last_win_stats(struct tcp_windows* stats, struct tcp_windows* last_stats)
{
    __builtin_memcpy(last_stats, stats, sizeof(struct tcp_windows));
}

static int is_win_stats_changed(struct tcp_windows* stats, struct tcp_windows* last_stats)
{
    if (stats->tcpi_notsent_bytes != last_stats->tcpi_notsent_bytes) {
        return 1;
    }
    if (stats->tcpi_notack_bytes != last_stats->tcpi_notack_bytes) {
        return 1;
    }
    if (stats->tcpi_snd_wnd != last_stats->tcpi_snd_wnd) {
        return 1;
    }
    if (stats->tcpi_avl_snd_wnd != last_stats->tcpi_avl_snd_wnd) {
        return 1;
    }
    if (stats->tcpi_rcv_wnd != last_stats->tcpi_rcv_wnd) {
        return 1;
    }
    if (stats->tcpi_reordering != last_stats->tcpi_reordering) {
        return 1;
    }
    if (stats->tcpi_snd_cwnd != last_stats->tcpi_snd_cwnd) {
        return 1;
    }

    return 0;
}

static void tcp_wnd_probe_func(void *ctx, struct sock *sk)
{
    struct tcp_metrics_s *metrics;
    struct tcp_windows last_win_stats = {0};

    // Avoid high performance costs
    if (!is_tmout_win(sk)) {
        return;
    }

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        set_last_win_stats(&(metrics->win_stats), &last_win_stats);
        get_tcp_wnd(sk, &(metrics->win_stats));
        if (is_win_stats_changed(&(metrics->win_stats), &last_win_stats)) {
            report_windows(ctx, metrics);
        }
    }
}

KRAWTRACE(tcp_rcv_space_adjust, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock*)ctx->args[0];
    tcp_wnd_probe_func(ctx, sk);
    return 0;
}

KPROBE(tcp_rcv_space_adjust, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    tcp_wnd_probe_func(ctx, sk);
    return 0;
}

SEC("tracepoint/tcp/tcp_rcv_space_adjust")
int bpf_trace_tcp_rcv_space_adjust_func(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    struct sock *sk = (struct sock*)ctx->skaddr;
    tcp_wnd_probe_func(ctx, sk);
    return 0;
}
