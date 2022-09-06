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
 * Create: 2022-07-28
 * Description: tcp windows probe
 ******************************************************************************/
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
    (void)bpf_perf_event_output(ctx, &tcp_output, BPF_F_CURRENT_CPU, metrics, sizeof(struct tcp_metrics_s));

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


KRAWTRACE(tcp_rcv_space_adjust, bpf_raw_tracepoint_args)
{
    struct tcp_metrics_s *metrics;
    struct tcp_windows last_win_stats = {0};
    struct sock *sk = (struct sock*)ctx->args[0];
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

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

