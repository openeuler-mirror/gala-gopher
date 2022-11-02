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
 * Description: tcp abnormal probe
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include <bpf/bpf_endian.h>
#include "bpf.h"
#include "tcp_link.h"

char g_linsence[] SEC("license") = "GPL";

static __always_inline char is_tmout_abn(struct sock *sk)
{
    struct sock_stats_s *sock_stats = bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (!sock_stats) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 period = get_period();
    if ((ts > sock_stats->ts_stats.abn_ts) && ((ts - sock_stats->ts_stats.abn_ts) >= period)) {
        sock_stats->ts_stats.abn_ts = ts;
        return 1;
    }
    return 0;
}

static __always_inline void report_abn(void *ctx, struct tcp_metrics_s *metrics, struct sock *sk, char immed)
{
    if (!immed) {
        if (!is_tmout_abn(sk)) {
            return;
        }
    }
    metrics->report_flags |= TCP_PROBE_ABN;
    u32 last_time_sk_drops = metrics->abn_stats.sk_drops;
    u32 last_time_lost_out = metrics->abn_stats.lost_out;
    u32 last_time_sacked_out = metrics->abn_stats.sacked_out;

    (void)bpf_perf_event_output(ctx, &tcp_output, BPF_F_CURRENT_CPU, metrics, sizeof(struct tcp_metrics_s));

    __builtin_memset(&(metrics->abn_stats), 0x0, sizeof(metrics->abn_stats));
    metrics->abn_stats.last_time_sk_drops = last_time_sk_drops;
    metrics->abn_stats.last_time_lost_out = last_time_lost_out;
    metrics->abn_stats.last_time_sacked_out = last_time_sacked_out;
    metrics->report_flags &= ~TCP_PROBE_ABN;
}

static int get_tcp_abn_stats(struct sock *sk, struct tcp_abn* stats)
{
    struct tcp_sock *tcp_sk = (struct tcp_sock *)sk;

    stats->sk_err = _(sk->sk_err);
    stats->sk_err_soft = _(sk->sk_err_soft);
    stats->sk_drops = _(sk->sk_drops.counter);
    stats->lost_out = _(tcp_sk->lost_out);
    stats->sacked_out = _(tcp_sk->sacked_out);

    if ((stats->sk_drops > stats->last_time_sk_drops)
        || (stats->lost_out > stats->last_time_lost_out)
        || (stats->sacked_out > stats->last_time_sacked_out)) {
        return 1;
    }

    return 0;
}

KRAWTRACE(tcp_probe, bpf_raw_tracepoint_args)
{
    struct tcp_metrics_s *metrics;
    struct sock *sk = (struct sock*)ctx->args[0];
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    // Avoid high performance costs
    if (!is_tmout_abn(sk)) {
        return;
    }

    metrics = get_tcp_metrics(sk);
    if (metrics && get_tcp_abn_stats(sk, &(metrics->abn_stats))) {
        report_abn(ctx, metrics, sk, 1);
    }
}

KPROBE_RET(tcp_add_backlog, pt_regs, CTX_KERNEL)
{
    bool discard = (bool)PT_REGS_RC(ctx);
    struct sock *sk;
    struct probe_val val;
    struct tcp_metrics_s *metrics;

    if (PROBE_GET_PARMS(tcp_add_backlog, ctx, val, CTX_KERNEL) < 0) {
        return;
    }

    if (discard) {
        sk = (struct sock *)PROBE_PARM1(val);

        metrics = get_tcp_metrics(sk);
        if (metrics) {
            TCP_BACKLOG_DROPS_INC(metrics->abn_stats);
            report_abn(ctx, metrics, sk, 0);
        }
    }
}

KPROBE_RET(tcp_filter, pt_regs, CTX_KERNEL)
{
    bool discard = (bool)PT_REGS_RC(ctx);
    struct sock *sk;
    struct probe_val val;
    struct tcp_metrics_s *metrics;

    if (PROBE_GET_PARMS(tcp_filter, ctx, val, CTX_KERNEL) < 0) {
        return;
    }

    if (discard) {

        sk = (struct sock *)PROBE_PARM1(val);
        metrics = get_tcp_metrics(sk);
        if (metrics) {
            TCP_FILTER_DROPS_INC(metrics->abn_stats);
            report_abn(ctx, metrics, sk, 0);
        }
    }
}
#ifndef TCP_WRITE_ERR_PROBE_OFF
KPROBE(tcp_write_err, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct tcp_metrics_s *metrics;
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_TMOUT_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 1);
    }
}
#endif
KRAWTRACE(sock_exceed_buf_limit, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock*)ctx->args[0];
    struct tcp_metrics_s *metrics;
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_SNDBUF_LIMIT_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 0);
    }
}

KRAWTRACE(tcp_send_reset, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock *)ctx->args[0];
    struct tcp_metrics_s *metrics;
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_SEND_RSTS_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 1);
    }
}

KRAWTRACE(tcp_receive_reset, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock *)ctx->args[0];
    struct tcp_metrics_s *metrics;
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_RECEIVE_RSTS_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 1);
    }
}

KPROBE(tcp_retransmit_skb, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    int segs = (int)PT_REGS_PARM3(ctx);
    struct tcp_metrics_s *metrics;
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_RETRANS_INC(metrics->abn_stats, segs);
        report_abn(ctx, metrics, sk, 0);
    }
}

KPROBE_RET(tcp_try_rmem_schedule, pt_regs, CTX_KERNEL)
{
    int ret = (int)PT_REGS_RC(ctx);
    struct sock *sk;
    struct probe_val val;
    struct tcp_metrics_s *metrics;

    if (PROBE_GET_PARMS(tcp_try_rmem_schedule, ctx, val, CTX_KERNEL) < 0) {
        return;
    }

    if (ret == 0) {
        return;
    }

    sk = (struct sock *)PROBE_PARM1(val);
    if (sk == (void *)0) {
        return;
    }

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_RMEM_SCHEDULS_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 0);
    }

    return;
}

KPROBE_RET(tcp_check_oom, pt_regs, CTX_KERNEL)
{
    bool ret = (bool)PT_REGS_RC(ctx);
    struct sock *sk;
    struct probe_val val;

    struct tcp_metrics_s *metrics;

    if (PROBE_GET_PARMS(tcp_check_oom, ctx, val, CTX_KERNEL) < 0) {
        return;
    }

    if (!ret) {
        return;
    }

    sk = (struct sock *)PROBE_PARM1(val);
    if (sk == (void *)0) {
        return;
    }

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_OOM_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 0);
    }

    return;
}
