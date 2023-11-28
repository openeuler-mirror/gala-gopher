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

static void tcp_abn_stats_probe_func(void *ctx, struct sock *sk)
{
    struct tcp_metrics_s *metrics;

    metrics = get_tcp_metrics(sk);
    if (metrics && get_tcp_abn_stats(sk, &(metrics->abn_stats))) {
        report_abn(ctx, metrics, sk, 1);
    }
}
#if (CURRENT_KERNEL_VERSION > KERNEL_VERSION(4, 18, 0))
KRAWTRACE(tcp_probe, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock*)ctx->args[0];
    tcp_abn_stats_probe_func(ctx, sk);
    return 0;
}
#else
KPROBE(tcp_rcv_established, pt_regs)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    tcp_abn_stats_probe_func(ctx, sk);
    return 0;
}
#endif

KPROBE_RET(tcp_add_backlog, pt_regs, CTX_KERNEL)
{
    bool discard = (bool)PT_REGS_RC(ctx);
    struct sock *sk;
    struct probe_val val;
    struct tcp_metrics_s *metrics;

    if (PROBE_GET_PARMS(tcp_add_backlog, ctx, val, CTX_KERNEL) < 0) {
        return 0;
    }

    if (discard) {
        sk = (struct sock *)PROBE_PARM1(val);

        metrics = get_tcp_metrics(sk);
        if (metrics) {
            TCP_BACKLOG_DROPS_INC(metrics->abn_stats);
            report_abn(ctx, metrics, sk, 0);
        }
    }
    return 0;
}

KPROBE_RET(tcp_filter, pt_regs, CTX_KERNEL)
{
    bool discard = (bool)PT_REGS_RC(ctx);
    struct sock *sk;
    struct probe_val val;
    struct tcp_metrics_s *metrics;

    if (PROBE_GET_PARMS(tcp_filter, ctx, val, CTX_KERNEL) < 0) {
        return 0;
    }

    if (discard) {
        sk = (struct sock *)PROBE_PARM1(val);
        metrics = get_tcp_metrics(sk);
        if (metrics) {
            TCP_FILTER_DROPS_INC(metrics->abn_stats);
            report_abn(ctx, metrics, sk, 0);
        }
    }
    return 0;
}
#ifndef TCP_WRITE_ERR_PROBE_OFF
KPROBE(tcp_write_err, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct tcp_metrics_s *metrics;

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_TMOUT_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 1);
    }
    return 0;
}
#endif
KRAWTRACE(sock_exceed_buf_limit, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock*)ctx->args[0];
    struct tcp_metrics_s *metrics;

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_SNDBUF_LIMIT_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 0);
    }
    return 0;
}

static int tcp_abn_snd_rsts_probe_func(void *ctx, struct sock *sk)
{
    struct tcp_metrics_s *metrics;

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_SEND_RSTS_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 1);
    }
    return 0;
}

static int tcp_abn_rcv_rsts_probe_func(void *ctx, struct sock *sk)
{
    struct tcp_metrics_s *metrics;

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_RECEIVE_RSTS_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 1);
    }
    return 0;
}

#if (CURRENT_KERNEL_VERSION > KERNEL_VERSION(4, 18, 0))
KRAWTRACE(tcp_send_reset, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock *)ctx->args[0];
    return tcp_abn_snd_rsts_probe_func(ctx, sk);
}

KRAWTRACE(tcp_receive_reset, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock *)ctx->args[0];
    return tcp_abn_rcv_rsts_probe_func(ctx, sk);
}
#elif (CURRENT_KERNEL_VERSION < KERNEL_VERSION(4, 13, 0))
static __always_inline unsigned char *__skb_transport_header(struct sk_buff *skb)
{
    return _(skb->head) + _(skb->transport_header);
}

static __always_inline struct tcphdr *__tcp_hdr(struct sk_buff *skb)
{
    return (struct tcphdr *)__skb_transport_header(skb);
}

static __always_inline int tcp_abn_snd_rsts_probe_precheck(struct sock *sk, struct sk_buff *skb)
{
    struct tcphdr *th;
    __u16 rst_flag = 0;

    if (sk == NULL || skb == NULL) {
        return 0;
    }

    th = __tcp_hdr(skb);
    /* rst is the llth bit of the byte after tcphdr:ack_seq */
    bpf_probe_read(&rst_flag, sizeof(rst_flag), (char *)&(th->ack_seq) + sizeof(th->ack_seq));
    rst_flag = (rst_flag >> 10) & 0x1;

    /* Will not send a reset in response to a reset. */
    if (rst_flag) {
        return 0;
    }

    /* only probe full socket(not a timewait or request socket) */
    if ((1 << _(sk->sk_state)) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV)) {
        return 1;
    }

    return 0;
}

/*
 * Tcp tracepoint does not exist in this version, so use kprobe as hook instead.
 *    tcp_send_reset --> tcp_v4_send_reset()/tcp_v6_send_reset()/tcp_send_active_reset()
 *    tcp_receive_reset --> tcp_reset()
 */
KPROBE(tcp_v4_send_reset, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    if (tcp_abn_snd_rsts_probe_precheck(sk, skb)) {
        tcp_abn_snd_rsts_probe_func(ctx, sk);
    }
    return 0;
}

KPROBE(tcp_v6_send_reset, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    if (tcp_abn_snd_rsts_probe_precheck(sk, skb)) {
        tcp_abn_snd_rsts_probe_func(ctx, sk);
    }
    return 0;
}

KPROBE(tcp_send_active_reset, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    tcp_abn_snd_rsts_probe_func(ctx, sk);
    return 0;
}

KPROBE(tcp_reset, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    tcp_abn_rcv_rsts_probe_func(ctx, sk);
    return 0;
}
#else
SEC("tracepoint/tcp/tcp_send_reset")
int bpf_trace_tcp_send_reset_func(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    return tcp_abn_snd_rsts_probe_func(ctx, sk);
}

SEC("tracepoint/tcp/tcp_receive_reset")
int bpf_trace_tcp_receive_reset_func(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    return tcp_abn_rcv_rsts_probe_func(ctx, sk);
}
#endif

KPROBE(tcp_retransmit_skb, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    int segs = (int)PT_REGS_PARM3(ctx);
    struct tcp_metrics_s *metrics;

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_RETRANS_INC(metrics->abn_stats, segs);
        report_abn(ctx, metrics, sk, 0);
    }
    return 0;
}

KPROBE_RET(tcp_try_rmem_schedule, pt_regs, CTX_KERNEL)
{
    int ret = (int)PT_REGS_RC(ctx);
    struct sock *sk;
    struct probe_val val;
    struct tcp_metrics_s *metrics;

    if (PROBE_GET_PARMS(tcp_try_rmem_schedule, ctx, val, CTX_KERNEL) < 0) {
        return 0;
    }

    if (ret == 0) {
        return 0;
    }

    sk = (struct sock *)PROBE_PARM1(val);
    if (sk == (void *)0) {
        return 0;
    }

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_RMEM_SCHEDULS_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 0);
    }

    return 0;
}

KPROBE_RET(tcp_check_oom, pt_regs, CTX_KERNEL)
{
    bool ret = (bool)PT_REGS_RC(ctx);
    struct sock *sk;
    struct probe_val val;

    struct tcp_metrics_s *metrics;

    if (PROBE_GET_PARMS(tcp_check_oom, ctx, val, CTX_KERNEL) < 0) {
        return 0;
    }

    if (!ret) {
        return 0;
    }

    sk = (struct sock *)PROBE_PARM1(val);
    if (sk == (void *)0) {
        return 0;
    }

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_OOM_INC(metrics->abn_stats);
        report_abn(ctx, metrics, sk, 0);
    }

    return 0;
}
