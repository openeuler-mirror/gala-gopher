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
 * Description: tcp rate probe
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include <bpf/bpf_endian.h>
#include "bpf.h"
#include "tcp_link.h"

char g_linsence[] SEC("license") = "GPL";

static __always_inline char is_tmout_rate(struct sock *sk)
{
    struct sock_stats_s *sock_stats = bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (!sock_stats) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 period = get_period();
    if ((ts > sock_stats->ts_stats.rate_ts) && ((ts - sock_stats->ts_stats.rate_ts) >= period)) {
        sock_stats->ts_stats.rate_ts = ts;
        return 1;
    }
    return 0;
}

static __always_inline void report_rate(void *ctx, struct tcp_metrics_s *metrics)
{
    metrics->report_flags |= TCP_PROBE_RATE;
    (void)bpfbuf_output(ctx, &tcp_output, metrics, sizeof(struct tcp_metrics_s));
    metrics->report_flags &= ~TCP_PROBE_RATE;
    //__builtin_memset(&(metrics->rate_stats), 0x0, sizeof(metrics->rate_stats));
}

// when CONFIG_HZ is 1000
static void get_tcp_rate(struct sock *sk, struct tcp_rate* stats)
{
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    // For the conversion method of jiffies to ms, please refer to: 
    // jiffies_to_clock_t(in kernel) and get_user_hz(in iproute2)
    stats->tcpi_rto = _(icsk->icsk_rto); // ms
    stats->tcpi_ato = _(icsk->icsk_ack.ato); // ms
}

static void tcp_rate_probe_func(void *ctx, struct sock *sk)
{
    struct tcp_metrics_s *metrics;

    // Avoid high performance costs
    if (!is_tmout_rate(sk)) {
        return;
    }

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        get_tcp_rate(sk, &(metrics->rate_stats));
        report_rate(ctx, metrics);
    }
}

KRAWTRACE(tcp_rcv_space_adjust, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock*)ctx->args[0];
    tcp_rate_probe_func(ctx, sk);
    return 0;
}

KPROBE(tcp_rcv_space_adjust, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    tcp_rate_probe_func(ctx, sk);
    return 0;
}

SEC("tracepoint/tcp/tcp_rcv_space_adjust")
int bpf_trace_tcp_rcv_space_adjust_func(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    struct sock *sk = (struct sock*)ctx->skaddr;
    tcp_rate_probe_func(ctx, sk);
    return 0;
}

