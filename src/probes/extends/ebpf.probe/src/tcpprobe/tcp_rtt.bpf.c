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
 * Description: tcp rtt probe
 ******************************************************************************/
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

    (void)bpf_perf_event_output(ctx, &tcp_output, BPF_F_CURRENT_CPU, metrics, sizeof(struct tcp_metrics_s));

    metrics->report_flags &= ~TCP_PROBE_RTT;
    //__builtin_memset(&(metrics->rtt_stats), 0x0, sizeof(metrics->rtt_stats));
}

static void get_tcp_rtt(struct sock *sk, struct tcp_rtt* stats)
{
    u32 tmp;
    struct tcp_sock *tcp_sk = (struct tcp_sock *)sk;

    tmp = _(tcp_sk->srtt_us) >> 3;  // microseconds to milliseconds
    stats->tcpi_srtt = tmp;

    tmp = _(tcp_sk->rcv_rtt_est.rtt_us);
    tmp = tmp >> 3; // microseconds to milliseconds
    stats->tcpi_rcv_rtt = tmp;
    return;
}

static void tcp_rtt_probe_func(void *ctx, struct sock *sk)
{
    struct tcp_metrics_s *metrics;

    // Avoid high performance costs
    if (!is_tmout_rtt(sk)) {
        return;
    }

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        get_tcp_rtt(sk, &(metrics->rtt_stats));
        report_rtt(ctx, metrics);
    }
}
#if (CURRENT_KERNEL_VERSION > KERNEL_VERSION(4, 18, 0))
KRAWTRACE(tcp_probe, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock*)ctx->args[0];
    tcp_rtt_probe_func(ctx, sk);
    return 0;
}
#else
KPROBE(tcp_rcv_established, pt_regs)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    tcp_rtt_probe_func(ctx, sk);
    return 0;
}
#endif

