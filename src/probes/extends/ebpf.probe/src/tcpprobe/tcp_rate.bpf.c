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

#if 0
static void tcp_compute_busy_time(struct tcp_sock *tcp_sk, struct tcp_rate* rate_stats)
{
    u32 i;
    u8 chrono_type;
    u32 chrono_stat[__TCP_CHRONO_MAX - 1] = {0};
    u32 chrono_start;
    u64 total = 0;
    u64 stats[__TCP_CHRONO_MAX];
    u64 ms = bpf_ktime_get_ns() >> 6; // ns -> ms

    chrono_start = _(tcp_sk->chrono_start);
    BPF_CORE_READ_INTO(chrono_stat, tcp_sk, chrono_stat);
    chrono_type = BPF_CORE_READ_BITFIELD_PROBED(tcp_sk, chrono_type);

#pragma clang loop unroll(full)
    for (i = TCP_CHRONO_BUSY; i < __TCP_CHRONO_MAX; ++i) {
        stats[i] = chrono_stat[i - 1];
        if (i == chrono_type)
            stats[i] += (ms > chrono_start) ? (ms - chrono_start) : 0;
        stats[i] *= USEC_PER_SEC / HZ;
        total += stats[i];
    }

    rate_stats->tcpi_busy_time = total;
    rate_stats->tcpi_rwnd_limited = stats[TCP_CHRONO_RWND_LIMITED];
    rate_stats->tcpi_sndbuf_limited = stats[TCP_CHRONO_SNDBUF_LIMITED];
}

static void tcp_compute_delivery_rate(struct tcp_sock *tcp_sk, struct tcp_rate* stats)
{
    u32 rate = _(tcp_sk->rate_delivered);
    u32 intv = _(tcp_sk->rate_interval_us);
    u32 mss_cache = _(tcp_sk->mss_cache);
    u64 rate64 = 0;

    if (rate && intv) {
        rate64 = (u64)rate * mss_cache * USEC_PER_SEC;
    }

    stats->tcpi_delivery_rate = rate64;
    return;
}
#endif

static __always_inline unsigned int jiffies_to_usecs(unsigned long j)
{
    return (USEC_PER_SEC / HZ) * j;
}

static void get_tcp_rate(struct sock *sk, struct tcp_rate* stats)
{
    u32 tmp;
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;

    tmp = jiffies_to_usecs(_(icsk->icsk_rto));
    stats->tcpi_rto = tmp;

    tmp = jiffies_to_usecs(_(icsk->icsk_ack.ato));
    stats->tcpi_ato = tmp;

#if 0
    stats->tcpi_snd_ssthresh = _(tcp_sk->snd_ssthresh);

    stats->tcpi_rcv_ssthresh = _(tcp_sk->rcv_ssthresh);

    stats->tcpi_advmss = _(tcp_sk->advmss);

    stats->tcpi_rcv_space = _(tcp_sk->rcvq_space.space);

    tcp_compute_delivery_rate(tcp_sk, stats);

    tcp_compute_busy_time(tcp_sk, stats);

    tmp = _(sk->sk_pacing_rate);
    if (tmp != ~0U) {
        stats->tcpi_pacing_rate = min_zero(stats->tcpi_pacing_rate, tmp);
    }

    tmp = _(sk->sk_max_pacing_rate);
    if (tmp != ~0U) {
        stats->tcpi_max_pacing_rate = min_zero(stats->tcpi_max_pacing_rate, tmp);
    }
#endif
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

