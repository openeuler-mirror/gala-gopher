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

static __always_inline char is_tmout_txrx(struct sock *sk)
{
    struct sock_stats_s *sock_stats = bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (!sock_stats) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 period = get_period();
    if ((ts > sock_stats->ts.txrx_ts) && ((ts - sock_stats->ts.txrx_ts) >= period)) {
        sock_stats->ts.txrx_ts = ts;
        return 1;
    }
    return 0;
}

static __always_inline void report_tx_rx(void *ctx, struct tcp_metrics_s *metrics, struct sock *sk)
{
    // Avoid high performance costs
    if (!is_tmout_txrx(sk)) {
        return;
    }

    u32 last_time_segs_out = metrics->tx_rx_stats.segs_out;
    u32 last_time_segs_in = metrics->tx_rx_stats.segs_in;

    metrics->report_flags |= TCP_PROBE_TXRX;
    (void)bpfbuf_output(ctx, &tcp_output, metrics, sizeof(struct tcp_metrics_s));

    metrics->report_flags &= ~TCP_PROBE_TXRX;
    __builtin_memset(&(metrics->tx_rx_stats), 0x0, sizeof(metrics->tx_rx_stats));
    metrics->tx_rx_stats.last_time_segs_in = last_time_segs_in;
    metrics->tx_rx_stats.last_time_segs_out = last_time_segs_out;
}

static void get_tcp_tx_rx_segs(struct sock *sk, struct tcp_tx_rx* stats)
{
    struct tcp_sock *tcp_sk = (struct tcp_sock *)sk;

    stats->segs_in = _(tcp_sk->segs_in);

    stats->segs_out = _(tcp_sk->segs_out);
}

KPROBE(tcp_sendmsg_locked, pt_regs)
{
    struct tcp_metrics_s *metrics;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        TCP_TX_XADD(metrics->tx_rx_stats, size);
        report_tx_rx(ctx, metrics, sk);
    }
    return 0;
}

KPROBE(tcp_cleanup_rbuf, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    int copied = (int)PT_REGS_PARM2(ctx);
    struct tcp_metrics_s *metrics;

    if (copied <= 0) {
        return 0;
    }

    metrics = get_tcp_metrics(sk);
    if (metrics) {
        get_tcp_tx_rx_segs(sk, &metrics->tx_rx_stats);
        TCP_RX_XADD(metrics->tx_rx_stats, copied);
        report_tx_rx(ctx, metrics, sk);
    }
    return 0;
}

