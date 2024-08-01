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
#include "bpf.h"
#include "tcp_link.h"

static __always_inline char is_tmout_delay(struct sock_stats_s *sock_stats)
{
    u64 curr_ts;

    curr_ts = bpf_ktime_get_ns();
    if (curr_ts > sock_stats->ts_stats.delay_ts + HIST_SAMPLE_PERIOD) {
        sock_stats->ts_stats.delay_ts = curr_ts;
        return 1;
    }
    return 0;
}

static __always_inline void report_delay(void *ctx, struct tcp_metrics_s *metrics)
{
    metrics->report_flags |= TCP_PROBE_DELAY;
    (void)bpfbuf_output(ctx, &tcp_output, metrics, sizeof(struct tcp_metrics_s));
    metrics->report_flags &= ~TCP_PROBE_DELAY;
    metrics->delay_stats.send_state = DELAY_SAMP_INIT;
    metrics->delay_stats.recv_state = DELAY_SAMP_INIT;
}

static __always_inline u64 get_recv_arrival_ts(struct sock *sk)
{
    u64 ts = 0;
    struct sk_buff *skb;

    skb = _(sk->sk_receive_queue.next);
    if (skb && skb != (struct sk_buff *)(&sk->sk_receive_queue)) {
        ts = _(skb->tstamp);
    }

    return ts;
}

static __always_inline void process_recv_finish(struct sock *sk, struct sock_stats_s *sock_stats, void *ctx)
{
    struct tcp_delay *delay_stats;
    u64 start_ts, curr_ts;

    delay_stats = &sock_stats->metrics.delay_stats;
    if (delay_stats->recv_state == DELAY_SAMP_FINISH) {
        if (!is_tmout_delay(sock_stats)) {
            return;
        }
        report_delay(ctx, &sock_stats->metrics);
    }

    curr_ts = bpf_ktime_get_ns();
    start_ts = get_recv_arrival_ts(sk);
    if (0 < start_ts && start_ts < curr_ts) {
        delay_stats->net_recv_delay = curr_ts - start_ts;
        delay_stats->recv_state = DELAY_SAMP_FINISH;
    }

    return;
}

KPROBE(tcp_recvmsg, pt_regs)
{
    struct sock *sk;
    struct sock_stats_s *sock_stats;

    sk = (struct sock *)PT_REGS_PARM1(ctx);
    sock_stats = (struct sock_stats_s *)bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (sock_stats == NULL) {
        return 0;
    }

    process_recv_finish(sk, sock_stats, ctx);
    return 0;
}

static __always_inline void process_send_start(struct sock *sk, struct sock_stats_s *sock_stats, void *ctx)
{
    struct tcp_delay *delay_stats;
    struct tcp_sock *tp;
    u32 write_seq;

    delay_stats = &sock_stats->metrics.delay_stats;
    if (delay_stats->send_state == DELAY_SAMP_FINISH) {
        if (!is_tmout_delay(sock_stats)) {
            return;
        }
        report_delay(ctx, &sock_stats->metrics);
    }

    tp = (struct tcp_sock *)sk;
    write_seq = _(tp->write_seq);
    if (delay_stats->send_state == DELAY_SAMP_START_READY) {
        if (delay_stats->write_seq <= write_seq) {
            return;
        }
    }
    delay_stats->write_start_ts = bpf_ktime_get_ns();
    delay_stats->write_seq = write_seq;
    delay_stats->send_state = DELAY_SAMP_START_READY;

    return;
}

KPROBE_RET(tcp_sendmsg, pt_regs, CTX_USER)
{
    int ret;
    struct sock *sk;
    struct sock_stats_s *sock_stats;
    struct probe_val val;

    ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }

    __builtin_memset(&val, 0, sizeof(struct probe_val));
    if (PROBE_GET_PARMS(tcp_sendmsg, ctx, val, CTX_USER) < 0) {
        return 0;
    }
    sk = (struct sock *)PROBE_PARM1(val);

    sock_stats = (struct sock_stats_s *)bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (sock_stats == NULL) {
        return 0;
    }

    process_send_start(sk, sock_stats, ctx);
    return 0;
}

static __always_inline void process_send_finish(struct sock *sk, struct sock_stats_s *sock_stats)
{
    struct tcp_delay *delay_stats;
    struct tcp_sock *tp;
    u32 snd_una;
    u64 curr_ts;

    delay_stats = &sock_stats->metrics.delay_stats;
    if (delay_stats->send_state != DELAY_SAMP_START_READY) {
        return;
    }

    tp = (struct tcp_sock *)sk;
    snd_una = _(tp->snd_una);
    if (delay_stats->write_seq <= snd_una) {
        curr_ts = bpf_ktime_get_ns();
        if (curr_ts > delay_stats->write_start_ts) {
            delay_stats->net_send_delay = curr_ts - delay_stats->write_start_ts;
            delay_stats->send_state = DELAY_SAMP_FINISH;
        } else {
            delay_stats->send_state = DELAY_SAMP_INIT;
        }
    }

    return;
}

KPROBE(tcp_clean_rtx_queue, pt_regs)
{
    struct sock *sk;
    struct sock_stats_s *sock_stats;

    sk = (struct sock *)PT_REGS_PARM1(ctx);
    sock_stats = (struct sock_stats_s *)bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (sock_stats == NULL) {
        return 0;
    }

    process_send_finish(sk, sock_stats);
    return 0;
}

/*
 * https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=e7ed11ee94
 * This commit added a const type of param to tcp_clean_rtx_queue so that the function in
 * /proc/kallsyms turns out to be tcp_clean_rtx_queue.constprop.0. But CONFIG_FPROBE is not
 * set in openEuler so we directly kprobe to it.
 */
KPROBE_WITH_CONSTPROP(tcp_clean_rtx_queue, pt_regs)
{
    struct sock *sk;
    struct sock_stats_s *sock_stats;

    sk = (struct sock *)PT_REGS_PARM1(ctx);
    sock_stats = (struct sock_stats_s *)bpf_map_lookup_elem(&tcp_link_map, &sk);
    if (sock_stats == NULL) {
        return 0;
    }

    process_send_finish(sk, sock_stats);
    return 0;
}

char g_licence[] SEC("license") = "GPL";