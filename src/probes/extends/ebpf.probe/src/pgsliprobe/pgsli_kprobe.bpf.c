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
#include <bpf/bpf_endian.h>
#include "pgsliprobe.h"
#include "pgsliprobe_bpf.h"

#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))

#define LO_IP4ADDR 16777343 // 127.0.0.1

char g_license[] SEC("license") = "GPL";

static __always_inline int init_conn_info(struct conn_info_t *conn_info, struct sock *sk)
{
    conn_info->client_ip_info.family = _(sk->sk_family);
    if (conn_info->client_ip_info.family == AF_INET) {
        conn_info->server_ip_info.ipaddr.ip4 = _(sk->sk_rcv_saddr);
        conn_info->client_ip_info.ipaddr.ip4 = _(sk->sk_daddr);
        if (conn_info->client_ip_info.ipaddr.ip4 == LO_IP4ADDR) {
            return SLI_ERR;
        }
    } else if (conn_info->client_ip_info.family == AF_INET6) {
        BPF_CORE_READ_INTO(conn_info->server_ip_info.ipaddr.ip6, sk, sk_v6_rcv_saddr);
        BPF_CORE_READ_INTO(conn_info->client_ip_info.ipaddr.ip6, sk, sk_v6_daddr);
    } else {
        return SLI_ERR;
    }

    conn_info->server_ip_info.port = _(sk->sk_num);
    conn_info->client_ip_info.port = _(sk->sk_dport);

    return SLI_OK;
}

static __always_inline int init_conn_samp_data(struct sock *sk)
{
    struct conn_samp_data_t csd = {.status = SAMP_INIT};
    return bpf_map_update_elem(&conn_samp_map, &sk, &csd, BPF_ANY);
}


static __always_inline void update_conn_map_n_conn_samp_map(struct conn_key_t *conn_key)
{
    struct conn_data_t conn_data = {0};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct sock *sk = sock_get_by_fd(conn_key->fd, task);
    if (sk == NULL) {
        return;
    }

    if (init_conn_info(&conn_data.conn_info, sk) < 0) {
        return;
    }

    if (init_conn_samp_data(sk) != SLI_OK) {
        return;
    }

    conn_data.sk = (void *)sk;
    bpf_map_update_elem(&conn_map, conn_key, &conn_data, BPF_ANY);
}

static __always_inline void process_sample_finish(struct conn_samp_data_t *csd, struct sock *sk)
{
    struct tcp_sock *tcp_sk = (struct tcp_sock *)sk;
    u32 snd_una = _(tcp_sk->snd_una);

    if (csd->status == SAMP_SKB_READY && csd->end_seq <= snd_una) {
        u64 end_ts_nsec = bpf_ktime_get_ns();
        if (end_ts_nsec < csd->start_ts_nsec) {
            csd->status = SAMP_INIT;
            return;
        }
        csd->rtt_ts_nsec = end_ts_nsec - csd->start_ts_nsec;
        csd->status = SAMP_FINISHED;
    }
}

KPROBE(__sys_recvfrom, pt_regs)
{
    int fd = (int)PT_REGS_PARM1(ctx);
    if (fd < 0) {
        return 0;
    }

    KPROBE_PARMS_STASH(__sys_recvfrom, ctx, CTX_USER);
    u32 tgid  = bpf_get_current_pid_tgid() >> INT_LEN;
    struct conn_key_t conn_key = {.fd = fd, .tgid = tgid};
    struct conn_data_t *conn_data = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
    if (conn_data != NULL && conn_data->sk != NULL) {
        return 0;
    }

    (void)update_conn_map_n_conn_samp_map(&conn_key);
    return 0;
}

KRETPROBE(__sys_recvfrom, pt_regs)
{
    struct probe_val val;
    if (PROBE_GET_PARMS(__sys_recvfrom, ctx, val, CTX_USER) < 0) {
        return 0;
    }

    int fd = (int)PROBE_PARM1(val);
    const char *buf = (const char *)PROBE_PARM2(val);
    int count = (int)PROBE_PARM3(val);

    process_rdwr_msg(fd, buf, count, MSG_READ, ctx);

    return 0;
}

KPROBE(__sys_sendto, pt_regs)
{
    int fd = (int)PT_REGS_PARM1(ctx);
    char *buf = (char *)PT_REGS_PARM2(ctx);
    int count = (int)PT_REGS_PARM3(ctx);
    process_rdwr_msg(fd, buf, count, MSG_WRITE, ctx);

    return 0;
}

KPROBE(close_fd, pt_regs)
{
    int fd = (int)PT_REGS_PARM2(ctx);
    if (fd < 0) {
        return 0;
    }

    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    struct conn_key_t conn_key = {.fd = fd, .tgid = tgid};
    struct conn_data_t *conn_data = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
    if (conn_data == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&conn_samp_map, &conn_data->sk);
    bpf_map_delete_elem(&conn_map, &conn_key);

    return 0;
}

KPROBE(__close_fd, pt_regs)
{
    int fd = (int)PT_REGS_PARM2(ctx);
    if (fd < 0) {
        return 0;
    }

    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    struct conn_key_t conn_key = {.fd = fd, .tgid = tgid};
    struct conn_data_t *conn_data = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
    if (conn_data == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&conn_samp_map, &conn_data->sk);
    bpf_map_delete_elem(&conn_map, &conn_key);

    return 0;
}

// static void tcp_event_new_data_sent(struct sock *sk, struct sk_buff *skb)
KPROBE(tcp_event_new_data_sent, pt_regs)
{
    struct sock *sk;
    struct sk_buff *skb;
    struct conn_samp_data_t *csd;

    sk = (struct sock *)PT_REGS_PARM1(ctx);
    skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    csd = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &sk);
    if (csd != (void *)0) {
        if (csd->status == SAMP_WRITE_READY) {
            csd->end_seq = _(TCP_SKB_CB(skb)->end_seq);
            csd->status = SAMP_SKB_READY;
        }
    }
    return 0;
}

KPROBE(tcp_clean_rtx_queue, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct conn_samp_data_t *csd;

    csd = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &sk);
    if (csd != (void *)0) {
        process_sample_finish(csd, sk);
    }
    return 0;
}

KPROBE_WITH_CONSTPROP(tcp_clean_rtx_queue, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct conn_samp_data_t *csd;

    csd = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &sk);
    if (csd != (void *)0) {
        process_sample_finish(csd, sk);
    }
    return 0;
}

KPROBE(tcp_recvmsg, pt_regs)
{
    struct sock *sk;
    struct conn_samp_data_t *csd;
    sk = (struct sock *)PT_REGS_PARM1(ctx);

    csd = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &sk);
    if (csd != (void *)0) {
        if ((csd->status == SAMP_FINISHED || csd->status == SAMP_INIT)) {
            if (sk != (void *)0) {
                struct sk_buff *skb = _(sk->sk_receive_queue.next);
                if (skb != (struct sk_buff *)(&sk->sk_receive_queue)){
                    csd->start_ts_nsec = _(skb->tstamp);
                }
            }
        }
    }
    return 0;
}
