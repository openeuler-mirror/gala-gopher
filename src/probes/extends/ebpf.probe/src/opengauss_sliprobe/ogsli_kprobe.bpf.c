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
 * Author: wo_cow
 * Create: 2022-8-16
 * Description: ogsli_kprobe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include <bpf/bpf_endian.h>
#include "opengauss_sli.h"
#include "opengauss_bpf.h"

#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))

char g_license[] SEC("license") = "GPL";

static __always_inline int init_conn_info(struct conn_info_t *conn_info, struct sock *sk)
{
    conn_info->client_ip_info.family = _(sk->sk_family);
    if (conn_info->client_ip_info.family == AF_INET) {
        conn_info->server_ip_info.ipaddr.ip4 = _(sk->sk_rcv_saddr);
        conn_info->client_ip_info.ipaddr.ip4 = _(sk->sk_daddr);
    } else if (conn_info->client_ip_info.family == AF_INET6) {
        bpf_probe_read(conn_info->server_ip_info.ipaddr.ip6, IP6_LEN, &sk->sk_v6_rcv_saddr);
        bpf_probe_read(conn_info->client_ip_info.ipaddr.ip6, IP6_LEN, &sk->sk_v6_daddr);
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

KPROBE(__sys_recvfrom, pt_regs)
{
    u32 tgid __maybe_unused = bpf_get_current_pid_tgid() >> INT_LEN;
    int fd = (int)PT_REGS_PARM1(ctx);
    if (fd < 0) {
        return;
    }

    struct conn_key_t conn_key = {.fd = fd, .tgid = tgid};
    struct conn_data_t *conn_data = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
    if (conn_data != NULL && conn_data->sk != NULL) {
        return;
    }
    
    (void)update_conn_map_n_conn_samp_map(&conn_key);

    return;
}

KPROBE(__close_fd, pt_regs)
{
    int fd = (int)PT_REGS_PARM2(ctx);
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;

    if (fd < 0) {
        return;
    }
    struct conn_key_t conn_key = {.fd = fd, .tgid = tgid};
    struct conn_data_t *conn_data = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
    if (conn_data == NULL) {
        return;
    }

    bpf_map_delete_elem(&conn_samp_map, &conn_data->sk);
    bpf_map_delete_elem(&conn_map, &conn_key);

    return;
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
}

KPROBE(tcp_clean_rtx_queue, pt_regs)
{
    struct sock *sk;
    struct tcp_sock *tcp_sk;
    u32 snd_una;
    struct conn_samp_data_t *csd;

    sk = (struct sock *)PT_REGS_PARM1(ctx);
    tcp_sk = (struct tcp_sock *)sk;
    snd_una = _(tcp_sk->snd_una);

    csd = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &sk);
    if (csd != (void *)0) {
        if (csd->status == SAMP_SKB_READY && csd->end_seq <= snd_una) {
            u64 end_ts_nsec = bpf_ktime_get_ns();
            if (end_ts_nsec < csd->start_ts_nsec) {
                csd->status = SAMP_INIT;
                return;
            }
            csd->rtt_ts_nsec = end_ts_nsec - csd->start_ts_nsec;
            csd->start_ts_nsec = 0;
            csd->status = SAMP_FINISHED;
        }
    }
}

#ifdef KERNEL_SUPPORT_TSTAMP
KPROBE(tcp_recvmsg, pt_regs)
{
    struct sock *sk;
    struct conn_samp_data_t *csd;
    sk = (struct sock *)PT_REGS_PARM1(ctx);

    csd = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &sk);
    if (csd != (void *)0) {
        if ((csd->status == SAMP_FINISHED || csd->status == SAMP_INIT)
            && (csd->start_ts_nsec == 0)) {
            if (sk != (void *)0) {
                struct sk_buff *skb = _(sk->sk_receive_queue.next);
                if (skb != (struct sk_buff *)(&sk->sk_receive_queue)){
                    csd->start_ts_nsec = _(skb->tstamp);
                }
            }
        }
    }
}
#endif
