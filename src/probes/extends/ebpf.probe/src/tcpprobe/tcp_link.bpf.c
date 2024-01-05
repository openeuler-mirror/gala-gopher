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
 * Create: 2022-07-22
 * Description: tcp_probe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include <bpf/bpf_endian.h>
#include "bpf.h"
#include "tcp_link.h"

char g_linsence[] SEC("license") = "GPL";

static __always_inline void report_srtt(void *ctx, struct tcp_metrics_s *metrics)
{
    metrics->report_flags |= TCP_PROBE_SRTT;
    (void)bpfbuf_output(ctx, &tcp_output, metrics, sizeof(struct tcp_metrics_s));
    metrics->report_flags &= ~TCP_PROBE_SRTT;
}

static __always_inline struct sock_info_s* is_exist_tcp_link(struct sock *sk, char *is_exist)
{
    struct sock_info_s *sock_info = bpf_map_lookup_elem(&sock_map, &sk);
    if (sock_info) {
        *is_exist = (char)sock_info->tcp_link_ok;
        return sock_info;
    }
    return NULL;
}

static __always_inline int add_tcp_link(struct sock *sk, struct sock_info_s *info, u32 tgid)
{
    struct tcp_link_s link = {0};

    if (!is_valid_tgid(tgid)) {
        return -1;
    }

    info->tcp_link_ok = 1;
    info->proc_id = tgid;

    link.family = _(sk->sk_family);

    if (info->role == LINK_ROLE_CLIENT) {
        if (link.family == AF_INET) {
            link.c_ip = _(sk->sk_rcv_saddr);
            link.s_ip = _(sk->sk_daddr);
        } else {
            BPF_CORE_READ_INTO(&link.c_ip6, sk, sk_v6_rcv_saddr);
            BPF_CORE_READ_INTO(&link.s_ip6, sk, sk_v6_daddr);
        }
        link.s_port = bpf_ntohs(_(sk->sk_dport));
        link.c_port = _(sk->sk_num);
    } else {
        if (link.family == AF_INET) {
            link.s_ip = _(sk->sk_rcv_saddr);
            link.c_ip = _(sk->sk_daddr);
        } else {
            BPF_CORE_READ_INTO(&link.c_ip6, sk, sk_v6_rcv_saddr);
            BPF_CORE_READ_INTO(&link.s_ip6, sk, sk_v6_daddr);
        }
        link.s_port = _(sk->sk_num);
        link.c_port = bpf_ntohs(_(sk->sk_dport));
    }

    link.role = (u16)info->role;
    link.tgid = tgid;
    (void)bpf_get_current_comm(&link.comm, sizeof(link.comm));
    return create_tcp_link(sk, &link, info->syn_srtt);
}

KPROBE(tcp_set_state, pt_regs)
{
    struct sock_info_s tcp_sock_data = {0};
    u16 new_state = (u16)PT_REGS_PARM2(ctx);
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct tcp_sock *tcp_sock = (struct tcp_sock *)sk;
    u16 old_state = _(sk->sk_state);

    if (old_state == TCP_SYN_SENT && new_state == TCP_ESTABLISHED) {
        /* create sock object */
        tcp_sock_data.role = LINK_ROLE_CLIENT;
        (void)create_sock_obj(0, sk, &tcp_sock_data);
    }

    if (old_state == TCP_SYN_RECV && new_state == TCP_ESTABLISHED) {
        /* create sock object */
        tcp_sock_data.role = LINK_ROLE_SERVER;
        tcp_sock_data.syn_srtt = _(tcp_sock->srtt_us) >> 3; // microseconds to milliseconds
        (void)create_sock_obj(0, sk, &tcp_sock_data);
    }

    if (new_state == TCP_CLOSE || new_state == TCP_CLOSE_WAIT || new_state == TCP_FIN_WAIT1) {
        struct tcp_metrics_s *metrics;
        metrics = get_tcp_metrics(sk);
        if (metrics) {
            // for short connections, we expect to only report abnormal/rtt/txrx/delay metrics
            metrics->report_flags |= (TCP_PROBE_ABN | TCP_PROBE_RTT | TCP_PROBE_TXRX | TCP_PROBE_DELAY);
            (void)bpfbuf_output(ctx, &tcp_output, metrics, sizeof(struct tcp_metrics_s));
        }

        (void)delete_tcp_link(sk);
    }
    return 0;
}

KRAWTRACE(tcp_destroy_sock, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock *)ctx->args[0];
    delete_sock_obj(sk);
    return 0;
}

KPROBE(tcp_v4_destroy_sock, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    delete_sock_obj(sk);
    return 0;
}

SEC("tracepoint/tcp/tcp_destroy_sock")
void bpf_trace_tcp_destroy_sock_func(struct trace_event_raw_tcp_event_sk *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    delete_sock_obj(sk);
}

KPROBE(tcp_sendmsg, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sock_info_s *info;
    struct tcp_metrics_s *metrics;
    char tcp_link_exist = 0;

    info = is_exist_tcp_link(sk, &tcp_link_exist);
    if (tcp_link_exist || !info) {
        return 0;
    }

    /* create tcp sock from tcp fd */
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;

    (void)add_tcp_link(sk, info, tgid);
    metrics = get_tcp_metrics(sk);
    if (metrics) {
        report_srtt(ctx, metrics);
    }
    return 0;
}

KPROBE(tcp_recvmsg, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct tcp_metrics_s *metrics;
    struct sock_info_s *info;
    char tcp_link_exist = 0;

    info = is_exist_tcp_link(sk, &tcp_link_exist);
    if (tcp_link_exist || !info) {
        return 0;
    }

    /* create tcp sock from tcp fd */
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;

    (void)add_tcp_link(sk, info, tgid);
    metrics = get_tcp_metrics(sk);
    if (metrics) {
        report_srtt(ctx, metrics);
    }
    return 0;
}

