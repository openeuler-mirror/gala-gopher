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
#include "toa.h"
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
            BPF_CORE_READ_INTO(&link.s_ip6, sk, sk_v6_rcv_saddr);
            BPF_CORE_READ_INTO(&link.c_ip6, sk, sk_v6_daddr);
        }
        link.s_port = _(sk->sk_num);
        link.c_port = bpf_ntohs(_(sk->sk_dport));
    }

    link.role = (u16)info->role;
    link.tgid = tgid;
    (void)bpf_get_current_comm(&link.comm, sizeof(link.comm));
    return create_tcp_link(sk, &link, info->syn_srtt);
}

static __always_inline void get_tcp_tx_rx_segs(struct sock *sk, struct tcp_tx_rx* stats)
{
    struct tcp_sock *tcp_sk = (struct tcp_sock *)sk;

    stats->segs_in = _(tcp_sk->segs_in);
    stats->segs_out = _(tcp_sk->segs_out);
}

// for short connections, we expect to only report abnormal/rtt/txrx/delay metrics
#define TCP_CLOSE_FLAG (TCP_PROBE_TCP_CLOSE | TCP_PROBE_ABN | TCP_PROBE_RTT | TCP_PROBE_TXRX | TCP_PROBE_DELAY)
static __always_inline void report_tcp_close(void *ctx, struct sock *sk, struct tcp_metrics_s *metrics)
{
    metrics->report_flags |= TCP_CLOSE_FLAG;
    get_tcp_tx_rx_segs(sk, &metrics->tx_rx_stats);
    u32 last_time_sk_drops = metrics->abn_stats.sk_drops;
    u32 last_time_lost_out = metrics->abn_stats.lost_out;
    u32 last_time_segs_out = metrics->tx_rx_stats.segs_out;
    u32 last_time_segs_in = metrics->tx_rx_stats.segs_in;

    (void)bpfbuf_output(ctx, &tcp_output, metrics, sizeof(struct tcp_metrics_s));

    metrics->report_flags &= ~TCP_CLOSE_FLAG;

    // reset tcp abn metrics
    __builtin_memset(&(metrics->abn_stats), 0x0, sizeof(metrics->abn_stats));
    metrics->abn_stats.last_time_sk_drops = last_time_sk_drops;
    metrics->abn_stats.last_time_lost_out = last_time_lost_out;

    // reset tcp tx_rx metrics
    __builtin_memset(&(metrics->tx_rx_stats), 0x0, sizeof(metrics->tx_rx_stats));
    metrics->tx_rx_stats.last_time_segs_in = last_time_segs_in;
    metrics->tx_rx_stats.last_time_segs_out = last_time_segs_out;
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
        tcp_sock_data.syn_srtt = _(tcp_sock->srtt_us) >> 3; // srtt_us is averaged rtt << 3 in usecs
        (void)create_sock_obj(0, sk, &tcp_sock_data);
    }

    if (new_state == TCP_CLOSE) {
        struct tcp_metrics_s *metrics;
        metrics = get_tcp_metrics(sk);
        if (metrics) {
            report_tcp_close(ctx, sk, metrics);
        }
    }
    return 0;
}

KRAWTRACE(tcp_destroy_sock, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock *)ctx->args[0];
    (void)delete_tcp_link(sk);
    delete_sock_obj(sk);
    return 0;
}

KPROBE(tcp_v4_destroy_sock, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    (void)delete_tcp_link(sk);
    delete_sock_obj(sk);
    return 0;
}

SEC("tracepoint/tcp/tcp_destroy_sock")
void bpf_trace_tcp_destroy_sock_func(struct trace_event_raw_tcp_event_sk *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    (void)delete_tcp_link(sk);
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

#ifdef L4_TOA
static __always_inline void report_toa(void *ctx, struct tcp_metrics_s *metrics)
{
    metrics->report_flags |= TCP_PROBE_TOA;
    (void) bpfbuf_output(ctx, &tcp_output, metrics, sizeof(struct tcp_metrics_s));
    metrics->report_flags &= ~TCP_PROBE_TOA;
}

static __always_inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
    unsigned char *skb_hdr = _(skb->head);
    u16 network_header_offset = _(skb->network_header);

    return (skb_hdr + network_header_offset);
}

static __always_inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
    return (struct iphdr *) skb_network_header(skb);
}

static __always_inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
    return (struct ipv6hdr *) skb_network_header(skb);
}

static __always_inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
    return _(skb->head) + _(skb->transport_header);
}

static __always_inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
    return (struct tcphdr *)skb_transport_header(skb);
}

/* Parse TCP options in skb, try to get client ip, port
 * @param skb [in] received skb, it should be a ack/get-ack packet.
 * @return NULL if we don't get client ip/port;
 *         value of toa_data in ret_ptr if we get client ip/port.
 */
static void *get_toa_data(struct sk_buff *skb, int af, enum toa_type *type, struct toa_v6_entry *v6_toa_data)
{
    const struct tcphdr *th = NULL;
    int length;
    const unsigned char *ptr = NULL;
    void *ret_ptr = NULL;

    th = tcp_hdr((const struct sk_buff *) skb);

    u16 _doff = BPF_CORE_READ_BITFIELD_PROBED(th, doff);
    length = _doff * 4 - sizeof(struct tcphdr);
    if (length <= 0) {
        return NULL;
    }

    ptr = (const unsigned char *) (th + 1);
    if (ptr == NULL) {
        return NULL;
    }

    // todo: 流程可优化为：先解套opcode&偏移opsize，再解出toa_opt或toa_opt_v6
    // todo: 避免在低版本OS内核中因ebpf对循环的限制而导致不可用
    while (length > 0) {
        int opcode = _(*ptr);
        ptr++;
        int opsize;
        switch (opcode) {
            case TCPOPT_EOL: {
                *type = TOA_NOT;
                return NULL;
            }
            case TCPOPT_NOP:    /* Ref: RFC 793 section 3.1 */
                length--;
                continue;
            default:
                opsize = _(*ptr);
                ptr++;
                if (opsize < 2) {
                    /* "silly options" */
                    *type = TOA_NOT;
                    return NULL;
                }
                if (opsize > length) {
                    /* don't parse partial options */
                    *type = TOA_NOT;
                    return NULL;
                }

                if (af == AF_INET && opcode == TCPOPT_TOA && opsize == TCPOLEN_TOA) {
                    bpf_core_read(&ret_ptr, sizeof(struct toa_opt), ptr - 2);
                    *type = TOA_IPV4;
                    return ret_ptr;
                } else if (af == AF_INET6 && opcode == TCPOPT_TOA_V6 && opsize == TCPOLEN_TOA_V6) {
                    bpf_core_read(&v6_toa_data->toa_data, sizeof(struct toa_opt_v6), ptr - 2);
                    *type = TOA_IPV6;
                    return v6_toa_data;
                } else if (af == AF_INET6 && opcode == TCPOPT_TOA && opsize == TCPOLEN_TOA) {
                    bpf_core_read(&ret_ptr, sizeof(struct toa_opt), ptr - 2);
                    *type = TOA_IPV4;
                    return ret_ptr;
                }
                ptr += opsize - 2;
                length -= opsize;
        }
    }

    *type = TOA_NOT;
    return NULL;
}

/**
 * Modify s_ip of link from TCP Option
 *
 * @param link tcp link
 * @param info sock_info
 * @param skb sk_buff
 */
static bool get_toa_from_opt(struct sk_buff *skb, struct tcp_link_s *link)
{
    // 1. Specify af according to IP-Protocol
    int af = -1;
    u16 protocol = BPF_CORE_READ(skb, protocol);
    if (protocol == bpf_htons(ETH_P_IP)) {
        af = AF_INET;
    } else if (protocol == bpf_htons(ETH_P_IPV6)) {
        af = AF_INET6;
    } else {
        return false;
    }

    // 2. Get toa_data from skb, and set is_toa flag
    void *toa_data_ptr = NULL;
    struct toa_v6_entry v6_toa_data = {0};
    enum toa_type type = TOA_NOT;
    toa_data_ptr = get_toa_data(skb, af, &type, &v6_toa_data);
    if (toa_data_ptr == NULL || type == TOA_NOT) {
        return false;
    }

    // 3. Transfer Returned data into toa_opt or toa_v6_entry, and then extract ip and port
    switch (type) {
        case TOA_IPV4: {
            struct toa_opt opt = {0};
            bpf_core_read(&opt, sizeof(struct toa_opt), &toa_data_ptr);
            link->opt_c_ip = opt.ip;
            link->family = af;
            link->opt_family = AF_INET;
            break;
        }
        case TOA_IPV6: {
            __builtin_memcpy(link->opt_c_ip6, v6_toa_data.toa_data.ip6, IP6_LEN);
            link->family = af;
            link->opt_family = AF_INET6;
            break;
        }
        default:
            return false;
    }
    return true;
}

static __always_inline int init_link_from_skb(struct sk_buff *skb, struct tcp_link_s *link)
{
    struct tcphdr *tcp_head = NULL;
    u16 port = 0;
    u16 protocol = BPF_CORE_READ(skb, protocol);

    // IPv4
    if (protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = NULL;
        iph = ip_hdr((const struct sk_buff *) skb);
        if (iph == NULL) {
            return 0;
        }
        link->s_ip = BPF_CORE_READ(iph, daddr);
        link->c_ip = BPF_CORE_READ(iph, saddr);

        tcp_head = tcp_hdr((const struct sk_buff *) skb);
        if (tcp_head == NULL) {
            return 0;
        }
        bpf_core_read(&port, sizeof(port), &(tcp_head->source));
        link->c_port = bpf_ntohs(port);
        bpf_core_read(&port, sizeof(port), &(tcp_head->dest));
        link->s_port = bpf_ntohs(port);
        link->family = AF_INET;
    } else { // IPv6
        struct ipv6hdr *ip6_hdr = NULL;
        ip6_hdr = ipv6_hdr((const struct sk_buff *) skb);
        if (ip6_hdr == NULL) {
            return 0;
        }
        BPF_CORE_READ_INTO(&(link->c_ip6), ip6_hdr, saddr);
        BPF_CORE_READ_INTO(&(link->s_ip6), ip6_hdr, daddr);

        tcp_head = tcp_hdr((const struct sk_buff *) skb);
        if (tcp_head == NULL) {
            return 0;
        }
        bpf_core_read(&port, sizeof(port), &(tcp_head->source));
        link->c_port = bpf_ntohs(port);
        bpf_core_read(&port, sizeof(port), &(tcp_head->dest));
        link->s_port = bpf_ntohs(port);
        link->family = AF_INET6;
    }

    // when conn_request, just receive syn, must be server
    link->role = LINK_ROLE_SERVER;
    return 1;
}

static struct tcp_metrics_s *create_tcp_link_4_toa(struct sk_buff *skb, struct sock_stats_s *sock_stats)
{
    bool is_toa = get_toa_from_opt(skb, &(sock_stats->metrics.link));
    if (is_toa == false) {
        // This hook is only for TOA packet(syn) on ELB-Nginx received from ELB-CVS
        return NULL;
    }
    int ret = init_link_from_skb(skb, &(sock_stats->metrics.link));
    if (ret == 0) {
        return NULL;
    }
    return &(sock_stats->metrics);
}

/**
 * TCP_CONN_REQUEST means the moment just received syn packet on TCP Server.
 * At this time, Server received the 1st packet(SYN) of 3-times HandShake, that means a TCP HandShake Request.
 * The TCP link has not been set up, so we can not get the link Context(Process info as well).
 * so, we can not get the process info(pid)
 */
KPROBE(tcp_conn_request, pt_regs)
{
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM4(ctx);
    struct sock_stats_s sock_stats = {0};
    struct tcp_metrics_s *metrics = create_tcp_link_4_toa(skb, &sock_stats);
    if (metrics) {
        report_toa(ctx, metrics);
    }
    return 0;
}
#endif
