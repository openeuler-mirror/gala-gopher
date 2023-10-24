/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: algorithmofdish
 * Create: 2021-10-25
 * Description: endpoint_probe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN

#include "bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "endpoint.h"


#define __KPROBE_SYSCALL(arch, func) KPROBE(arch##func, pt_regs)

#if defined(__TARGET_ARCH_x86)
#define KPROBE_SYSCALL(func) __KPROBE_SYSCALL(__x64_sys_, func)
#elif defined(__TARGET_ARCH_arm64)
#define KPROBE_SYSCALL(func)  __KPROBE_SYSCALL(__arm64_sys_, func)
#endif

#define __KRETPROBE_SYSCALL(arch, func) KRETPROBE(arch##func, pt_regs)

#if defined(__TARGET_ARCH_x86)
#define KRETPROBE_SYSCALL(func) __KRETPROBE_SYSCALL(__x64_sys_, func)
#elif defined(__TARGET_ARCH_arm64)
#define KRETPROBE_SYSCALL(func) __KRETPROBE_SYSCALL(__arm64_sys_, func)
#endif

char g_license[] SEC("license") = "GPL";
#define ETH_P_IP    0x0800      /* Internet Protocol packet */

#define __MAX_CONCURRENCY   1000
typedef u64 conn_ctx_t;         // pid & tgid

struct tcp_connect_args_s {
    struct sock *sk;
};

struct tcp_check_req_args_s {
    struct sock *sk;
    struct request_sock *req;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct tcp_connect_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} tcp_connect_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct tcp_check_req_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} tcp_check_req_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} tcp_evt_map SEC(".maps");


static __always_inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
    unsigned char *skb_hdr = _(skb->head);
    u16 network_header_offset = _(skb->network_header);

    return (skb_hdr + network_header_offset);
}

static __always_inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
    return (struct iphdr *)skb_network_header(skb);
}

static __always_inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
    return (struct ipv6hdr *)skb_network_header(skb);
}

static __always_inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
    unsigned char *skb_hdr = _(skb->head);
    u16 transport_header_offset = _(skb->transport_header);
    return (skb_hdr + transport_header_offset);
}

static __always_inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
    return (struct tcphdr *)skb_transport_header(skb);
}

static __always_inline bool sk_acceptq_is_full(const struct sock *sk)
{
    u32 ack_backlog = _(sk->sk_ack_backlog);
    u32 max_ack_backlog = _(sk->sk_max_ack_backlog);

    return ack_backlog > max_ack_backlog;
}

static __always_inline bool sk_synq_is_full(const struct sock *sk)
{
    u32 max_ack_backlog = _(sk->sk_max_ack_backlog);
    struct inet_connection_sock *inet_csk = (struct inet_connection_sock *)sk;
    int syn_qlen = BPF_CORE_READ(inet_csk, icsk_accept_queue.qlen.counter);

    return (u32)syn_qlen >= max_ack_backlog;
}

static __always_inline void get_check_req_sockaddr(struct tcp_socket_event_s* evt, const struct sock* sk, const struct request_sock *req)
{
    u16 family, server_port, client_port;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);

    server_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    client_port = BPF_CORE_READ(req, __req_common.skc_dport);
    client_port = bpf_ntohs(client_port);

    evt->client_ipaddr.port = client_port;
    evt->server_ipaddr.port = server_port;

    if (family == AF_INET) {
        evt->server_ipaddr.ip = BPF_CORE_READ(req, __req_common.skc_rcv_saddr);
        evt->client_ipaddr.ip = BPF_CORE_READ(req, __req_common.skc_daddr);
    } else {
        BPF_CORE_READ_INTO(&(evt->server_ipaddr.ip6), req, __req_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&(evt->client_ipaddr.ip6), req, __req_common.skc_v6_daddr);
    }
    return;
}

static __always_inline void get_connect_sockaddr(struct tcp_socket_event_s* evt, const struct sock* sk)
{
    u16 family, server_port, client_port;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    evt->client_ipaddr.family = family;
    evt->server_ipaddr.family = family;

    server_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    server_port = bpf_ntohs(server_port);
    client_port = BPF_CORE_READ(sk, __sk_common.skc_num);

    evt->client_ipaddr.port = client_port;
    evt->server_ipaddr.port = server_port;

    if (family == AF_INET) {
        evt->client_ipaddr.ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        evt->server_ipaddr.ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else {
        BPF_CORE_READ_INTO(&(evt->client_ipaddr.ip6), sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&(evt->server_ipaddr.ip6), sk, __sk_common.skc_v6_daddr);
    }
    return;
}

static __always_inline void get_accept_sockaddr(struct tcp_socket_event_s* evt, const struct sock* sk)
{
    u16 family, server_port, client_port;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);

    evt->client_ipaddr.family = family;
    evt->server_ipaddr.family = family;

    server_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    client_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    client_port = bpf_ntohs(client_port);

    evt->client_ipaddr.port = client_port;
    evt->server_ipaddr.port = server_port;

    if (family == AF_INET) {
        evt->client_ipaddr.ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        evt->server_ipaddr.ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    } else {
        BPF_CORE_READ_INTO(&(evt->client_ipaddr.ip6), sk, __sk_common.skc_v6_daddr);
        BPF_CORE_READ_INTO(&(evt->server_ipaddr.ip6), sk, __sk_common.skc_v6_rcv_saddr);
    }
    return;
}

// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
KRETPROBE_SYSCALL(accept)
{
    int tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);
    int new_fd = (int)PT_REGS_RC(ctx);
    if (new_fd < 0) {
        goto end;
    }

    struct sock *sk = sock_get_by_fd(new_fd, (struct task_struct *)bpf_get_current_task());
    if (!sk) {
        goto end;
    }

    struct tcp_socket_event_s evt = {0};

    get_accept_sockaddr(&evt, (const struct sock *)sk);
    evt.evt = EP_STATS_PASSIVE_OPENS;
    evt.tgid = tgid;

    // report;
    evt.role = TCP_SERVER;
    (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
end:

    return 0;
}

// int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
KRETPROBE_SYSCALL(accept4)
{
    int tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);
    int new_fd = (int)PT_REGS_RC(ctx);
    if (new_fd < 0) {
        goto end;
    }

    struct sock *sk = sock_get_by_fd(new_fd, (struct task_struct *)bpf_get_current_task());
    if (!sk) {
        goto end;
    }

    struct tcp_socket_event_s evt = {0};

    get_accept_sockaddr(&evt, (const struct sock *)sk);
    evt.evt = EP_STATS_PASSIVE_OPENS;
    evt.tgid = tgid;

    // report;
    evt.role = TCP_SERVER;
    (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
end:

    return 0;
}

KPROBE(tcp_v4_connect, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct tcp_connect_args_s args = {0};
    args.sk = sk;
    bpf_map_update_elem(&tcp_connect_args, &id, &args, BPF_ANY);

    return 0;
}

KRETPROBE(tcp_v4_connect, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);

    struct tcp_connect_args_s* args = bpf_map_lookup_elem(&tcp_connect_args, &id);
    if (args == NULL) {
        goto end;
    }

    struct sock *sk = args->sk;
    if (sk == NULL) {
        goto end;
    }

    struct tcp_socket_event_s evt = {0};
    get_connect_sockaddr(&evt, (const struct sock *)sk);
    evt.evt = (ret == 0) ? EP_STATS_ACTIVE_OPENS : EP_STATS_ACTIVE_FAILS;
    evt.tgid = (int)(id >> INT_LEN);

    // report;
    evt.role = TCP_CLIENT;
    (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));

end:
    bpf_map_delete_elem(&tcp_connect_args, &id);
    return 0;
}

KPROBE(tcp_check_req, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct request_sock *req = (struct request_sock *)PT_REGS_PARM3(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct tcp_check_req_args_s args = {0};
    args.sk = sk;
    args.req = req;
    bpf_map_update_elem(&tcp_check_req_args, &id, &args, BPF_ANY);

    return 0;
}

KRETPROBE(tcp_check_req, pt_regs)
{
    struct sock *new_sk = (struct sock *)PT_REGS_RC(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();

    if (new_sk != NULL) {
        goto end;
    }

    struct tcp_check_req_args_s* args = bpf_map_lookup_elem(&tcp_check_req_args, &id);
    if (args == NULL) {
        goto end;
    }

    struct sock *sk = args->sk;
    struct request_sock *req = args->req;
    if (sk == NULL || req == NULL) {
        goto end;
    }

    struct tcp_socket_event_s evt = {0};
    get_check_req_sockaddr(&evt, (const struct sock *)sk, (const struct request_sock *)req);
    evt.evt = EP_STATS_PASSIVE_FAILS;
    evt.tgid = (int)(id >> INT_LEN);

    // report;
    evt.role = TCP_SERVER;
    (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));

end:
    bpf_map_delete_elem(&tcp_check_req_args, &id);
    return 0;
}

KPROBE(tcp_conn_request, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM3(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM4(ctx);
    struct tcp_socket_event_s evt = {0};

    if (sk == NULL || skb == NULL) {
        goto end;
    }

    evt.evt = EP_STATS_MAX;
    if (sk_acceptq_is_full((const struct sock *)sk)) {
        evt.evt = EP_STATS_ACCEPT_OVERFLOW;
    }
    if (sk_synq_is_full((const struct sock *)sk)) {
        evt.evt = EP_STATS_SYN_OVERFLOW;
    }

    if (evt.evt == EP_STATS_MAX) {
        goto end;
    }

    struct tcphdr *tcp_head = NULL;
    u16 port = 0;
    u16 protocol = BPF_CORE_READ(skb, protocol);

    if (protocol == bpf_htons(ETH_P_IP)) {
        u32 ipaddr = 0;
        struct iphdr *iph = NULL;
        iph = ip_hdr((const struct sk_buff *)skb);
        if (iph == NULL) {
            goto end;
        }
        bpf_core_read(&ipaddr, sizeof(ipaddr), &(iph->daddr));
        evt.server_ipaddr.ip = bpf_ntohl(ipaddr);
        bpf_core_read(&ipaddr, sizeof(ipaddr), &(iph->saddr));
        evt.client_ipaddr.ip = bpf_ntohl(ipaddr);
        tcp_head = tcp_hdr((const struct sk_buff *)skb);
        if (tcp_head == NULL) {
            goto end;
        }
        bpf_core_read(&port, sizeof(port), &(tcp_head->source));
        evt.client_ipaddr.port = bpf_ntohs(port);
        bpf_core_read(&port, sizeof(port), &(tcp_head->dest));
        evt.server_ipaddr.port = bpf_ntohs(port);
    } else {
        struct ipv6hdr *ip6_hdr = NULL;
        ip6_hdr = ipv6_hdr((const struct sk_buff *)skb);
        if (ip6_hdr == NULL) {
            goto end;
        }
        BPF_CORE_READ_INTO(&(evt.client_ipaddr.ip6), ip6_hdr, saddr);
        BPF_CORE_READ_INTO(&(evt.server_ipaddr.ip6), ip6_hdr, daddr);

        tcp_head = tcp_hdr((const struct sk_buff *)skb);
        if (tcp_head == NULL) {
            goto end;
        }
        bpf_core_read(&port, sizeof(port), &(tcp_head->source));
        evt.client_ipaddr.port = bpf_ntohs(port);
        bpf_core_read(&port, sizeof(port), &(tcp_head->dest));
        evt.server_ipaddr.port = bpf_ntohs(port);
    }

    evt.role = TCP_SERVER;
    evt.tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);
    // report;
    evt.role = TCP_SERVER;
    (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));

end:
    return 0;
}

KPROBE(tcp_req_err, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    bool abort = (bool)PT_REGS_PARM3(ctx);
    struct tcp_socket_event_s evt = {0};

    if (!abort) {
        goto end;
    }

    get_accept_sockaddr(&evt, (const struct sock *)sk);
    evt.evt = EP_STATS_LISTEN_DROPS;
    evt.tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);

    // report;
    evt.role = TCP_SERVER;
    (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
end:
    return 0;
}

KRAWTRACE(tcp_retransmit_synack, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock *)ctx->args[0];
    struct tcp_socket_event_s evt = {0};

    get_accept_sockaddr(&evt, (const struct sock *)sk);
    evt.evt = EP_STATS_RETRANS_SYNACK;
    evt.tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);

    // report;
    evt.role = TCP_SERVER;
    (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_synack")
int bpf_trace_tcp_retransmit_synack_func(struct trace_event_raw_tcp_retransmit_synack *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    struct tcp_socket_event_s evt = {0};

    get_accept_sockaddr(&evt, (const struct sock *)sk);
    evt.evt = EP_STATS_RETRANS_SYNACK;
    evt.tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);

    // report;
    evt.role = TCP_SERVER;
    (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));

    return 0;
}

KPROBE(inet_csk_reqsk_queue_drop_and_put, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct request_sock *req = (struct request_sock *)PT_REGS_PARM2(ctx);
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;

    int sysctl_tcp_synack_retries = BPF_CORE_READ(sk, __sk_common.skc_net.net, ipv4.sysctl_tcp_synack_retries);
    int icsk_syn_retries = _(icsk->icsk_syn_retries);
    int max_retries = icsk_syn_retries ? : sysctl_tcp_synack_retries;

    u8 num_timeout = BPF_CORE_READ_BITFIELD_PROBED(req, num_timeout);

    if (num_timeout >= max_retries) {
        struct tcp_socket_event_s evt = {0};
        get_accept_sockaddr(&evt, (const struct sock *)sk);
        evt.evt = EP_STATS_REQ_DROP;
        evt.tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);

        // report;
        evt.role = TCP_SERVER;
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    }
    return 0;
}

KPROBE(tcp_retransmit_timer, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    struct request_sock *req = _(tp->fastopen_rsk);
    if (req == NULL) {
        return 0;
    }

    int sysctl_tcp_synack_retries = BPF_CORE_READ(sk, __sk_common.skc_net.net, ipv4.sysctl_tcp_synack_retries);
    int icsk_syn_retries = _(icsk->icsk_syn_retries);
    int max_retries = icsk_syn_retries ? : sysctl_tcp_synack_retries + 1;

    u8 num_timeout = BPF_CORE_READ_BITFIELD_PROBED(req, num_timeout);

    if (num_timeout >= max_retries) {
        struct tcp_socket_event_s evt = {0};
        get_accept_sockaddr(&evt, (const struct sock *)sk);
        evt.evt = EP_STATS_LOST_SYNACK;
        evt.tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);

        // report;
        evt.role = TCP_SERVER;
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));

    }
    return 0;
}

