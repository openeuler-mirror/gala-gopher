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

char g_license[] SEC("license") = "GPL";
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/

#define __MAX_CONCURRENCY   1000
typedef u64 conn_ctx_t;         // pid & tgid

struct sock_args_s {
    struct sock *sk;
    struct request_sock *req;
};

struct socket_args_s {
    struct socket *socket;
};

struct tcp_check_req_args_s {
    struct sock *sk;
};

struct tcp_connect_args_s {
    char neigh_failed;
    struct sock *sk;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct tcp_listen_key_s));
    __uint(value_size, sizeof(struct tcp_listen_val_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} tcp_listen_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct tcp_connect_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} tcp_connect_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct sock_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} tcp_v4_send_synack_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct sock_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} tcp_v6_send_synack_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct socket_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} tcp_inet_listen_args SEC(".maps");

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

struct sock_info_s {
    enum socket_role_e role;
    int tgid;
    int is_multi;          // 1: multi procs listen to one sock
    u64 syn_start_ts;      // client: ts of SYN_SENT ; server: ts of sending synack
};

#define __TCP_SOCKS_MAX (10 * 1024)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct sock *));
    __uint(value_size, sizeof(struct sock_info_s));
    __uint(max_entries, __TCP_SOCKS_MAX);
} tcp_socks SEC(".maps");

static __always_inline struct tcp_listen_val_s* lkup_tgid_by_sock_inode(struct tcp_listen_key_s *key)
{
    struct tcp_listen_val_s *val;

    val = bpf_map_lookup_elem(&tcp_listen_port, key);
    if (val == NULL) {
        return 0;
    }

    return val;
}

static __always_inline struct sock_info_s* lkup_sock(const struct sock *sk)
{
    return (struct sock_info_s *)bpf_map_lookup_elem(&tcp_socks, &sk);
}

static __always_inline void add_sock(const struct sock *sk, enum socket_role_e role)
{
    int tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);

    struct sock_info_s* info = lkup_sock((const struct sock *)sk);
    if (info != NULL) {
        if (info->tgid != tgid) {
            // multi tgid listen to one sock,
            // set is_multi to 1, but not update tgid
            info->is_multi = 1;
        }
        return;
    }

    struct sock_info_s new_info = {0};
    new_info.tgid = tgid;
    new_info.is_multi = 0;      // default is 0
    new_info.role = role;

    if (role == TCP_CLIENT) {
        new_info.syn_start_ts = bpf_ktime_get_ns();
    }

    bpf_map_update_elem(&tcp_socks, &sk, &new_info, BPF_ANY);
    return;
}

static __always_inline void add_sock_and_tgid(const struct sock *sk, enum socket_role_e role, struct tcp_listen_val_s *v)
{
    struct sock_info_s info = {0};

    info.tgid = v->proc_id;
    info.is_multi = v->is_multi;
    info.role = role;
    bpf_map_update_elem(&tcp_socks, &sk, &info, BPF_ANY);
    return;
}

static __always_inline void add_sock_by_listen_sk(const struct sock *sk, struct sock_info_s *info)
{
    struct sock_info_s new_info = {0};

    new_info.tgid = info->tgid;
    new_info.role = TCP_SERVER;
    new_info.syn_start_ts = info->syn_start_ts;
    bpf_map_update_elem(&tcp_socks, &sk, &new_info, BPF_ANY);
    return;
}

static __always_inline void del_sock(const struct sock *sk)
{
    (void)bpf_map_delete_elem(&tcp_socks, &sk);
    return;
}

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

static __always_inline void get_inode_by_sock(const struct sock *listen_sk, unsigned long *ino)
{
    struct socket *socket = _(listen_sk->sk_socket);
    struct socket_alloc *ei = container_of(socket, struct socket_alloc, socket);
    *ino = BPF_CORE_READ(ei, vfs_inode.i_ino);

    return;
}

static __always_inline struct tcp_listen_val_s* get_proc_info_by_listen_sk(const struct sock* listen_sk)
{
    struct tcp_listen_key_s key = {0};

    get_inode_by_sock(listen_sk, &(key.inode));

    struct tcp_listen_val_s *val = lkup_tgid_by_sock_inode(&key);
    if (val == NULL || val->proc_id == 0) {
        return NULL;
    }

    return val;
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

static __always_inline void get_request_sockaddr(struct tcp_socket_event_s* evt, const struct request_sock* req)
{
    u16 family, server_port, client_port;

    family = BPF_CORE_READ(req, __req_common.skc_family);

    evt->client_ipaddr.family = family;
    evt->server_ipaddr.family = family;

    server_port = BPF_CORE_READ(req, __req_common.skc_num);
    client_port = BPF_CORE_READ(req, __req_common.skc_dport);
    client_port = bpf_ntohs(client_port);

    evt->client_ipaddr.port = client_port;
    evt->server_ipaddr.port = server_port;

    if (family == AF_INET) {
        evt->client_ipaddr.ip = BPF_CORE_READ(req, __req_common.skc_daddr);
        evt->server_ipaddr.ip = BPF_CORE_READ(req, __req_common.skc_rcv_saddr);
    } else {
        BPF_CORE_READ_INTO(&(evt->client_ipaddr.ip6), req, __req_common.skc_v6_daddr);
        BPF_CORE_READ_INTO(&(evt->server_ipaddr.ip6), req, __req_common.skc_v6_rcv_saddr);
    }
    return;
}

static __always_inline void report_synack_sent_evt(void *ctx, const struct sock* sk, const struct request_sock *req, bool retran)
{
    if (sk == NULL || req == NULL) {
        return;
    }

    struct sock_info_s* info = lkup_sock(sk);
    if (info == NULL) {
        return;
    }

    struct tcp_socket_event_s evt = {0};
    get_request_sockaddr(&evt, req);
    evt.evt = retran ? EP_STATS_RETRANS_SYNACK : EP_STATS_SYNACK_SENT;
    evt.tgid = info->tgid;
    evt.is_multi = info->is_multi;

    // report;
    evt.role = TCP_SERVER;
    (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
}

KPROBE(tcp_connect, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct tcp_connect_args_s args = {0};
    args.sk = sk;
    bpf_map_update_elem(&tcp_connect_args, &id, &args, BPF_ANY);

    return 0;
}

KRETPROBE(tcp_connect, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);

    if (ret != 0) {
        goto end;
    }

    struct tcp_connect_args_s* args = bpf_map_lookup_elem(&tcp_connect_args, &id);
    if (args == NULL) {
        goto end;
    }

    struct sock *sk = args->sk;
    if (sk == NULL) {
        goto end;
    }

    add_sock((const struct sock *)sk, TCP_CLIENT);

    struct tcp_socket_event_s evt = {0};
    get_connect_sockaddr(&evt, (const struct sock *)sk);
    evt.evt = args->neigh_failed ? EP_STATS_SYN_DROP : EP_STATS_SYN_SENT;
    evt.tgid = (int)(id >> INT_LEN);
    evt.is_multi = 0;

    // report;
    evt.role = TCP_CLIENT;
    (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));

end:
    bpf_map_delete_elem(&tcp_connect_args, &id);
    return 0;
}

KRETPROBE(__neigh_event_send, pt_regs)
{
    int ret = (int)PT_REGS_RC(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct tcp_connect_args_s* args = bpf_map_lookup_elem(&tcp_connect_args, &id);
    if (args == NULL) {
        return 0;
    }

    struct sock *sk = args->sk;
    if (sk == NULL) {
        return 0;
    }

    args->neigh_failed = ret;
    return 0;
}

KPROBE(inet_listen, pt_regs)
{
    struct socket *socket = (struct socket *)PT_REGS_PARM1(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct socket_args_s args = {0};
    args.socket = socket;
    bpf_map_update_elem(&tcp_inet_listen_args, &id, &args, BPF_ANY);

    return 0;
}

KRETPROBE(inet_listen, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);

    if (ret != 0) {
        goto end;
    }

    struct socket_args_s* args = bpf_map_lookup_elem(&tcp_inet_listen_args, &id);
    if (args == NULL) {
        goto end;
    }

    struct socket *socket = args->socket;
    if (socket == NULL) {
        goto end;
    }

    struct sock *sk = _(socket->sk);
    if (sk == NULL) {
        goto end;
    }

    add_sock((const struct sock *)sk, TCP_LISTEN_SK);
end:
    bpf_map_delete_elem(&tcp_inet_listen_args, &id);
    return 0;
}


KPROBE(tcp_set_state, pt_regs)
{
    u16 new_state = (u16)PT_REGS_PARM2(ctx);
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct tcp_socket_event_s evt = {0};
    u16 old_state = _(sk->sk_state);
    u64 curr_ts;

    struct sock_info_s* info = lkup_sock((const struct sock *)sk);
    if (info == NULL) {
        return 0;
    }

    if (new_state == TCP_ESTABLISHED) {
        if (info->role == TCP_CLIENT) {
            get_connect_sockaddr(&evt, (const struct sock *)sk);
            evt.evt = EP_STATS_ACTIVE_OPENS;
            evt.role = TCP_CLIENT;
        } else if (info->role == TCP_SERVER) {
            get_accept_sockaddr(&evt, (const struct sock *)sk);
            evt.evt = EP_STATS_PASSIVE_OPENS;
            evt.role = TCP_SERVER;
        } else {
            return 0;
        }

        evt.tgid = info->tgid;
        evt.is_multi = info->is_multi;
        curr_ts = bpf_ktime_get_ns();
        if (info->syn_start_ts != 0 && (curr_ts > info->syn_start_ts)) {
            evt.estab_latency = curr_ts - info->syn_start_ts;
            info->syn_start_ts = 0;
        }
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    }

    if (new_state == TCP_CLOSE && old_state == TCP_SYN_SENT) {
        get_connect_sockaddr(&evt, (const struct sock *)sk);
        evt.evt = EP_STATS_ACTIVE_FAILS;
        evt.tgid = info->tgid;
        evt.is_multi = info->is_multi;

        // report;
        evt.role = TCP_CLIENT;
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    }

    if (new_state != TCP_ESTABLISHED && old_state == TCP_SYN_RECV) {
        get_accept_sockaddr(&evt, (const struct sock *)sk);
        evt.evt = EP_STATS_PASSIVE_FAILS;
        evt.tgid = info->tgid;
        evt.is_multi = info->is_multi;

        // report;
        evt.role = TCP_SERVER;
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    }

    if (new_state == TCP_CLOSE || new_state == TCP_CLOSE_WAIT || new_state == TCP_FIN_WAIT1) {
        if (info->role == TCP_CLIENT) {
            get_connect_sockaddr(&evt, (const struct sock *)sk);
        } else if (info->role == TCP_SERVER) {
            get_accept_sockaddr(&evt, (const struct sock *)sk);
        } else {
            return 0;
        }

        evt.evt = EP_STATS_CONN_CLOSE;
        evt.tgid = info->tgid;
        evt.is_multi = info->is_multi;
        evt.role = info->role;
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    }

    return 0;
}

KPROBE(tcp_v4_send_synack, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct request_sock *req = (struct request_sock *)PT_REGS_PARM4(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();
    struct sock_args_s args = {0};

    struct sock_info_s* info = lkup_sock(sk);
    if (info == NULL) {
        return 0;
    }

    args.sk = sk;
    args.req = req;
    info->syn_start_ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&tcp_v4_send_synack_args, &id, &args, BPF_ANY);

    return 0;
}

KRETPROBE(tcp_v4_send_synack, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);

    if (ret != 0) {
        goto end;
    }

    struct sock_args_s* args = bpf_map_lookup_elem(&tcp_v4_send_synack_args, &id);
    if (args == NULL) {
        goto end;
    }

    report_synack_sent_evt(ctx, (const struct sock *)(args->sk), (const struct request_sock *)(args->req), false);

end:
    bpf_map_delete_elem(&tcp_v4_send_synack_args, &id);
    return 0;
}


KPROBE(tcp_v6_send_synack, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct request_sock *req = (struct request_sock *)PT_REGS_PARM4(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();
    struct sock_args_s args = {0};

    struct sock_info_s* info = lkup_sock(sk);
    if (info == NULL) {
        return 0;
    }

    args.sk = sk;
    args.req = req;
    info->syn_start_ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&tcp_v6_send_synack_args, &id, &args, BPF_ANY);

    return 0;
}

KRETPROBE(tcp_v6_send_synack, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);

    if (ret != 0) {
        goto end;
    }

    struct sock_args_s* args = bpf_map_lookup_elem(&tcp_v6_send_synack_args, &id);
    if (args == NULL) {
        goto end;
    }

    report_synack_sent_evt(ctx, (const struct sock *)(args->sk), (const struct request_sock *)(args->req), false);

end:
    bpf_map_delete_elem(&tcp_v6_send_synack_args, &id);
    return 0;
}

KPROBE(tcp_check_req, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct tcp_check_req_args_s args = {0};
    args.sk = sk;
    bpf_map_update_elem(&tcp_check_req_args, &id, &args, BPF_ANY);

    return 0;
}

KRETPROBE(tcp_check_req, pt_regs)
{
    struct sock *new_sk = (struct sock *)PT_REGS_RC(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();

    if (new_sk == NULL) {
        goto end;
    }

    struct tcp_check_req_args_s* args = bpf_map_lookup_elem(&tcp_check_req_args, &id);
    if (args == NULL) {
        goto end;
    }

    struct sock *sk = args->sk;
    if (sk == NULL) {
        goto end;
    }

    struct sock_info_s* info = lkup_sock((const struct sock *)sk);
    if (info && info->role == TCP_LISTEN_SK) {
        add_sock_by_listen_sk((const struct sock *)new_sk, info);
        info->syn_start_ts = 0;
    }

end:
    bpf_map_delete_elem(&tcp_check_req_args, &id);
    return 0;
}

KPROBE(tcp_conn_request, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM3(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM4(ctx);
    struct tcp_socket_event_s evt = {0};
    int tgid = 0;
    int is_multi = 0;

    if (sk == NULL || skb == NULL) {
        goto end;
    }

    struct sock_info_s* info = lkup_sock((const struct sock *)sk);
    if (info && info->role == TCP_LISTEN_SK) {
        tgid = info->tgid;
        is_multi = info->is_multi;
    } else {
        struct tcp_listen_val_s *val = get_proc_info_by_listen_sk((const struct sock *)sk);
        if (val == NULL) {
            goto end;
        }
        tgid = val->proc_id;
        if (tgid == 0) {
            goto end;
        }
        is_multi = val->is_multi;
        add_sock_and_tgid((const struct sock *)sk, TCP_LISTEN_SK, val);
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
        struct iphdr *iph = NULL;
        iph = ip_hdr((const struct sk_buff *)skb);
        if (iph == NULL) {
            goto end;
        }
        evt.server_ipaddr.ip = BPF_CORE_READ(iph, daddr);
        evt.server_ipaddr.family = AF_INET;
        evt.client_ipaddr.ip = BPF_CORE_READ(iph, saddr);
        evt.client_ipaddr.family = AF_INET;

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
        evt.client_ipaddr.family = AF_INET6;
        bpf_core_read(&port, sizeof(port), &(tcp_head->dest));
        evt.server_ipaddr.port = bpf_ntohs(port);
        evt.server_ipaddr.family = AF_INET6;
    }

    evt.tgid = tgid;
    evt.is_multi = is_multi;
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

    struct sock_info_s* info = lkup_sock((const struct sock *)sk);
    if (info == NULL) {
        goto end;
    }

    get_accept_sockaddr(&evt, (const struct sock *)sk);
    evt.evt = EP_STATS_LISTEN_DROPS;
    evt.tgid = info->tgid;
    evt.is_multi = info->is_multi;

    // report;
    evt.role = TCP_SERVER;
    (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
end:
    return 0;
}

KRAWTRACE(tcp_retransmit_synack, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock *)ctx->args[0];
    struct request_sock *req = (struct request_sock *)ctx->args[1];

    report_synack_sent_evt(ctx, sk, req, true);
    return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_synack")
int bpf_trace_tcp_retransmit_synack_func(struct trace_event_raw_tcp_retransmit_synack *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    struct request_sock *req = (struct request_sock *)ctx->req;

    report_synack_sent_evt(ctx, sk, req, true);

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

    struct sock_info_s* info = lkup_sock((const struct sock *)sk);
    if (info == NULL) {
        return 0;
    }
    u8 num_timeout = BPF_CORE_READ_BITFIELD_PROBED(req, num_timeout);

    if (num_timeout >= max_retries) {
        struct tcp_socket_event_s evt = {0};
        get_accept_sockaddr(&evt, (const struct sock *)sk);
        evt.evt = EP_STATS_REQ_DROP;
        evt.tgid = info->tgid;
        evt.is_multi = info->is_multi;

        // report;
        evt.role = TCP_SERVER;
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    }
    return 0;
}

static __always_inline void tcp_send_reset(void *ctx, struct sock* sk)
{
    struct sock_info_s* info = lkup_sock((const struct sock *)sk);
    if (info == NULL) {
        return;
    }

    struct tcp_socket_event_s evt = {0};
    if (info->role == TCP_CLIENT) {
        get_connect_sockaddr(&evt, (const struct sock *)sk);
        evt.evt = EP_STATS_RST_SENT;
        evt.tgid = info->tgid;
        evt.is_multi = info->is_multi;

        // report;
        evt.role = TCP_CLIENT;
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    } else if (info->role == TCP_SERVER) {
        get_accept_sockaddr(&evt, (const struct sock *)sk);
        evt.evt = EP_STATS_RST_SENT;
        evt.tgid = info->tgid;
        evt.is_multi = info->is_multi;

        // report;
        evt.role = TCP_SERVER;
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    }
}

static __always_inline void tcp_recv_reset(void *ctx, struct sock* sk)
{
    struct sock_info_s* info = lkup_sock((const struct sock *)sk);
    if (info == NULL) {
        return;
    }

    struct tcp_socket_event_s evt = {0};
    if (info->role == TCP_CLIENT) {
        get_connect_sockaddr(&evt, (const struct sock *)sk);
        evt.evt = EP_STATS_RST_RCVS;
        evt.tgid = info->tgid;
        evt.is_multi = info->is_multi;

        // report;
        evt.role = TCP_CLIENT;
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    } else if (info->role == TCP_SERVER) {
        get_accept_sockaddr(&evt, (const struct sock *)sk);
        evt.evt = EP_STATS_RST_RCVS;
        evt.tgid = info->tgid;
        evt.is_multi = info->is_multi;

        // report;
        evt.role = TCP_SERVER;
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    }
}

KRAWTRACE(tcp_send_reset, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock *)ctx->args[0];
    tcp_send_reset(ctx, sk);

    return 0;
}

KRAWTRACE(tcp_receive_reset, bpf_raw_tracepoint_args)
{
    struct sock *sk = (struct sock *)ctx->args[0];
    tcp_recv_reset(ctx, sk);

    return 0;
}

SEC("tracepoint/tcp/tcp_send_reset")
int bpf_trace_tcp_send_reset_func(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    tcp_send_reset(ctx, sk);

    return 0;
}

SEC("tracepoint/tcp/tcp_receive_reset")
int bpf_trace_tcp_receive_reset_func(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    tcp_recv_reset(ctx, sk);

    return 0;
}

#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20
#define TCPHDR_ECE 0x40
#define TCPHDR_CWR 0x80

KPROBE(tcp_retransmit_skb, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    struct sock_info_s* info = lkup_sock((const struct sock *)sk);
    if (info == NULL) {
        return 0;
    }

    if (info->role != TCP_CLIENT) {
        return 0;
    }

    struct tcp_skb_cb *tsc;
    tsc = (struct tcp_skb_cb *)((unsigned long)skb + offsetof(struct sk_buff, cb[0]));
    u8 tcp_flags = _(tsc->tcp_flags);

    if (tcp_flags & TCPHDR_SYN) {
        struct tcp_socket_event_s evt = {0};
        get_connect_sockaddr(&evt, (const struct sock *)sk);
        evt.evt = EP_STATS_RETRANS_SYN;
        evt.tgid = info->tgid;
        evt.is_multi = info->is_multi;

        // report;
        evt.role = info->role;
        (void)bpfbuf_output(ctx, &tcp_evt_map, &evt, sizeof(struct tcp_socket_event_s));
    }
    return 0;
}

KPROBE(inet_csk_destroy_sock, pt_regs)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    del_sock((const struct sock *)sk);
    return 0;
}
