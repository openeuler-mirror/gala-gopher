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

#define ETH_P_IP    0x0800      /* Internet Protocol packet */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} udp_evt_map SEC(".maps");

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

static __always_inline __maybe_unused void get_remote_addr(struct udp_socket_event_s* evt, const struct sockaddr* remote_addr)
{
    const struct sockaddr_in *addr_in = (const struct sockaddr_in *)remote_addr;
    const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)remote_addr;

    evt->remote_ipaddr.family = _(remote_addr->sa_family);
    if (evt->remote_ipaddr.family == AF_INET) {
        evt->remote_ipaddr.ip = _(addr_in->sin_addr.s_addr);
        evt->remote_ipaddr.port = bpf_ntohs(_(addr_in->sin_port));
    } else {
        BPF_CORE_READ_INTO(&(evt->remote_ipaddr.ip6), addr_in6, sin6_addr);
        evt->remote_ipaddr.port = bpf_ntohs(_(addr_in6->sin6_port));
    }

    return;
}

static __always_inline void get_local_sockaddr(struct udp_socket_event_s* evt, const struct sock* sk)
{
    u16 family;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    evt->local_ipaddr.family = family;

    if (family == AF_INET) {
        evt->local_ipaddr.ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    } else {
        BPF_CORE_READ_INTO(&(evt->local_ipaddr.ip6), sk, __sk_common.skc_v6_rcv_saddr);
    }
    return;
}

static __always_inline void get_remote_sockaddr(struct udp_socket_event_s* evt, const struct sock* sk)
{
    u16 family;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    evt->remote_ipaddr.family = family;

    if (family == AF_INET) {
        evt->remote_ipaddr.ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else {
        BPF_CORE_READ_INTO(&(evt->remote_ipaddr.ip6), sk, __sk_common.skc_v6_daddr);
    }
    return;
}


KPROBE(udp_sendmsg, pt_regs)
{
    struct sock* sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);

    struct udp_socket_event_s evt = {0};

    struct sockaddr* msg_name = BPF_CORE_READ(msg, msg_name);

    if (msg_name == NULL) {
        get_remote_sockaddr(&evt, (const struct sock *)sk);
    } else {
        get_remote_addr(&evt, (const struct sockaddr *)msg_name);
    }

    get_local_sockaddr(&evt, (const struct sock *)sk);
    evt.val = (u64)len;
    evt.tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);
    evt.evt = EP_STATS_UDP_SENDS;

    // report;
    (void)bpfbuf_output(ctx, &udp_evt_map, &evt, sizeof(struct udp_socket_event_s));

    return 0;
}

KRETPROBE(__skb_recv_udp, pt_regs)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);
    struct udp_socket_event_s evt = {0};

    if (skb == NULL) {
        goto end;
    }

    u16 protocol = BPF_CORE_READ(skb, protocol);

    if (protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = NULL;
        iph = ip_hdr((const struct sk_buff *)skb);
        if (iph == NULL) {
            goto end;
        }
        evt.local_ipaddr.ip = BPF_CORE_READ(iph, daddr);
        evt.local_ipaddr.family = AF_INET;
        evt.remote_ipaddr.ip = BPF_CORE_READ(iph, saddr);
        evt.remote_ipaddr.family = AF_INET;
    } else {
        struct ipv6hdr *ip6_hdr = NULL;
        ip6_hdr = ipv6_hdr((const struct sk_buff *)skb);
        if (ip6_hdr == NULL) {
            goto end;
        }
        BPF_CORE_READ_INTO(&(evt.local_ipaddr.ip6), ip6_hdr, daddr);
        BPF_CORE_READ_INTO(&(evt.remote_ipaddr.ip6), ip6_hdr, saddr);
        evt.local_ipaddr.family = AF_INET6;
        evt.remote_ipaddr.family = AF_INET6;
    }

    unsigned int len = _(skb->len);
    evt.val = (u64)len;
    evt.tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);
    evt.evt = EP_STATS_UDP_RCVS;

    // report;
    (void)bpfbuf_output(ctx, &udp_evt_map, &evt, sizeof(struct udp_socket_event_s));

end:
    return 0;
}

#define __MAX_CONCURRENCY   1000
typedef u64 conn_ctx_t;         // pid & tgid

struct udp_enqueue_args_s {
    struct sk_buff *skb;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct udp_enqueue_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} udp_enqueue_args SEC(".maps");

KPROBE(__udp_enqueue_schedule_skb, pt_regs)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct udp_enqueue_args_s args = {0};
    args.skb = skb;

    bpf_map_update_elem(&udp_enqueue_args, &id, &args, BPF_ANY);

    return 0;
}

KRETPROBE(__udp_enqueue_schedule_skb, pt_regs)
{
    int ret = (int)PT_REGS_RC(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();

    if (ret == 0) {
        goto end;
    }

    struct udp_enqueue_args_s* args = bpf_map_lookup_elem(&udp_enqueue_args, &id);
    if (args == NULL) {
        goto end;
    }

    struct sk_buff *skb = args->skb;
    if (skb == NULL) {
        goto end;
    }

    struct udp_socket_event_s evt = {0};

    u16 protocol = BPF_CORE_READ(skb, protocol);

    if (protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = NULL;
        iph = ip_hdr((const struct sk_buff *)skb);
        if (iph == NULL) {
            goto end;
        }
        evt.local_ipaddr.ip = BPF_CORE_READ(iph, daddr);
        evt.local_ipaddr.family = AF_INET;
        evt.remote_ipaddr.ip = BPF_CORE_READ(iph, saddr);
        evt.remote_ipaddr.family = AF_INET;
    } else {
        struct ipv6hdr *ip6_hdr = NULL;
        ip6_hdr = ipv6_hdr((const struct sk_buff *)skb);
        if (ip6_hdr == NULL) {
            goto end;
        }
        BPF_CORE_READ_INTO(&(evt.local_ipaddr.ip6), ip6_hdr, daddr);
        BPF_CORE_READ_INTO(&(evt.remote_ipaddr.ip6), ip6_hdr, saddr);
        evt.local_ipaddr.family = AF_INET6;
        evt.remote_ipaddr.family = AF_INET6;
    }

    unsigned int len = _(skb->len);
    evt.val = (u64)len;
    evt.evt = EP_STATS_QUE_RCV_FAILED;
    evt.tgid = (int)(id >> INT_LEN);

    // report;
    (void)bpfbuf_output(ctx, &udp_evt_map, &evt, sizeof(struct udp_socket_event_s));

end:
    bpf_map_delete_elem(&udp_enqueue_args, &id);
    return 0;
}
