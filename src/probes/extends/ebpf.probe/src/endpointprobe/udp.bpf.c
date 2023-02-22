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
#include <bpf/bpf_endian.h>
#include "bpf.h"
#include "output.h"

char g_license[] SEC("license") = "GPL";

#define __ENDPOINT_STAT_MAX (1024)

// Used to identifies the UDP object.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct udp_client_key_t));
    __uint(value_size, sizeof(struct endpoint_val_t));
    __uint(max_entries, __ENDPOINT_STAT_MAX);
} udp_sock_map SEC(".maps");

// Used to identifies the UDP bind object.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct udp_server_key_t));
    __uint(value_size, sizeof(struct endpoint_val_t));
    __uint(max_entries, __ENDPOINT_STAT_MAX);
} udp_bind_map SEC(".maps");

static __always_inline int create_udp_obj(struct endpoint_key_t *key)
{
    struct endpoint_val_t value = {0};

    value.ts = bpf_ktime_get_ns();
    __builtin_memcpy(&(value.key), key, sizeof(struct endpoint_key_t));

    if (key->type == SK_TYPE_LISTEN_UDP) {
        return bpf_map_update_elem(&udp_bind_map, &(key->key.udp_server_key), &value, BPF_ANY);
    } else if (key->type == SK_TYPE_CLIENT_UDP) {
        return bpf_map_update_elem(&udp_sock_map, &(key->key.udp_client_key), &value, BPF_ANY);
    }

    return -1;
}

static __always_inline struct endpoint_val_t* get_udp_obj(struct endpoint_key_t *key)
{
    if (key->type == SK_TYPE_LISTEN_UDP) {
        return bpf_map_lookup_elem(&udp_bind_map, &(key->key.udp_server_key));
    } else if (key->type == SK_TYPE_CLIENT_UDP) {
        return bpf_map_lookup_elem(&udp_sock_map, &(key->key.udp_client_key));
    }

    return 0;
}

static void get_udp_key(struct sock *sk, struct endpoint_key_t *key, u32 tgid)
{
    if (key->type == SK_TYPE_LISTEN_UDP) {
        key->key.udp_server_key.tgid = tgid;
        init_ip(&key->key.udp_server_key.ip_addr, sk);
    } else if (key->type == SK_TYPE_CLIENT_UDP) {
        key->key.udp_client_key.tgid = tgid;
        init_ip(&key->key.udp_client_key.ip_addr, sk);
    }
    return;
}

static struct endpoint_val_t* get_udp_val(struct sock *sk, int *new_entry)
{
    int ret;
    struct endpoint_v *epv;
    enum endpoint_t type;
    struct endpoint_key_t key = {0};
    struct endpoint_val_t *value;

    *new_entry = 0;

    if (sk == 0)
        return 0;

    // get endpoint val
    epv = get_endpoint_val(sk);
    if (epv == 0)
        return 0;
    type = epv->type;

    // get udp key by sock type
    key.type = type;
    get_udp_key(sk, &key, epv->tgid);

    // get udp obj
    value = get_udp_obj(&key);
    if (value != 0)
        return value;

    // create udp obj
    ret = create_udp_obj(&key);
    if (ret < 0)
        return 0;

    *new_entry = 1;
    return get_udp_obj(&key);
}

static void report_udp(struct pt_regs *ctx, struct sock *sk)
{
    int new_entry;
    struct endpoint_val_t* value;

    value = get_udp_val(sk, &new_entry);
    if (new_entry && value)
        report(ctx, value, new_entry);
}

KPROBE_RET(inet_bind, pt_regs, CTX_KERNEL)
{
    int ret = PT_REGS_RC(ctx);
    struct socket *sock;
    struct sock *sk;
    struct probe_val val;

    if (PROBE_GET_PARMS(inet_bind, ctx, val, CTX_KERNEL) < 0)
        return 0;

    if (ret != 0) {
        return 0;
    }

    sock = (struct socket *)PROBE_PARM1(val);
    sk = _(sock->sk);
    if (sk == (void *)0) {
        return 0;
    }

    if (_(sock->type) == SOCK_DGRAM) {
        (void)create_sock_map(sk, SK_TYPE_LISTEN_UDP, (bpf_get_current_pid_tgid() >> INT_LEN));
        report_udp(ctx, sk);
    }

    return 0;
}

KPROBE(udp_sendmsg, pt_regs)
{
    int new_entry;
    struct endpoint_val_t* val;
    struct sock* sk = (struct sock *)PT_REGS_PARM1(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);

    val = get_udp_val(sk, &new_entry);
    if (val) {
        ATOMIC_INC_EP_STATS(val, EP_STATS_UDP_SENDS, len);
        report(ctx, val, new_entry);
    }
    return 0;
}

KPROBE(udp_recvmsg, pt_regs)
{
    int new_entry;
    struct endpoint_val_t* val;
    struct sock* sk = (struct sock *)PT_REGS_PARM1(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);

    val = get_udp_val(sk, &new_entry);
    if (val) {
        ATOMIC_INC_EP_STATS(val, EP_STATS_UDP_RCVS, len);
        report(ctx, val, new_entry);
    }
    return 0;
}

KRAWTRACE(udp_fail_queue_rcv_skb, bpf_raw_tracepoint_args)
{
    int new_entry;
    struct endpoint_val_t* val;
    int rc = (int)ctx->args[0];
    struct sock *sk = (struct sock *)ctx->args[1];

    val = get_udp_val(sk, &new_entry);
    if (val) {
        ATOMIC_INC_EP_STATS(val, EP_STATS_QUE_RCV_FAILED, 1);
        val->udp_err_code = rc;
    }
    return 0;
}

KPROBE(udp_init_sock, pt_regs)
{
    struct sock* sk = (struct sock *)PT_REGS_PARM1(ctx);
    (void)create_sock_map(sk, SK_TYPE_CLIENT_UDP, (bpf_get_current_pid_tgid() >> INT_LEN));
    report_udp(ctx, sk);
    return 0;
}
