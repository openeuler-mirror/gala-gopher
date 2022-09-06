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

#define rsk_listener    __req_common.skc_listener


char g_license[] SEC("license") = "GPL";

#define __ENDPOINT_STAT_MAX (1024)
// Used to identifies the TCP listen object.
struct bpf_map_def SEC("maps") listen_sock_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct tcp_listen_key_t),
    .value_size = sizeof(struct endpoint_val_t),
    .max_entries = __ENDPOINT_STAT_MAX,
};

// Used to identifies the TCP connect object.
struct bpf_map_def SEC("maps") conn_sock_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct tcp_connect_key_t),
    .value_size = sizeof(struct endpoint_val_t),
    .max_entries = __ENDPOINT_STAT_MAX,
};

#define __LISTEN_FD_MAX (1024)
struct bpf_map_def SEC("maps") listen_sockfd_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct listen_sockfd_key_t),
    .value_size = sizeof(int),
    .max_entries = __LISTEN_FD_MAX,
};

static __always_inline int create_tcp_obj(struct endpoint_key_t *key)
{
    struct endpoint_val_t value = {0};

    value.ts = bpf_ktime_get_ns();
    __builtin_memcpy(&(value.key), key, sizeof(struct endpoint_key_t));

    if (key->type == SK_TYPE_LISTEN_TCP) {
        return bpf_map_update_elem(&listen_sock_map, &(key->key.tcp_listen_key), &value, BPF_ANY);
    } else if (key->type == SK_TYPE_CLIENT_TCP) {
        return bpf_map_update_elem(&conn_sock_map, &(key->key.tcp_connect_key), &value, BPF_ANY);
    }

    return -1;
}

static __always_inline struct endpoint_val_t* get_tcp_obj(struct endpoint_key_t *key)
{
    if (key->type == SK_TYPE_LISTEN_TCP) {
        return bpf_map_lookup_elem(&listen_sock_map, &(key->key.tcp_listen_key));
    } else if (key->type == SK_TYPE_CLIENT_TCP) {
        return bpf_map_lookup_elem(&conn_sock_map, &(key->key.tcp_connect_key));
    }

    return 0;
}

static void get_tcp_key(struct sock *sk, struct endpoint_key_t *key, u32 tgid)
{
    if (key->type == SK_TYPE_LISTEN_TCP) {
        key->key.tcp_listen_key.tgid = tgid;
        key->key.tcp_listen_key.port = (int)_(sk->sk_num);
    } else if (key->type == SK_TYPE_CLIENT_TCP) {
        key->key.tcp_connect_key.tgid = tgid;
        init_ip(&key->key.tcp_connect_key.ip_addr, sk);
    }
    return;
}

static struct endpoint_val_t* get_tcp_val(struct sock *sk, int *new_entry)
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

    // get tcp key by sock type
    key.type = epv->type;
    get_tcp_key(sk, &key, epv->tgid);

    // get tcp obj
    value = get_tcp_obj(&key);
    if (value != 0)
        return value;

    // create tcp obj
    ret = create_tcp_obj(&key);
    if (ret < 0)
        return 0;

    *new_entry = 1;
    return get_tcp_obj(&key);
}

static void report_tcp(struct pt_regs *ctx, struct sock *sk)
{
    int new_entry;
    struct endpoint_val_t* value;

    value = get_tcp_val(sk, &new_entry);
    if (new_entry && value)
        report(ctx, value, new_entry);
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
    struct request_sock_queue icsk_accept_queue = _(inet_csk->icsk_accept_queue);

    int syn_qlen;
    bpf_probe_read(&syn_qlen, sizeof(int), &(icsk_accept_queue.qlen));

    return syn_qlen >= max_ack_backlog;
}

static __always_inline struct sock *listen_sock(struct sock *sk)
{
    struct request_sock *req = (struct request_sock *)sk;
    struct sock *lsk = _(req->rsk_listener);

    return lsk;
}

KPROBE(__sock_release, pt_regs)
{
    struct socket* socket = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = _(socket->sk);
    (void)delete_sock_map(sk);
}

KPROBE(inet_listen, pt_regs)
{
    struct socket* socket = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = _(socket->sk);
    (void)create_sock_map(sk, SK_TYPE_LISTEN_TCP, (bpf_get_current_pid_tgid() >> INT_LEN));
    report_tcp(ctx, sk);
}

KPROBE(__sys_accept4, pt_regs)
{
    int new_entry;
    struct endpoint_val_t* value;
    struct sock *sk;
    int fd = PT_REGS_PARM1(ctx);
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct listen_sockfd_key_t listen_sockfd_key = {0};

    listen_sockfd_key.tgid = tgid;
    listen_sockfd_key.fd = fd;
    if (bpf_map_lookup_elem(&listen_sockfd_map, &listen_sockfd_key) == (void *)0) {
        return;
    }

    if (task == (void *)0) {
        return;
    }

    sk = sock_get_by_fd(fd, task);
    if (sk == (void *)0) {
        return;
    }

    (void)bpf_map_delete_elem(&listen_sockfd_map, &listen_sockfd_key);

    (void)create_sock_map(sk, SK_TYPE_LISTEN_TCP, (bpf_get_current_pid_tgid() >> INT_LEN));
    value = get_tcp_val(sk, &new_entry);
    if (value) {
        ATOMIC_INC_EP_STATS(value, EP_STATS_PASSIVE_OPENS, 1);
        report(ctx, value, new_entry);
    }
    return;
}

KPROBE_RET(tcp_connect, pt_regs, CTX_KERNEL)
{
    int new_entry;
    struct endpoint_val_t* value;
    int ret = (int)PT_REGS_RC(ctx);
    struct sock *sk;
    struct probe_val val;

    if (PROBE_GET_PARMS(tcp_connect, ctx, val, CTX_KERNEL) < 0)
        return;

    sk = (struct sock *)PROBE_PARM1(val);
    if (sk == (void *)0) {
        return;
    }
    (void)create_sock_map(sk, SK_TYPE_CLIENT_TCP, (bpf_get_current_pid_tgid() >> INT_LEN));
    value = get_tcp_val(sk, &new_entry);
    if (value) {
        if (ret == 0) {
            ATOMIC_INC_EP_STATS(value, EP_STATS_ACTIVE_OPENS, 1);
        } else {
            ATOMIC_INC_EP_STATS(value, EP_STATS_ACTIVE_FAILS, 1);
        }
        report(ctx, value, new_entry);
    }
}

KPROBE(tcp_conn_request, pt_regs)
{
    int new_entry;
    struct endpoint_val_t* value;
    struct sock *sk = (struct sock *)PT_REGS_PARM3(ctx);
    bool flag = 0;
    
    value = get_tcp_val(sk, &new_entry);
    if (value) {
        if (sk_acceptq_is_full((const struct sock *)sk)) {
            ATOMIC_INC_EP_STATS(value, EP_STATS_ACCEPT_OVERFLOW, 1);
            flag = 1;
        }
        if (sk_synq_is_full((const struct sock *)sk)) {
            ATOMIC_INC_EP_STATS(value, EP_STATS_SYN_OVERFLOW, 1);
            flag = 1;
        }
        if (flag) {
            report(ctx, value, new_entry);
        }
    }

    return;
}

KPROBE(tcp_req_err, pt_regs)
{
    int new_entry;
    struct endpoint_val_t* value;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    bool abort = (bool)PT_REGS_PARM3(ctx);
    struct sock *lsk = listen_sock(sk);

    if (!abort)
        return;

     value = get_tcp_val(lsk, &new_entry);

     if (value) {
         ATOMIC_INC_EP_STATS(value, EP_STATS_LISTEN_DROPS, 1);
         report(ctx, value, new_entry);
     }

    return;
}

KPROBE_RET(tcp_create_openreq_child, pt_regs, CTX_KERNEL)
{
    struct sock *new_sk = (struct sock *)PT_REGS_RC(ctx);
    struct sock *sk;
    struct probe_val val;
    int new_entry;
    struct endpoint_val_t* value;

    if (PROBE_GET_PARMS(tcp_create_openreq_child, ctx, val, CTX_KERNEL) < 0)
        return;

    sk = (struct sock *)PROBE_PARM1(val);
    if (sk == (void *)0) {
        return;
    }
    value = get_tcp_val(sk, &new_entry);
    if (value == 0)
        return;

    if (new_sk) {
        ATOMIC_INC_EP_STATS(value, EP_STATS_PASSIVE_OPENS, 1);
    } else {
        ATOMIC_INC_EP_STATS(value, EP_STATS_LISTEN_DROPS, 1);
    }
    return;
}


KPROBE_RET(tcp_check_req, pt_regs, CTX_KERNEL)
{
    struct sock *new_sk = (struct sock *)PT_REGS_RC(ctx);
    struct sock *sk;
    struct probe_val val;
    int new_entry;
    struct endpoint_val_t* value;

    if (PROBE_GET_PARMS(tcp_check_req, ctx, val, CTX_KERNEL) < 0)
        return;

    sk = (struct sock *)PROBE_PARM1(val);
    if (sk == (void *)0) {
        return;
    }
    value = get_tcp_val(sk, &new_entry);
    if (value == 0)
        return;

    if (!new_sk) {
        ATOMIC_INC_EP_STATS(value, EP_STATS_PASSIVE_FAILS, 1);
    }
    return;
}

KRAWTRACE(tcp_retransmit_synack, bpf_raw_tracepoint_args)
{
    int new_entry;
    struct endpoint_val_t* value;
    struct sock *sk = (struct sock *)ctx->args[0];
    
    value = get_tcp_val(sk, &new_entry);
    if (value) {
        ATOMIC_INC_EP_STATS(value, EP_STATS_RETRANS_SYNACK, 1);
        report(ctx, value, new_entry);
    }

    return;
}

