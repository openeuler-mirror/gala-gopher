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
 * Author: Ernest
 * Create: 2022-08-27
 * Description: kernel probe bpf prog for http syscall
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN

#include "httpprobe.bpf.h"

#define BPF_F_INDEX_MASK        0xffffffffULL
#define BPF_F_CURRENT_CPU       BPF_F_INDEX_MASK

char g_linsence[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} http_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct http_args_s));
    __uint(max_entries, 1);
} args_map SEC(".maps");

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_accept/format
struct sys_exit_accept_args {
    unsigned long long __unused__;
    long __syscall_nr;
    long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_accept4/format
struct sys_exit_accept4_args {
    unsigned long long __unused__;
    long __syscall_nr;
    long ret;
};

#ifndef PERIOD
#define PERIOD NS(5)
#endif
static __always_inline u64 get_period()
{
    u32 key = 0;
    u64 period = PERIOD;

    struct http_args_s *args = (struct http_args_s *)bpf_map_lookup_elem(&args_map, &key);
    if (args) {
        period = args->period;
    }
    return period;
}

static __always_inline void init_conn_info(struct conn_info_t *conn_info, struct sock *sk)
{
    conn_info->client_ip_info.family = _(sk->sk_family);
    if (conn_info->client_ip_info.family == AF_INET) {
        conn_info->server_ip_info.ipaddr.ip4 = _(sk->sk_rcv_saddr);
        conn_info->client_ip_info.ipaddr.ip4 = _(sk->sk_daddr);
    } else if (conn_info->client_ip_info.family == AF_INET6) {
        bpf_probe_read(conn_info->server_ip_info.ipaddr.ip6, IP6_LEN, &sk->sk_v6_rcv_saddr);
        bpf_probe_read(conn_info->client_ip_info.ipaddr.ip6, IP6_LEN, &sk->sk_v6_daddr);
    } else {
        return;
    }
    conn_info->server_ip_info.port = _(sk->sk_num);
    conn_info->client_ip_info.port = _(sk->sk_dport);
}

static __always_inline void periodic_report(struct conn_samp_data_t *data, struct pt_regs *ctx, struct sock *sk)
{
    struct http_request req = {0};
    u64 curr_nano_time = bpf_ktime_get_ns(), period = get_period();
 
    if (data->method == HTTP_UNKNOWN) {
        return;
    }
    if (data->ackedtime - data->recvtime > data->longestrtt) {
        data->longestrtt = data->ackedtime - data->recvtime;
    }
    if (curr_nano_time > data->lastreport && curr_nano_time - data->lastreport > period) {
        data->lastreport = curr_nano_time;
        req.tgid = data->tgid;
        req.skfd = data->skfd;
        req.method = data->method;
        req.latestrtt = data->ackedtime - data->recvtime;
        req.longestrtt = data->longestrtt;
        init_conn_info(&(req.conn_info), sk);
        bpf_perf_event_output(ctx, &http_events, BPF_F_CURRENT_CPU, &req, sizeof(struct http_request));
    }
}

static __always_inline void handle_req(struct pt_regs *ctx)
{
    char buf[REQ_BUF_SIZE] = {0};
    struct conn_key_t key = {0};
    struct conn_data_t *data = NULL;
    struct probe_val val = {0};
    if (PROBE_GET_PARMS(__sys_recvfrom, ctx, val, CTX_USER) < 0 || (int)PT_REGS_RC(ctx) < REQ_BUF_SIZE) {
        return;
    }

    u32 tgid = bpf_get_current_pid_tgid() >> TGID_LSHIFT_LEN;
    key.tgid = tgid;
    key.skfd = (int)PROBE_PARM1(val);
    data = bpf_map_lookup_elem(&conn_map, &key);
    if (data == NULL || data->status == READY_FOR_SEND) {
        return;
    }
    bpf_probe_read(buf, REQ_BUF_SIZE, (const char *)PROBE_PARM2(val));
    data->method = parse_req_method(buf);
    if (data->method == HTTP_UNKNOWN) {
        data->status = READY_FOR_RECVIVE;
        return;
    }
    data->status = READY_FOR_SEND;
    data->recvtime = bpf_ktime_get_ns();
}

static __always_inline int handle_sys_accept4(int skfd)
{
    struct conn_key_t ckey = {0};
    struct conn_data_t cdata = {0};
    struct conn_samp_key_t cskey = {0};
    struct conn_samp_data_t csdata = {0};
    struct task_struct *task_p = (struct task_struct *)bpf_get_current_task();
    u32 tgid = bpf_get_current_pid_tgid() >> TGID_LSHIFT_LEN;
    ckey.tgid = tgid;
    ckey.skfd = skfd;
    cdata.status = READY_FOR_RECVIVE;
    cdata.sock = (u64)sock_get_by_fd(ckey.skfd, task_p);
    bpf_map_update_elem(&conn_map, &ckey, &cdata, BPF_ANY);

    cskey.sk = (struct sock *)cdata.sock;
    csdata.tgid = ckey.tgid;
    csdata.skfd = ckey.skfd;
    csdata.status = READY_FOR_WRITE;
    bpf_map_update_elem(&conn_samp_map, &cskey, &csdata, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_accept4")
int function_sys_exit_accept4(struct sys_exit_accept4_args *ctx)
{
    int skfd = (int)(ctx->ret);
    if (skfd < 0) {
        return 0;
    }
    return handle_sys_accept4(skfd);
}

bpf_section("tracepoint/syscalls/sys_exit_accept")
int function_sys_exit_accept(struct sys_exit_accept_args *ctx)
{
    int skfd = (int)(ctx->ret);
    if (skfd < 0) {
        return 0;
    }
    return handle_sys_accept4(skfd);
}

KPROBE_RET(__sys_recvfrom, pt_regs, CTX_USER)
{
    handle_req(ctx);
    return 0;
}

KPROBE_RET(ksys_read, pt_regs, CTX_USER)
{
    handle_req(ctx);
    return 0;
}

KPROBE_RET(do_writev, pt_regs, CTX_USER)
{
    struct conn_key_t ckey = {0};
    struct conn_data_t *cdata = NULL;
    struct conn_samp_key_t cskey = {0};
    struct conn_samp_data_t *csdata = NULL;
    struct probe_val val = {0};

    if (PROBE_GET_PARMS(do_writev, ctx, val, CTX_USER) < 0 || (int)PT_REGS_RC(ctx) <= REQ_BUF_SIZE - 1) {
        return 0;
    }

    u32 tgid = bpf_get_current_pid_tgid() >> TGID_LSHIFT_LEN;
    ckey.tgid = tgid;
    ckey.skfd = (int)PROBE_PARM1(val);
    cdata = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &ckey);
    if (cdata == NULL || cdata->status == READY_FOR_RECVIVE) {
        return 0;
    }
    cskey.sk = (struct sock *)cdata->sock;
    if (cskey.sk == 0) {
        return 0;
    }
    csdata = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &cskey);
    if (csdata == NULL || csdata->status != READY_FOR_WRITE) {
        return 0;
    }
    csdata->method = cdata->method;
    csdata->status = READY_FOR_SKBSENT;
    csdata->recvtime = cdata->recvtime;
    csdata->endseq = 0;
 
    cdata->status = READY_FOR_RECVIVE;
    cdata->recvtime = 0;
    cdata->method = HTTP_UNKNOWN;
    return 0;
}

KPROBE(tcp_event_new_data_sent, pt_regs)
{
    struct sk_buff *skb_p = NULL;
    struct conn_samp_key_t key = {0};
    struct conn_samp_data_t *data = NULL;

    key.sk = (struct sock *)PT_REGS_PARM1(ctx);
    skb_p = (struct sk_buff *)PT_REGS_PARM2(ctx);
    data = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &key);
    if (data != NULL && data->status == READY_FOR_SKBSENT) {
        data->status = READY_FOR_SKBACKED;
        data->endseq = _(TCP_SKB_CB(skb_p)->end_seq);
    }
    return 0;
}

KPROBE(tcp_rate_skb_delivered, pt_regs)
{
    u32 snd_una;
    struct tcp_sock *tcp_sk;
    struct conn_samp_key_t key = {0};
    struct conn_samp_data_t *data = NULL;
    
    key.sk = (struct sock *)PT_REGS_PARM1(ctx);
    tcp_sk = (struct tcp_sock *)key.sk;
    snd_una = _(tcp_sk->snd_una);
    data = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &key);
    if (data != NULL && data->endseq <= snd_una && data->status == READY_FOR_SKBACKED) {
        data->status = READY_FOR_WRITE;
        data->ackedtime = bpf_ktime_get_ns();
        periodic_report(data, ctx, key.sk);
    }
    return 0;
}

KPROBE(__close_fd, pt_regs)
{
    struct conn_key_t ckey = {0};
    struct conn_data_t *cdata = NULL;
    struct conn_samp_key_t cskey = {0};
    struct conn_samp_data_t *csdata = NULL;

    ckey.tgid = bpf_get_current_pid_tgid() >> TGID_LSHIFT_LEN;
    ckey.skfd = (int)PT_REGS_PARM2(ctx);
    cdata = bpf_map_lookup_elem(&conn_map, &ckey);
    if (cdata != NULL) {
        cskey.sk = (struct sock *)cdata->sock;
        csdata = bpf_map_lookup_elem(&conn_samp_map, &cskey);
        if (csdata != NULL) {
            bpf_map_delete_elem(&conn_samp_map, &cskey);
        }
        bpf_map_delete_elem(&conn_map, &ckey);
    }
    return 0;
}