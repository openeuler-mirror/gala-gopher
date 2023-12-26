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
 * Author: wo_cow
 * Create: 2022-4-14
 * Description: ksli probe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include <bpf/bpf_endian.h>
#include "feat_probe.h"
#include "ksliprobe.h"

#define MAX_CONN_LEN                8192
#define MAX_CHECK_TIMES                2

#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))

char g_license[] SEC("license") = "GPL";

struct stash_args {
    unsigned int fd;
    char *buf;
};

// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
struct sys_enter_read_args {
    unsigned long long __unused__;
    long __syscall_nr;
    unsigned int fd;
    char *buf;
    u64 count;
};

// cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
struct sys_exit_read_args {
    unsigned long long __unused__;
    long __syscall_nr;
    int ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct conn_key_t));
    __uint(value_size, sizeof(struct conn_data_t));
    __uint(max_entries, MAX_CONN_LEN);
} conn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} msg_event_map SEC(".maps");

// Data collection args
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32)); // const value 0
    __uint(value_size, sizeof(struct ksli_args_s)); // args
    __uint(max_entries, 1);
} args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct stash_args));
    __uint(max_entries, 10 * 1024);
} stash_args_map SEC(".maps");

enum samp_status_t {
    SAMP_INIT = 0,
    SAMP_READ_READY,
    SAMP_SKB_READY,
    SAMP_FINISHED,
};

struct conn_samp_data_t {
    enum samp_status_t status;
    u32 end_seq;
    u64 start_ts_nsec;
    u64 rtt_ts_nsec;
    char command[MAX_COMMAND_REQ_SIZE]; // command
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct sock *));
    __uint(value_size, sizeof(struct conn_samp_data_t));
    __uint(max_entries, MAX_CONN_LEN);
} conn_samp_map SEC(".maps");

static __always_inline void init_conn_key(struct conn_key_t *conn_key, int fd, int tgid)
{
    conn_key->fd = fd;
    conn_key->tgid = tgid;
}

static __always_inline int init_conn_id(struct conn_id_t *conn_id, int fd, int tgid, struct sock *sk)
{

    conn_id->client_ip_info.family = _(sk->sk_family);
    if (conn_id->client_ip_info.family == AF_INET) {
        conn_id->server_ip_info.ipaddr.ip4 = _(sk->sk_rcv_saddr);
        conn_id->client_ip_info.ipaddr.ip4 = _(sk->sk_daddr);
    } else if (conn_id->client_ip_info.family == AF_INET6) {
        bpf_core_read(conn_id->server_ip_info.ipaddr.ip6, IP6_LEN, &sk->sk_v6_rcv_saddr);
        bpf_core_read(conn_id->client_ip_info.ipaddr.ip6, IP6_LEN, &sk->sk_v6_daddr);
    } else {
        return -1;
    }

    conn_id->server_ip_info.port = _(sk->sk_num);
    conn_id->client_ip_info.port = _(sk->sk_dport);

    conn_id->fd = fd;
    conn_id->tgid = tgid;
    return 0;
}

static __always_inline int init_conn_samp_data(struct sock *sk)
{
    struct conn_samp_data_t csd = {0};
    csd.status = SAMP_INIT;
    return bpf_map_update_elem(&conn_samp_map, &sk, &csd, BPF_ANY);
}

#ifndef __PERIOD
#define __PERIOD NS(5)
#endif
static __always_inline void get_args(struct conn_data_t *conn_data)
{
    u32 key = 0;
    u64 period = __PERIOD;
    char continuous_sampling_flag = 0;

    struct ksli_args_s *args;
    args = (struct ksli_args_s *)bpf_map_lookup_elem(&args_map, &key);
    if (args) {
        period = args->period;
        continuous_sampling_flag = args->continuous_sampling_flag;
    }

    conn_data->report_period = period;
    conn_data->continuous_sampling_flag = continuous_sampling_flag;

    return;
}

static __always_inline int update_conn_map_n_conn_samp_map(int fd, int tgid, struct conn_key_t *conn_key)
{
    long err;
    struct conn_data_t conn_data = {0};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct sock *sk = sock_get_by_fd(fd, task);
    if (sk == (void *)0) {
        return SLI_ERR;
    }
    conn_data.sk = (void *)sk;

    if (init_conn_id(&conn_data.id, fd, tgid, sk) < 0) {
        return SLI_ERR;
    }

    get_args(&conn_data);

    err = bpf_map_update_elem(&conn_map, conn_key, &conn_data, BPF_ANY);
    if (err < 0) {
        return SLI_ERR;
    }

    return init_conn_samp_data(sk);
}

// 关闭 tcp 连接
KPROBE(__close_fd, pt_regs)
{
    int fd;
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    struct conn_key_t conn_key = {0};
    struct conn_data_t *conn_data;

    fd = (int)PT_REGS_PARM2(ctx);
    init_conn_key(&conn_key, fd, tgid);
    conn_data = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
    if (conn_data == (void *)0) {
        return 0;
    }
    bpf_map_delete_elem(&conn_samp_map, &conn_data->sk);
    bpf_map_delete_elem(&conn_map, &conn_key);

    return 0;
}

static __always_inline void parse_msg_to_redis_cmd(char msg_char, int *j, char *command, unsigned short *find_state)
{
    switch (*find_state) {
        case FIND0_MSG_START:
            if (msg_char == '*') {
                *find_state = FIND1_PARM_NUM;
            } else {
                *find_state = FIND_MSG_ERR_STOP;
            }
            break;
            
        case FIND1_PARM_NUM:
            if (msg_char == '$') {
                *find_state = FIND2_CMD_LEN;
            }
            break;
        case FIND2_CMD_LEN:
            if (msg_char == '\n') {
                *find_state = FIND3_CMD_STR;
            }
            break;
        case FIND3_CMD_STR:
            if (*j == 3) {
                *find_state = FIND_MSG_OK_STOP;
                break;
            }
            if (msg_char >= 'a') 
                msg_char = msg_char - ('a'-'A');
            if (msg_char >= 'A' && msg_char <= 'Z') {
                command[*j] = msg_char;
                *j = *j + 1;
            } else {
                *find_state = FIND_MSG_ERR_STOP;
            }
            break;
        case FIND_MSG_OK_STOP:
        case FIND_MSG_ERR_STOP:
            break;
        default:
            break;
    }
    
    return;
}

static __always_inline int identify_protocol_redis(char *msg, char *command)
{
    int j = 0;
    unsigned short find_state = FIND0_MSG_START;

#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_COMMAND_REQ_SIZE - 2; i++) {
       parse_msg_to_redis_cmd(msg[i], &j, command, &find_state);
    }
    if (find_state != FIND_MSG_OK_STOP) {
        return SLI_ERR;
    }
    return SLI_OK;
}

static __always_inline int parse_req(struct conn_data_t *conn_data, const unsigned int count, const char *buf)
{
    volatile u32 copy_size;
    long err;
    char msg[MAX_COMMAND_REQ_SIZE] = {0};

    copy_size = count < MAX_COMMAND_REQ_SIZE ? count : (MAX_COMMAND_REQ_SIZE - 1);
    err = bpf_probe_read(msg, copy_size & MAX_COMMAND_REQ_SIZE, buf);
    if (err < 0) {
        bpf_printk("parse_req read buffer failed.\n");
        return PROTOCOL_NO_REDIS;
    }

    // 解析请求中的command，确认协议
    if (identify_protocol_redis(msg, conn_data->current.command) == SLI_OK) {
        conn_data->current.command[3] = 0;
        return PROTOCOL_REDIS;
    }

    return PROTOCOL_NO_REDIS;
}

static __always_inline int periodic_report(u64 ts_nsec, struct conn_data_t *conn_data, void *ctx)
{
    long err;
    int ret = 0;

    // period cannot be 0, so it is considered that the user mode has not written to args_map by now.
    // therefore we try to get the value agagin.
    if (conn_data->report_period == 0)
        get_args(conn_data);

    u64 period = (conn_data->report_period != 0) ? conn_data->report_period : __PERIOD;

    // 表示没有任何采样数据，不上报
    if (conn_data->latency.rtt_nsec == 0) {
        return 0;
    }

    if (ts_nsec > conn_data->last_report_ts_nsec &&
        ts_nsec - conn_data->last_report_ts_nsec >= period) {
        // rtt larger than period is considered an invalid value
        if (conn_data->latency.rtt_nsec < period) {
            struct msg_event_data_t msg_evt_data = {0};
            msg_evt_data.conn_id = conn_data->id;
            msg_evt_data.server_ip_info = conn_data->id.server_ip_info;
            msg_evt_data.client_ip_info = conn_data->id.client_ip_info;
            msg_evt_data.latency = conn_data->latency;
            msg_evt_data.max = conn_data->max;
            err = bpfbuf_output(ctx, &msg_event_map, &msg_evt_data, sizeof(struct msg_event_data_t));
            if (err < 0) {
                bpf_printk("message event sent failed.\n");
            }
        }
        conn_data->latency.rtt_nsec = 0;
        conn_data->max.rtt_nsec = 0;
        conn_data->last_report_ts_nsec = ts_nsec;
        ret = 1;
    }
    return ret;
}

static __always_inline void sample_finished(struct conn_data_t *conn_data, struct conn_samp_data_t *csd)
{
    if (conn_data->latency.rtt_nsec == 0) {
        conn_data->latency.rtt_nsec = csd->rtt_ts_nsec;
        __builtin_memcpy(&conn_data->latency.command, &csd->command, MAX_COMMAND_REQ_SIZE);
    }
    if (conn_data->continuous_sampling_flag) {
        if (conn_data->max.rtt_nsec < csd->rtt_ts_nsec) {
            conn_data->max.rtt_nsec = csd->rtt_ts_nsec;
            __builtin_memcpy(&conn_data->max.command, &csd->command, MAX_COMMAND_REQ_SIZE);
        }
    }
    csd->status = SAMP_INIT;
}

static __always_inline void mark_no_redis_conn(struct conn_data_t *conn_data)
{
    conn_data->id.protocol = PROTOCOL_NO_REDIS;
    bpf_map_delete_elem(&conn_samp_map, &conn_data->sk);
}

static __always_inline void process_rd_msg(u32 tgid, int fd, const char *buf, const unsigned int count,
                                           void *ctx)
{
    struct conn_key_t conn_key = {0};
    struct conn_data_t *conn_data;
    u64 ts_nsec = bpf_ktime_get_ns();
    struct conn_samp_data_t *csd;
    int reported = 0;

    init_conn_key(&conn_key, fd, tgid);
    conn_data = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
    if (conn_data == (void *)0) {
        return;
    }
    csd = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &conn_data->sk);
    if (csd == (void *)0) {
        return;
    }

    if (csd->status == SAMP_FINISHED) {
        sample_finished(conn_data, csd);
    }

    // 周期上报
    reported = periodic_report(ts_nsec, conn_data, ctx);

    if (csd->status != SAMP_INIT) {
        // 超过采样周期，则重置采样状态，避免采样状态一直处于不可达的情况
        if (ts_nsec > csd->start_ts_nsec &&
            ts_nsec - csd->start_ts_nsec >= __PERIOD) {
            csd->status = SAMP_INIT;
        }
        return;
    }

    // 非循环采样每次上报后就返回，等待下次上报周期再采样。这种方式无法获取周期内max sli
    if (!conn_data->continuous_sampling_flag && reported)
        return;

    // 连接的协议类型未知时，连续3次read报文时解析不出是redis协议，就确认此条连接非redis请求连接，不做采样
    // 一旦确认为redis连接则不会再修改连接的协议类型
    enum conn_protocol_t protocol = parse_req(conn_data, count, buf);
    if (protocol == PROTOCOL_NO_REDIS) {
        if (conn_data->id.protocol == PROTOCOL_UNKNOWN) {
            if (conn_data->procotol_check_times >= MAX_CHECK_TIMES) {
                mark_no_redis_conn(conn_data);
            } else {
                conn_data->procotol_check_times++;
            }
        }
        return;
    }
    if (conn_data->id.protocol == PROTOCOL_UNKNOWN) {
        conn_data->id.protocol = PROTOCOL_REDIS;
    }

    __builtin_memcpy(&csd->command, conn_data->current.command, MAX_COMMAND_REQ_SIZE);

    if (!probe_tstamp()) {
        csd->start_ts_nsec = ts_nsec;
    } else {
        if (csd->start_ts_nsec == 0 || csd->start_ts_nsec > ts_nsec) {
            csd->start_ts_nsec = ts_nsec;
        }
    }

    csd->status = SAMP_READ_READY;

    return;
}

bpf_section("tracepoint/syscalls/sys_enter_read")
int function_sys_enter_read(struct sys_enter_read_args *ctx)
{
    int fd = ctx->fd;
    if (fd == 0) {
        return 0;
    }

    struct conn_key_t conn_key = {0};
    u64 key = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(key >> INT_LEN);
    init_conn_key(&conn_key, fd, tgid);

    struct conn_data_t * conn_data = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
    if (conn_data == (void *)0) {
        if (update_conn_map_n_conn_samp_map(fd, tgid, &conn_key) != SLI_OK)
            return 0;
    }
    
    if (conn_data == (void *)0)
        return 0;

    if (conn_data->id.protocol == PROTOCOL_NO_REDIS)
        return 0;

    if (!conn_data->continuous_sampling_flag) {
        if (bpf_ktime_get_ns() - conn_data->last_report_ts_nsec < conn_data->report_period)
            return 0;
    }

    struct stash_args in_params = {0};
    in_params.fd = fd;
    in_params.buf = ctx->buf;
    (void)bpf_map_update_elem(&stash_args_map, &key, &in_params, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_read")
int function_sys_exit_read(struct sys_exit_read_args *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct stash_args *in_params = (struct stash_args *)bpf_map_lookup_elem(&stash_args_map, &key);
    if (in_params == (void *)0) {
        return 0;
    }
    int fd = in_params->fd;
    char *buf = in_params->buf;
    (void)bpf_map_delete_elem(&stash_args_map, &key);

    int count = ctx->ret;
    if (count <= 0) {
        return 0;
    }

    u32 tgid = (u32)(key >> INT_LEN);
    process_rd_msg(tgid, fd, buf, count, ctx);

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
        if (csd->status == SAMP_READ_READY) {
            csd->end_seq = _(TCP_SKB_CB(skb)->end_seq);
            csd->status = SAMP_SKB_READY;
        }
    }
    return 0;
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
                csd->start_ts_nsec = 0;
                return 0;
            }
            csd->rtt_ts_nsec = end_ts_nsec - csd->start_ts_nsec;
            csd->status = SAMP_FINISHED;
            csd->start_ts_nsec = 0;
        }
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
