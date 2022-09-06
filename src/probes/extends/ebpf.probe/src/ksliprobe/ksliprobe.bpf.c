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
#include "ksliprobe.h"

#define BPF_F_INDEX_MASK        0xffffffffULL
#define BPF_F_CURRENT_CPU       BPF_F_INDEX_MASK

#define MAX_CONN_LEN            8192

#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))

char g_license[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") conn_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct conn_key_t),
    .value_size = sizeof(struct conn_data_t),
    .max_entries = MAX_CONN_LEN,
};

struct bpf_map_def SEC("maps") msg_event_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
};

// Data collection args
struct bpf_map_def SEC("maps") args_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),    // const value 0
    .value_size = sizeof(struct ksli_args_s),  // args
    .max_entries = 1,
};

enum samp_status_t {
    SAMP_INIT = 0,
    SAMP_READ_READY,
    SAMP_WRITE_READY,
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

struct bpf_map_def SEC("maps") conn_samp_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock *),
    .value_size = sizeof(struct conn_samp_data_t),
    .max_entries = MAX_CONN_LEN,
};

static __always_inline char is_redis_proc(void)
{
    u32 key = 0;
    char comm[TASK_COMM_LEN] = {0};

    struct ksli_args_s *args;
    args = (struct ksli_args_s *)bpf_map_lookup_elem(&args_map, &key);

    (void)bpf_get_current_comm(&comm, TASK_COMM_LEN);

    if (args == NULL) {
        if ((comm[0] == 'r') && (comm[1] == 'e')
            && (comm[2] == 'd') && (comm[3] == 'i') && (comm[4] == 's')) {
            return 1;
        }
    } else {
        if ((comm[0] == args->redis_proc[0]) && (comm[1] == args->redis_proc[1])
            && (comm[2] == args->redis_proc[2]) && (comm[3] == args->redis_proc[3])
            && (comm[4] == args->redis_proc[4])) {
            return 1;
        }
    }

    return 0;
}

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
        bpf_probe_read(conn_id->server_ip_info.ipaddr.ip6, IP6_LEN, &sk->sk_v6_rcv_saddr);
        bpf_probe_read(conn_id->client_ip_info.ipaddr.ip6, IP6_LEN, &sk->sk_v6_daddr);
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

    if (is_redis_proc()) {
        conn_data.id.protocol = PROTOCOL_REDIS;
    }

    err = bpf_map_update_elem(&conn_map, conn_key, &conn_data, BPF_ANY);
    if (err < 0) {
        return SLI_ERR;
    }

    return init_conn_samp_data(sk);
}

// 创建服务端 tcp 连接
KRETPROBE(__sys_accept4, pt_regs)
{
    int fd = PT_REGS_RC(ctx);
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;

    struct conn_key_t conn_key = {0};

    if (fd < 0) {
        return;
    }

    init_conn_key(&conn_key, fd, tgid);
    (void)update_conn_map_n_conn_samp_map(fd, tgid, &conn_key);

    return;
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
        return;
    }
    bpf_map_delete_elem(&conn_samp_map, &conn_data->sk);
    bpf_map_delete_elem(&conn_map, &conn_key);

    return;
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
            if ((msg_char >= '0' && msg_char <= '9') || msg_char == '\r' || msg_char == '\n') {
                ;
            } else if (msg_char == '$') {
                *find_state = FIND2_CMD_LEN;
            } else {
                *find_state = FIND_MSG_ERR_STOP;
            }
            break;
        case FIND2_CMD_LEN:
            if ((msg_char >= '0' && msg_char <= '9') || msg_char == '\r') {
                ;
            } else if (msg_char == '\n') {
                *find_state = FIND3_CMD_STR;
            } else {
                *find_state = FIND_MSG_ERR_STOP;
            }
            break;
        case FIND3_CMD_STR:
            if (msg_char >= 'a') 
                msg_char = msg_char - ('a'-'A');
            if (msg_char >= 'A' && msg_char <= 'Z') {
                command[*j] = msg_char;
                *j = *j + 1;
            } else if (msg_char == '\r' || msg_char == '\n') {
                *find_state = FIND_MSG_OK_STOP;
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
        return PROTOCOL_UNKNOWN;
    }

    // 解析请求中的command，确认协议
    if (identify_protocol_redis(msg, conn_data->current.command) == SLI_OK) {
        return PROTOCOL_REDIS;
    }

    return PROTOCOL_UNKNOWN;
}

#ifndef __PERIOD
#define __PERIOD NS(30)
#endif
static __always_inline u64 get_period()
{
    u32 key = 0;
    u64 period = __PERIOD;

    struct ksli_args_s *args;
    args = (struct ksli_args_s *)bpf_map_lookup_elem(&args_map, &key);
    if (args) {
        period = args->period;
    }

    return period; // units from second to nanosecond
}

static __always_inline void periodic_report(u64 ts_nsec, struct conn_data_t *conn_data, struct pt_regs *ctx)
{
    long err;
    u64 period = get_period();

    // 表示没有任何采样数据，不上报
    if (conn_data->latency.rtt_nsec == 0) {
        return;
    }

    if (ts_nsec > conn_data->last_report_ts_nsec &&
        ts_nsec - conn_data->last_report_ts_nsec >= period) {
        // rtt larger than period is considered an invalid value
        if (conn_data->latency.rtt_nsec < period && conn_data->max.rtt_nsec < period) {
            struct msg_event_data_t msg_evt_data = {0};
            msg_evt_data.conn_id = conn_data->id;
            msg_evt_data.server_ip_info = conn_data->id.server_ip_info;
            msg_evt_data.client_ip_info = conn_data->id.client_ip_info;
            msg_evt_data.latency = conn_data->latency;
            msg_evt_data.max = conn_data->max;
            err = bpf_perf_event_output(ctx, &msg_event_map, BPF_F_CURRENT_CPU,
                                        &msg_evt_data, sizeof(struct msg_event_data_t));
            if (err < 0) {
                bpf_printk("message event sent failed.\n");
            }
        }
        conn_data->latency.rtt_nsec = 0;
        conn_data->max.rtt_nsec = 0;
        conn_data->last_report_ts_nsec = ts_nsec;
    }
    return;
}

static __always_inline void sample_finished(struct conn_data_t *conn_data, struct conn_samp_data_t *csd)
{
    if (conn_data->latency.rtt_nsec == 0) {
        conn_data->latency.rtt_nsec = csd->rtt_ts_nsec;
        __builtin_memcpy(&conn_data->latency.command, &csd->command, MAX_COMMAND_REQ_SIZE);
    }
    if (conn_data->max.rtt_nsec < csd->rtt_ts_nsec) {
        conn_data->max.rtt_nsec = csd->rtt_ts_nsec;
        __builtin_memcpy(&conn_data->max.command, &csd->command, MAX_COMMAND_REQ_SIZE);
    }
    csd->status = SAMP_INIT;
}

static __always_inline void process_rdwr_msg(int fd, const char *buf, const unsigned int count, enum msg_event_rw_t rw_type,
                                             struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    struct conn_key_t conn_key = {0};
    struct conn_data_t *conn_data;
    u64 ts_nsec = bpf_ktime_get_ns();
    struct conn_samp_data_t *csd;
    int parsed = 0;

    init_conn_key(&conn_key, fd, tgid);
    conn_data = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
    if (conn_data == (void *)0) {
        return;
    }
    csd = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &conn_data->sk);
    if (csd == (void *)0) {
        return;
    }

    if ((rw_type == MSG_READ) && (conn_data->id.protocol == PROTOCOL_UNKNOWN)) {
        enum conn_protocol_t protocol = parse_req(conn_data, count, buf);
        conn_data->id.protocol = protocol;
        parsed = 1;
    }

    if (conn_data->id.protocol == PROTOCOL_UNKNOWN) {
        return;
    }

    if (rw_type == MSG_READ) {
        if (csd->status == SAMP_FINISHED) {
            sample_finished(conn_data, csd);
        }

        // 周期上报
        periodic_report(ts_nsec, conn_data, ctx);

        if (csd->status != SAMP_INIT) {
            // 超过采样周期，则重置采样状态，避免采样状态一直处于不可达的情况
            if (ts_nsec > csd->start_ts_nsec &&
                ts_nsec - csd->start_ts_nsec >= __PERIOD) {
                csd->status = SAMP_INIT;
            }
            return;
        }

        if (!parsed) {
            (void)parse_req(conn_data, count, buf);
        }
        __builtin_memcpy(&csd->command, conn_data->current.command, MAX_COMMAND_REQ_SIZE);

#ifndef KERNEL_SUPPORT_TSTAMP
        csd->start_ts_nsec = ts_nsec;
#endif
        csd->status = SAMP_READ_READY;
    } else {
        if (csd->status == SAMP_READ_READY) {
            csd->status = SAMP_WRITE_READY;
        }
    }

    return;
}

// 跟踪连接 read 读消息
KSLIPROBE_RET(ksys_read, pt_regs, CTX_USER)
{
    int fd;
    u32 tgid __maybe_unused = bpf_get_current_pid_tgid() >> INT_LEN;
    int count = PT_REGS_RC(ctx);
    char *buf;
    struct probe_val val;
    int err;

    err = PROBE_GET_PARMS(ksys_read, ctx, val, CTX_USER);
    if (err < 0) {
        return;
    }

    if (count <= 0) {
        return;
    }

    fd = (int)PROBE_PARM1(val);
    buf = (char *)PROBE_PARM2(val);

    process_rdwr_msg(fd, buf, count, MSG_READ, ctx);

    return;
}

// 跟踪连接 write 写消息
KPROBE(ksys_write, pt_regs)
{
    int fd;
    u32 tgid __maybe_unused = bpf_get_current_pid_tgid() >> INT_LEN;
    char *buf;

    fd = (int)PT_REGS_PARM1(ctx);
    buf = (char *)PT_REGS_PARM2(ctx);

    // MSG_WRITE doesn't need pass count
    process_rdwr_msg(fd, buf, 0, MSG_WRITE, ctx);

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
        if ((csd->status == SAMP_FINISHED || csd->status == SAMP_INIT)) {
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
