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
 * Description: ksli probe header file
 ******************************************************************************/
#ifndef __KSLIPROBE_H__
#define __KSLIPROBE_H__

#define TC_PROG "tc_tstamp.bpf.o"

#define MAX_COMMAND_REQ_SIZE (32 - 1)
#define MAX_REDIS_PROC_NAME_SIZE 8

#define FIND0_MSG_START 0
#define FIND1_PARM_NUM 1
#define FIND2_CMD_LEN 2
#define FIND3_CMD_STR 3
#define FIND_MSG_ERR_STOP 10
#define FIND_MSG_OK_STOP 11

#define SLI_OK       0
#define SLI_ERR      (-1)

#if ((CURRENT_KERNEL_VERSION == KERNEL_VERSION(4, 18, 0)) || (CURRENT_KERNEL_VERSION >= KERNEL_VERSION(5, 10, 0)))
#define KERNEL_SUPPORT_TSTAMP
#endif

struct ksli_args_s {
    __u64 period;               // Sampling period, unit ns
    char redis_proc[MAX_REDIS_PROC_NAME_SIZE];
};

enum msg_event_rw_t {
    MSG_READ,                       // 读消息事件
    MSG_WRITE,                          // 写消息事件
};

enum conn_protocol_t {
    PROTOCOL_UNKNOWN,
    PROTOCOL_REDIS,
};

struct ip {
    union {
        __u32 ip4;
        __u8 ip6[IP6_LEN];
    };
};

struct ip_info_t {
    struct ip ipaddr;
    __u16 port;
    __u32 family;
};

struct conn_key_t {
    int tgid;                           // 连接所属进程的 tgid
    int fd;                             // 连接对应 socket 的文件描述符
};

struct conn_id_t {
    int tgid;
    int fd;
    enum conn_protocol_t protocol;
    struct ip_info_t server_ip_info;
    struct ip_info_t client_ip_info;
};

struct rtt_cmd_t {
    char command[MAX_COMMAND_REQ_SIZE]; // command
    __u64 rtt_nsec;                     // 收发时延
};

struct conn_data_t {
    struct conn_id_t id;
    void *sk;                               // tcp连接对应的 sk 地址
    struct rtt_cmd_t latency;
    struct rtt_cmd_t max;
    struct rtt_cmd_t current;
    __u64 last_report_ts_nsec;              // 上一次上报完成的时间点
};

struct msg_event_data_t {
    struct conn_id_t conn_id;
    struct rtt_cmd_t latency;
    struct rtt_cmd_t max;
    struct ip_info_t server_ip_info;
    struct ip_info_t client_ip_info;
};

#define KSLIPROBE_RET(func, type, caller_type) \
    bpf_section("kprobe/" #func) \
    void __kprobe_bpf_##func(struct type *ctx) { \
        int ret; \
        int fd = (int)PT_REGS_PARM1(ctx); \
        struct __probe_key __key = {0}; \
        struct __probe_val __val = {0}; \
        struct conn_key_t conn_key = {0}; \
        u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN; \
        init_conn_key(&conn_key, fd, tgid); \
        if ((struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key) == (void *)0) { \
            if (update_conn_map_n_conn_samp_map(fd, tgid, &conn_key) != SLI_OK) \
                return; \
        } \
        __get_probe_key(&__key, (const long)PT_REGS_FP(ctx), caller_type); \
        __get_probe_val(&__val, (const long)PT_REGS_PARM1(ctx), \
                               (const long)PT_REGS_PARM2(ctx), \
                               (const long)PT_REGS_PARM3(ctx), \
                               (const long)PT_REGS_PARM4(ctx), \
                               (const long)PT_REGS_PARM5(ctx), \
                               (const long)PT_REGS_PARM6(ctx)); \
        ret = __do_push_match_map(&__key, &__val); \
        if (ret < 0) { \
            bpf_printk("---KPROBE_RET[" #func "] push failed.\n"); \
            __do_pop_match_map_entry((const struct __probe_key *)&__key, \
                                        &__val); \
        } \
    } \
    \
    bpf_section("kretprobe/" #func) \
    void __kprobe_ret_bpf_##func(struct type *ctx)

#endif