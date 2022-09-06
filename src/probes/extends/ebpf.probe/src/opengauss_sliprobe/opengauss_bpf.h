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
 * Author: wo_cow
 * Create: 2022-7-29
 * Description: opengauss_sli bpf header file
 ******************************************************************************/
#ifndef __OPENGAUSS_BPF_H__
#define __OPENGAUSS_BPF_H__

#define MAX_MSG_LEN_SSL 32
#define MAX_COMMAND_REQ_SIZE (32 - 1)
#define MAX_CONN_LEN            8192

enum samp_status_t {
    SAMP_INIT = 0,
    SAMP_READ_READY,
    SAMP_WRITE_READY,
    SAMP_SKB_READY,
    SAMP_FINISHED,
};

struct conn_key_t {
    __u32 tgid;
    int fd;
};

struct conn_data_t {
    struct conn_info_t conn_info;
    void *sk; // tcp连接对应的 sk 地址
    struct rtt_cmd_t latency;
    struct rtt_cmd_t max;
    __u64 last_report_ts_nsec;
};

struct conn_samp_data_t {
    enum samp_status_t status;
    u32 end_seq;
    u64 start_ts_nsec;
    u64 rtt_ts_nsec;
    char req_cmd;
    char rsp_cmd;
};

struct bpf_map_def SEC("maps") conn_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct conn_key_t),
    .value_size = sizeof(struct conn_data_t),
    .max_entries = MAX_CONN_LEN,
};

// Data collection args
struct bpf_map_def SEC("maps") args_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32), // const value 0
    .value_size = sizeof(struct ogsli_args_s), // args
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") conn_samp_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32), // struct sock *
    .value_size = sizeof(struct conn_samp_data_t),
    .max_entries = MAX_CONN_LEN,
};

#endif