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
 * Description: pgsliprobe header file
 ******************************************************************************/
#ifndef __PGSLIPROBE_H__
#define __PGSLIPROBE_H__

#define TC_TSTAMP_PROG "tc_tstamp.bpf.o"

#define SLI_OK       0
#define SLI_ERR      (-1)

#if ((CURRENT_KERNEL_VERSION == KERNEL_VERSION(4, 18, 0)) || (CURRENT_KERNEL_VERSION >= KERNEL_VERSION(5, 10, 0)))
#define KERNEL_SUPPORT_TSTAMP
#endif

struct ogsli_args_s {
    __u64 period; // Sampling period, unit ns
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

struct conn_info_t {
    struct ip_info_t server_ip_info;
    struct ip_info_t client_ip_info;
};

struct rtt_cmd_t {
    char req_cmd;
    __u64 rtt_nsec;
};

struct msg_event_data_t {
    __u32 tgid;
    int fd;
    struct conn_info_t conn_info;
    struct rtt_cmd_t latency;
    struct rtt_cmd_t max;
};


#endif