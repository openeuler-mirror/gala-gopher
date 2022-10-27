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
 * Description: include file for *.bpf.c and http probe user prog
 ******************************************************************************/
#ifndef __HTTPPROBE_H
#define __HTTPPROBE_H

#pragma once

#include "bpf.h"

#define METRIC_NAME_HTTP_PROBE  "httpprobe"

#define HTTP_UNKNOWN            0x0
#define HTTP_GET                0x1
#define HTTP_HEAD               0x2
#define HTTP_POST               0x3
#define HTTP_PUT                0x4
#define HTTP_DELETE             0x5
#define HTTP_CONNECT            0x6
#define HTTP_OPTIONS            0x7
#define HTTP_TRACE              0x8
#define HTTP_PATCH              0x9
#define HTTP_NUMS               0x9

#define READY_FOR_WRITE         0x0
#define READY_FOR_RECVIVE       0x1
#define READY_FOR_SEND          0x2
#define READY_FOR_SKBSENT       0x3
#define READY_FOR_SKBACKED      0x4

#define REQ_BUF_SIZE            0x8
#define MAX_CONN_LEN            0x500

#define TGID_LSHIFT_LEN         0x20

#if !defined INET_ADDRSTRLEN
    #define INET_ADDRSTRLEN     0x4
#endif

#define HTTP_CONN_PATH          "/sys/fs/bpf/probe/__http_conn"
#define HTTP_CONN_SAMP_PATH     "/sys/fs/bpf/probe/__http_conn_samp"

#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))

struct http_args_s {
    u64 period;
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

struct http_request {
    u32 tgid;
    int skfd;
    int method;
    u64 latestrtt;
    u64 longestrtt;
    struct conn_info_t conn_info;
};

#endif