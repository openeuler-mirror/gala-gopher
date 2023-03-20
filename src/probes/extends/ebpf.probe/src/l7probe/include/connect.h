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
 * Author: luzhihao
 * Create: 2023-02-22
 * Description: Socket defined
 ******************************************************************************/
#pragma once

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>

#include "l7.h"

#define L7_CONN_BPF_PATH          "/sys/fs/bpf/gala-gopher/__l7_connect"

union sockaddr_t {
  struct sockaddr sa;
  struct sockaddr_in in4;
  struct sockaddr_in6 in6;
};

enum l7_direction_t {
    L7_EGRESS,
    L7_INGRESS,
};

enum role_type_t {
    ROLE_UNKNOW = 0,
    ROLE_CLIENT,
    ROLE_SERVER,
    ROLE_UDP,
};

struct conn_id_s {
    int tgid;                   // process id
    int fd;
};

struct conn_info_s {
    struct conn_id_s id;
    char is_ssl;
    enum role_type_t role;      // TCP client or server; UDP
    enum proto_type_t protocol; // L7 protocol type
    union sockaddr_t remote_addr; // TCP remote address; UDP datagram address
};

typedef u64 conn_ctx_t;         // pid & tgid

// The information of socket connection
struct sock_conn_s {
    struct conn_info_s info;

    // The number of bytes written/read on this socket connection.
    u64 wr_bytes;
    u64 rd_bytes;
};

enum conn_evt_e {
    CONN_EVT_OPEN,
    CONN_EVT_CLOSE,
};

struct conn_open_s {
    union sockaddr_t addr;
    enum role_type_t role;
};

struct conn_close_s {
    u64 wr_bytes;
    u64 rd_bytes;
};

// Exchange data between user mode/kernel using
// 'conn_control_events' perf channel.
struct conn_ctl_s {
    struct conn_id_s conn_id;
    u64 timestamp_ns;

    enum conn_evt_e type;
    struct conn_open_s open;
    struct conn_close_s close;
};

// Exchange data between user mode/kernel using
// 'conn_stats_events' perf channel.
struct conn_stats_s {
    struct conn_id_s conn_id;
    u64 timestamp_ns;

    // The number of bytes written on this connection.
    u64 wr_bytes;
    // The number of bytes read on this connection.
    u64 rd_bytes;
};

// Exchange data between user mode/kernel using
// 'conn_data_events' perf channel.
#define LOOP_LIMIT 4
#define CONN_DATA_MAX_SIZE  (10 * 1024)
struct conn_data_s {
    struct conn_id_s conn_id;

    u64 timestamp_ns;   // The timestamp when syscall completed.

    enum proto_type_t proto;
    enum role_type_t role;
    enum l7_direction_t direction;  // Only for tcp connection

    u64 offset_pos;     // The position is for the first data of this message.
    u64 data_size;      // The actually data size, maybe less than msg_size.
    char data[CONN_DATA_MAX_SIZE];
};

