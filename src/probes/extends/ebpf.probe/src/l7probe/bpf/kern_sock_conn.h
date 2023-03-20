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
 * Author: luzhihao
 * Create: 2023-03-14
 * Description: kernel socket connection
 ******************************************************************************/
#ifndef __KERN_SOCK_CONN_H__
#define __KERN_SOCK_CONN_H__

#pragma once

#ifdef BPF_PROG_KERN

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "bpf.h"
#include "connect.h"

#define __MAX_CONCURRENCY   1000
#define __MAX_CONN_COUNT    1000

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct conn_id_s));
    __uint(value_size, sizeof(struct sock_conn_s));
    __uint(max_entries, __MAX_CONN_COUNT);
} conn_tbl SEC(".maps");

static __always_inline __maybe_unused struct sock_conn_s* get_sock_conn(int tgid, int fd)
{
    conn_id_s id = {.tgid = tgid, fd = fd};

    return (struct sock_conn_s *)bpf_map_lookup_elem(&conn_tbl, &id);
}

static __always_inline __maybe_unused int set_sock_conn_ssl(int tgid, int fd)
{
    struct sock_conn_s *sock_conn = get_sock_conn(tgid, fd);
    if (sock_conn == NULL) {
        return -1;
    }
    sock_conn->info.is_ssl = 1;
    return 0;
}

#endif

#endif
