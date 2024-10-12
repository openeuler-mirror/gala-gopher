/*
 * bpf code runs in the Linux kernel
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef __KERN_SOCK_CONN_H__
#define __KERN_SOCK_CONN_H__

#pragma once

#include "bpf.h"
#include "connect.h"

#define __MAX_CONCURRENCY   1000
#define __MAX_CONN_COUNT    1000

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct conn_id_s));
    __uint(value_size, sizeof(struct sock_conn_s));
    __uint(max_entries, __MAX_CONN_COUNT);
} conn_tbl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct conn_id_s));
    __uint(value_size, sizeof(int));    // 0: client, 1: server
    __uint(max_entries, __MAX_CONN_COUNT);
} l7_tcp SEC(".maps");

static __always_inline __maybe_unused struct sock_conn_s* lkup_sock_conn(int tgid, int fd)
{
    struct conn_id_s id = {.tgid = tgid, .fd = fd};

    return (struct sock_conn_s *)bpf_map_lookup_elem(&conn_tbl, &id);
}

static __always_inline __maybe_unused int lkup_l7_tcp(int tgid, int fd)
{
    int *value = NULL;
    struct conn_id_s id = {.tgid = tgid, .fd = fd};

    value = (int *)bpf_map_lookup_elem(&l7_tcp, &id);
    if (value == NULL) {
        return -1;
    }
    return *value;
}

static __always_inline __maybe_unused int set_sock_conn_ssl(int tgid, int fd)
{
    struct sock_conn_s *sock_conn = lkup_sock_conn(tgid, fd);
    if (sock_conn == NULL) {
        return -1;
    }
    sock_conn->info.is_ssl = 1;
    return 0;
}
#endif
