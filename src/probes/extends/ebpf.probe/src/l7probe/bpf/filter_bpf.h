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

#ifndef __L7_FILTER_BPF_H__
#define __L7_FILTER_BPF_H__

#pragma once

#if defined( BPF_PROG_KERN ) || defined( BPF_PROG_USER )

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "bpf.h"
#include "filter.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct filter_args_s));
    __uint(max_entries, 1);
} filter_args_tbl SEC(".maps");

static __always_inline __maybe_unused char is_filter_id(enum filter_type_t type, int filter_id)
{
    switch (type) {
        case FILTER_TGID:
        {
            struct proc_s proc = {.proc_id = (unsigned int)filter_id};
            return is_proc_exist(&proc);
        }
        case FILTER_CGRPID:
        {
            struct cgroup_s obj = {.knid = (unsigned int)filter_id, .type = CGP_TYPE_CPUACCT};
            return is_cgrp_exist(&obj);
        }
        default:
        {
            break;
        }
    }
    return 0;
}

static __always_inline __maybe_unused u32 get_filter_proto(void)
{
    int key = 0;
    struct filter_args_s *args = (struct filter_args_s *)bpf_map_lookup_elem(&filter_args_tbl, &key);
    return (args != NULL) ? (args->proto_flags) : 0;
}

static __always_inline __maybe_unused char is_filter_by_cgrp(void)
{
    int key = 0;
    struct filter_args_s *args = (struct filter_args_s *)bpf_map_lookup_elem(&filter_args_tbl, &key);
    return (args != NULL) ? (args->is_filter_by_cgrp) : 0;
}


#endif

#endif
