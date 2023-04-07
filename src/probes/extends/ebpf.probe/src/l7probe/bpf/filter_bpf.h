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
 * Description: l7 probe bpf filter
 ******************************************************************************/
#ifndef __L7_FILTER_BPF_H__
#define __L7_FILTER_BPF_H__

#pragma once

#ifdef BPF_PROG_KERN

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "bpf.h"
#include "include/filter.h"

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
