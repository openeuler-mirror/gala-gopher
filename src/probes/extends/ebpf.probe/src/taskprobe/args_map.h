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
 * Create: 2022-07-13
 * Description: args map defined
 ******************************************************************************/
#ifndef __ARGS_MAP_H__
#define __ARGS_MAP_H__

#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "task_args.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32)); // const value 0
    __uint(value_size, sizeof(struct task_args_s));
    __uint(max_entries, 1);
} args_map SEC(".maps");

#define PERIOD NS(30)  // 30s
static __always_inline __maybe_unused u64 get_period()
{
    u32 key = 0;
    u64 period = PERIOD;
    struct task_args_s *args;

    args = (struct task_args_s *)bpf_map_lookup_elem(&args_map, &key);
    if (args && args->report_period != 0) {
        period = args->report_period;
    }

    return period; // units: nanosecond
}

#define OFFLINE_THR NS(5)  // 5s
static __always_inline __maybe_unused u64 get_offline_thr()
{
    u32 key = 0;
    u64 offline_thr = OFFLINE_THR;
    struct task_args_s *args;

    args = (struct task_args_s *)bpf_map_lookup_elem(&args_map, &key);
    if (args && args->offline_thr != 0) {
        offline_thr = args->offline_thr;
    }

    return offline_thr; // units: nanosecond
}


#endif
