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
static __always_inline __maybe_unused u64 get_period(void)
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
