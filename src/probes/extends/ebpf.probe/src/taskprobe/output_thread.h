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
 * Description: output of thread
 ******************************************************************************/
#ifndef __OUTPUT_THREAD_H__
#define __OUTPUT_THREAD_H__

#pragma once

#ifdef BPF_PROG_KERN

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "args_map.h"
#include "task.h"
#include "thread.h"

#define BPF_F_INDEX_MASK    0xffffffffULL
#define BPF_F_CURRENT_CPU   BPF_F_INDEX_MASK

#define PERF_OUT_MAX (64)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, PERF_OUT_MAX);
} g_thread_output SEC(".maps");

#define IS_THREAD_TMOUT(stats_ts, ts, period, type, tmout) \
    do \
    { \
        if (((ts) > (stats_ts)->ts_##type) && (((ts) - (stats_ts)->ts_##type) >= period)) { \
            (stats_ts)->ts_##type = (ts); \
            tmout = 1; \
        } else { \
            tmout = 0; \
        } \
    } while (0)

static __always_inline __maybe_unused char is_thread_tmout(struct thread_data *task, u32 flags)
{
    char tmout;
    u64 ts = bpf_ktime_get_ns();
    u64 period = get_period();

    struct thread_ts_s *stats_ts = &(task->stats_ts);

    if (flags & TASK_PROBE_THREAD_CPU) {
        IS_THREAD_TMOUT(stats_ts, ts, period, cpu, tmout);
    } else {
        tmout = 0;
    }

    return tmout;
}

static __always_inline __maybe_unused void report_thread(void *ctx, struct thread_data *val, u32 flags)
{
    if (!is_thread_tmout(val, flags)) {
        return;
    }

    val->flags = flags;
    (void)bpf_perf_event_output(ctx, &g_thread_output, BPF_F_CURRENT_CPU, val, sizeof(struct thread_data));
    val->flags = 0;

    if (flags & TASK_PROBE_THREAD_CPU) {
        __builtin_memset(&(val->cpu), 0x0, sizeof(val->cpu));
    }
}

#endif

#endif
