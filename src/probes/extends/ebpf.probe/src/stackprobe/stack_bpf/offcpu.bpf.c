/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wo_cow
 * Create: 2023-04-10
 * Description: function stack tracing
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "../stack.h"
#include "stackprobe_bpf.h"

char g_linsence[] SEC("license") = "GPL";

#define MAXBLOCK_US ((u64)-1)
#define MINBLOCK_US 1000 // 1000us
#define MAX_START_ENTRIES 1024

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, MAX_CPU);
} stackmap_perf_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, MAX_CPU);
} stackmap_perf_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));   // pid
    __uint(value_size, sizeof(u64)); // offcpu start time(ns)
    __uint(max_entries, MAX_START_ENTRIES);
} start SEC(".maps");

static __always_inline u64 get_real_start_time()
{
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (task) {
        struct task_struct* group_leader = _(task->group_leader);
        if (group_leader) {
#if (CURRENT_KERNEL_VERSION >= KERNEL_VERSION(5, 10, 0))
        return _(group_leader->start_boottime);
#else
        return _(group_leader->real_start_time);
#endif
        }
    }
    return 0;
}

KRAWTRACE(sched_switch, bpf_raw_tracepoint_args)
{
    const u32 zero = 0;
    struct convert_data_t *convert_data = (struct convert_data_t *)bpf_map_lookup_elem(&convert_map, &zero);
    if (!convert_data) {
        return -1;
    }

    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    if (!prev || !next) {
        return 0;
    }

    u32 prev_tgid = _(prev->tgid);
    u32 curr_pid = _(next->pid);
    if (prev_tgid <= 1 || curr_pid <= 1) {
        return 0;
    }

    int filter = 0;
    if (!convert_data->whitelist_enable) {
        filter = 1;
    } else {
        struct proc_s obj = {.proc_id = prev_tgid};
        if (is_proc_exist(&obj)) {
            filter = 1;
        }
    }

    if (filter) {
        u64 prev_ts = bpf_ktime_get_ns();
        u32 prev_pid = _(prev->pid);
        bpf_map_update_elem(&start, &prev_pid, &prev_ts, BPF_ANY);
    }

    u64 *t_start = (u64 *)bpf_map_lookup_elem(&start, &curr_pid);
    if (!t_start) {
        return 0;
    }
    bpf_map_delete_elem(&start, &curr_pid);

    u64 t_end = bpf_ktime_get_ns();
    if (*t_start > t_end) {
        return 0;
    }

    u64 delta_us = (t_end - *t_start) / 1000;
    // TODO: MINBLOCK_US and MAXBLOCK_US configurable
    if ((delta_us < MINBLOCK_US) || (delta_us > MAXBLOCK_US)) { 
        return 0;
    }

    struct raw_trace_s raw_trace = {.count = delta_us};
    raw_trace.stack_id.pid.proc_id = _(next->tgid);
    raw_trace.stack_id.pid.real_start_time = get_real_start_time();
    (void)bpf_get_current_comm(&raw_trace.stack_id.comm, sizeof(raw_trace.stack_id.comm));
    char is_stackmap_a = ((convert_data->convert_counter % 2) == 0);
    if (is_stackmap_a) {
        raw_trace.stack_id.kern_stack_id = bpf_get_stackid(ctx, &stackmap_a, KERN_STACKID_FLAGS);
        raw_trace.stack_id.user_stack_id = bpf_get_stackid(ctx, &stackmap_a, USER_STACKID_FLAGS);
    } else {
        raw_trace.stack_id.kern_stack_id = bpf_get_stackid(ctx, &stackmap_b, KERN_STACKID_FLAGS);
        raw_trace.stack_id.user_stack_id = bpf_get_stackid(ctx, &stackmap_b, USER_STACKID_FLAGS);
    }
    if (raw_trace.stack_id.kern_stack_id < 0 && raw_trace.stack_id.user_stack_id < 0) {
        return -1;
    }

    if (is_stackmap_a) {
        (void)bpf_perf_event_output(ctx, &stackmap_perf_a, BPF_F_CURRENT_CPU, &raw_trace, sizeof(raw_trace));
    } else {
        (void)bpf_perf_event_output(ctx, &stackmap_perf_b, BPF_F_CURRENT_CPU, &raw_trace, sizeof(raw_trace));
    }

    return 0;

}

