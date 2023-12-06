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

#define MAXBLOCK_MS ((u64)-1)
#define MINBLOCK_MS 1 // 1ms
#define MAX_START_ENTRIES 1024

struct start_info_t {
    u32 tgid;
    u64 ts; // offcpu start time(ns)
    struct raw_trace_s raw_trace;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} stackmap_perf_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} stackmap_perf_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));   // pid
    __uint(value_size, sizeof(struct start_info_t));
    __uint(max_entries, MAX_START_ENTRIES);
} start SEC(".maps");

static __always_inline u64 get_real_start_time()
{
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (task) {
        struct task_struct* group_leader = _(task->group_leader);
        if (group_leader) {
            if (bpf_core_field_exists(((struct task_struct *)0)->start_boottime)) {
                return _(group_leader->start_boottime);
            }
            if (bpf_core_field_exists(((struct task_struct *)0)->real_start_time)) {
                return _(group_leader->real_start_time);
            }
        }
    }
    return 0;
}

KRAWTRACE(sched_switch, bpf_raw_tracepoint_args)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    if (!prev || !next) {
        return 0;
    }

    u32 prev_pid = _(prev->pid);
    u32 next_pid = _(next->pid);
    if (next_pid <= 1 || prev_pid <= 1) {
        return 0;
    }

    const u32 zero = 0;
    struct convert_data_t *convert_data = (struct convert_data_t *)bpf_map_lookup_elem(&convert_map, &zero);
    if (!convert_data) {
        return -1;
    }

    u32 prev_tgid = _(prev->tgid);

    int filter = 0;
    struct proc_s obj = {.proc_id = prev_tgid};
    if (is_proc_exist(&obj)) {
        filter = 1;
    }
    u64 t_end = bpf_ktime_get_ns();
    if (filter) {
        struct start_info_t prev_info = {0};
        prev_info.tgid = prev_tgid;
        prev_info.ts = t_end;
        struct stack_id_s *stack_id = &prev_info.raw_trace.stack_id;
        stack_id->pid.proc_id = prev_tgid;
        stack_id->pid.real_start_time = get_real_start_time();
        (void)bpf_get_current_comm(&stack_id->comm, sizeof(stack_id->comm));
        if (((convert_data->convert_counter % 2) == 0)) { // % 2 代表对stackmap_a和stackmap_b的选择
            stack_id->kern_stack_id = bpf_get_stackid(ctx, &stackmap_a, KERN_STACKID_FLAGS);
            stack_id->user_stack_id = bpf_get_stackid(ctx, &stackmap_a, USER_STACKID_FLAGS);
        } else {
            stack_id->kern_stack_id = bpf_get_stackid(ctx, &stackmap_b, KERN_STACKID_FLAGS);
            stack_id->user_stack_id = bpf_get_stackid(ctx, &stackmap_b, USER_STACKID_FLAGS);
        }
        if (stack_id->kern_stack_id < 0 && stack_id->user_stack_id < 0) {
            return -1;
        }
        bpf_map_update_elem(&start, &prev_pid, &prev_info, BPF_ANY);
    }

    struct start_info_t *next_info = (struct start_info_t *)bpf_map_lookup_elem(&start, &next_pid);
    if (!next_info) {
        return 0;
    }

    u64 t_start = next_info->ts;
    if (t_start > t_end) {
        goto out;
    }

    u64 delta_ms = (t_end - t_start) / 1000000; // 1000000ns = 1ms
    // TODO: MINBLOCK_MS and MAXBLOCK_MS configurable
    if ((delta_ms < MINBLOCK_MS) || (delta_ms > MAXBLOCK_MS)) { 
        goto out;
    }

    struct raw_trace_s *next_raw_trace = &next_info->raw_trace;
    next_raw_trace->count = delta_ms;
    if (((convert_data->convert_counter % 2) == 0)) { // % 2 代表对stackmap_a和stackmap_b的选择
        (void)bpfbuf_output(ctx, &stackmap_perf_a, next_raw_trace,
            sizeof(struct raw_trace_s));
    } else {
        (void)bpfbuf_output(ctx, &stackmap_perf_b, next_raw_trace,
            sizeof(struct raw_trace_s));
    }

out:
    bpf_map_delete_elem(&start, &next_pid);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int bpf_trace_sched_switch_func(struct trace_event_raw_sched_switch *ctx)
{
    u32 prev_pid = (u32)ctx->prev_pid;
    u32 next_pid = (u32)ctx->next_pid;
    if (next_pid <= 1 || prev_pid <= 1) {
        return 0;
    }

    const u32 zero = 0;
    struct convert_data_t *convert_data = (struct convert_data_t *)bpf_map_lookup_elem(&convert_map, &zero);
    if (!convert_data) {
        return -1;
    }

    u32 prev_tgid = bpf_get_current_pid_tgid() >> INT_LEN;

    int filter = 0;
    struct proc_s obj = {.proc_id = prev_tgid};
    if (is_proc_exist(&obj)) {
        filter = 1;
    }
    u64 t_end = bpf_ktime_get_ns();
    if (filter) {
        struct start_info_t prev_info = {0};
        prev_info.tgid = prev_tgid;
        prev_info.ts = t_end;
        struct stack_id_s *stack_id = &prev_info.raw_trace.stack_id;
        stack_id->pid.proc_id = prev_tgid;
        stack_id->pid.real_start_time = get_real_start_time();
        (void)bpf_get_current_comm(&stack_id->comm, sizeof(stack_id->comm));
        if (((convert_data->convert_counter % 2) == 0)) { // % 2 代表对stackmap_a和stackmap_b的选择
            stack_id->kern_stack_id = bpf_get_stackid(ctx, &stackmap_a, KERN_STACKID_FLAGS);
            stack_id->user_stack_id = bpf_get_stackid(ctx, &stackmap_a, USER_STACKID_FLAGS);
        } else {
            stack_id->kern_stack_id = bpf_get_stackid(ctx, &stackmap_b, KERN_STACKID_FLAGS);
            stack_id->user_stack_id = bpf_get_stackid(ctx, &stackmap_b, USER_STACKID_FLAGS);
        }
        if (stack_id->kern_stack_id < 0 && stack_id->user_stack_id < 0) {
            return -1;
        }
        bpf_map_update_elem(&start, &prev_pid, &prev_info, BPF_ANY);
    }

    struct start_info_t *next_info = (struct start_info_t *)bpf_map_lookup_elem(&start, &next_pid);
    if (!next_info) {
        return 0;
    }

    u64 t_start = next_info->ts;
    if (t_start > t_end) {
        goto out;
    }

    u64 delta_ms = (t_end - t_start) / 1000000; // 1000000ns = 1ms
    // TODO: MINBLOCK_MS and MAXBLOCK_MS configurable
    if ((delta_ms < MINBLOCK_MS) || (delta_ms > MAXBLOCK_MS)) { 
        goto out;
    }

    struct raw_trace_s *next_raw_trace = &next_info->raw_trace;
    next_raw_trace->count = delta_ms;
    if (((convert_data->convert_counter % 2) == 0)) { // % 2 代表对stackmap_a和stackmap_b的选择
        (void)bpfbuf_output(ctx, &stackmap_perf_a, next_raw_trace,
            sizeof(struct raw_trace_s));
    } else {
        (void)bpfbuf_output(ctx, &stackmap_perf_b, next_raw_trace,
            sizeof(struct raw_trace_s));
    }

out:
    bpf_map_delete_elem(&start, &next_pid);
    return 0;
}
