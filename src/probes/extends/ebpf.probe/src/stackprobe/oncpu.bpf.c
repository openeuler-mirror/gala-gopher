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
 * Create: 2022-08-13
 * Description: function stack tracing
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "stack.h"

char g_linsence[] SEC("license") = "GPL";

#ifndef BPF_F_FAST_STACK_CMP
#define BPF_F_FAST_STACK_CMP    (1ULL << 9)
#endif

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK    (1ULL << 8)
#endif

#ifndef BPF_F_INDEX_MASK
#define BPF_F_INDEX_MASK        0xffffffffULL
#endif

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU       BPF_F_INDEX_MASK
#endif

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

/*
  To ensure that BPF continuously collects stack-trace data, BPF provides two data channels (A/B).
  One data channel is used to collect stack-trace data, and the other is used to read stack-trace data in user mode.
  Two data channel periodically alternate roles.
*/

struct bpf_map_def SEC("maps") convert_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),    // const value 0
    .value_size = sizeof(u64),  // convert counter
    .max_entries = 1,
};

/* Data channel A */
struct bpf_map_def SEC("maps") stackmap_a = {
    .type = BPF_MAP_TYPE_STACK_TRACE,
    .key_size = sizeof(u32),
    .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
    .max_entries = PERCPU_SAMPLE_COUNT,
};

struct bpf_map_def SEC("maps") stackmap_perf_a = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = MAX_CPU,
};

/* Data channel B */
struct bpf_map_def SEC("maps") stackmap_b = {
    .type = BPF_MAP_TYPE_STACK_TRACE,
    .key_size = sizeof(u32),
    .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
    .max_entries = PERCPU_SAMPLE_COUNT,
};

struct bpf_map_def SEC("maps") stackmap_perf_b = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = MAX_CPU,
};

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

bpf_section("perf_event")
int function_stack_trace(struct bpf_perf_event_data *ctx)
{
    struct stack_id_s stack_id = {0};
    const u32 zero = 0;
    u64 *convert_count = bpf_map_lookup_elem(&convert_map, &zero);
    if (!convert_count) {
        return -1;
    }

    // Obtains the data channel used to collect stack-trace data.
    char is_stackmap_a = ((*convert_count % 2) == 0);

    stack_id.pid.proc_id = bpf_get_current_pid_tgid() >> INT_LEN;
    if (stack_id.pid.proc_id > 1) {
        struct proc_s obj = {.proc_id = stack_id.pid.proc_id};
        if (!is_proc_exist(&obj)) {
            return 0;
        }
    }
    stack_id.pid.real_start_time = get_real_start_time();
    (void)bpf_get_current_comm(&stack_id.pid.comm, sizeof(stack_id.pid.comm));

    if (is_stackmap_a) {
        stack_id.kern_stack_id = bpf_get_stackid(ctx, &stackmap_a, KERN_STACKID_FLAGS);
        stack_id.user_stack_id = bpf_get_stackid(ctx, &stackmap_a, USER_STACKID_FLAGS);
    } else {
        stack_id.kern_stack_id = bpf_get_stackid(ctx, &stackmap_b, KERN_STACKID_FLAGS);
        stack_id.user_stack_id = bpf_get_stackid(ctx, &stackmap_b, USER_STACKID_FLAGS);
    }

    if (stack_id.kern_stack_id < 0 && stack_id.user_stack_id < 0) {
        // error.
        return -1;
    }

    if (is_stackmap_a) {
        (void)bpf_perf_event_output(ctx, &stackmap_perf_a, BPF_F_CURRENT_CPU, &stack_id, sizeof(stack_id));
    } else {
        (void)bpf_perf_event_output(ctx, &stackmap_perf_b, BPF_F_CURRENT_CPU, &stack_id, sizeof(stack_id));
    }

    return 0;
}

