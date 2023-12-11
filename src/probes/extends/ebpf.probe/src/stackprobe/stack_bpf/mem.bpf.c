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
 * Create: 2023-06-01
 * Description: stack tracing based on page fault
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "../stack.h"
#include "stackprobe_bpf.h"
#include "py_stack_bpf.h"

char g_linsence[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} stackmap_perf_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} stackmap_perf_b SEC(".maps");


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

struct page_fault_args {
    unsigned long address;
    unsigned long ip;
    unsigned long error_code;
};

static __always_inline struct py_raw_trace_s *get_py_raw_trace(struct raw_trace_s *raw_trace)
{
    struct py_proc_data *py_proc_data;
    struct py_sample *py_sample;

    py_proc_data = (struct py_proc_data *)bpf_map_lookup_elem(&py_proc_map, &raw_trace->stack_id.pid.proc_id);
    if (!py_proc_data) {
        return 0;
    }
    py_sample = get_py_sample();
    if (!py_sample) {
        return 0;
    }

    py_sample->cpu_id = bpf_get_smp_processor_id();
    if (get_py_stack(py_sample, py_proc_data)) {
        return 0;
    }
    __builtin_memcpy(&py_sample->event.raw_trace, raw_trace, sizeof(struct raw_trace_s));
    py_sample->event.raw_trace.lang_type = TRACE_LANG_TYPE_PYTHON;

    return &py_sample->event;
}

static __always_inline int report_stack(struct page_fault_args *ctx)
{
    struct raw_trace_s raw_trace = {.count = 1};
    const u32 zero = 0;
    struct convert_data_t *convert_data = (struct convert_data_t *)bpf_map_lookup_elem(&convert_map, &zero);
    struct py_raw_trace_s *py_trace;

    if (!convert_data) {
        return -1;
    }

    // Obtains the data channel used to collect stack-trace data.
    char is_stackmap_a = ((convert_data->convert_counter % 2) == 0);

    raw_trace.stack_id.pid.proc_id = bpf_get_current_pid_tgid() >> INT_LEN;
    struct proc_s obj = {.proc_id = raw_trace.stack_id.pid.proc_id};
    if (!is_proc_exist(&obj)) {
        return 0;
    }
    raw_trace.stack_id.pid.real_start_time = get_real_start_time();

    // test found that the comm is thread command
    (void)bpf_get_current_comm(&raw_trace.stack_id.comm, sizeof(raw_trace.stack_id.comm));
    raw_trace.lang_type = TRACE_LANG_TYPE_DEFAULT;

    if (is_stackmap_a) {
        raw_trace.stack_id.kern_stack_id = bpf_get_stackid(ctx, &stackmap_a, KERN_STACKID_FLAGS);
        raw_trace.stack_id.user_stack_id = bpf_get_stackid(ctx, &stackmap_a, USER_STACKID_FLAGS);
    } else {
        raw_trace.stack_id.kern_stack_id = bpf_get_stackid(ctx, &stackmap_b, KERN_STACKID_FLAGS);
        raw_trace.stack_id.user_stack_id = bpf_get_stackid(ctx, &stackmap_b, USER_STACKID_FLAGS);
    }
    if (raw_trace.stack_id.kern_stack_id < 0 && raw_trace.stack_id.user_stack_id < 0) {
        // error.
        return -1;
    }

    py_trace = get_py_raw_trace(&raw_trace);
    if (py_trace) {
        if (is_stackmap_a) {
            (void)bpfbuf_output(ctx, &stackmap_perf_a, py_trace, sizeof(struct py_raw_trace_s));
        } else {
            (void)bpfbuf_output(ctx, &stackmap_perf_b, py_trace, sizeof(struct py_raw_trace_s));
        }
        return 0;
    }

    if (is_stackmap_a) {
        (void)bpfbuf_output(ctx, &stackmap_perf_a, &raw_trace, sizeof(raw_trace));
    } else {
        (void)bpfbuf_output(ctx, &stackmap_perf_b, &raw_trace, sizeof(raw_trace));
    }

    return 0;
}

bpf_section("tracepoint/exceptions/page_fault_user")
int tracepoint_page_fault_user(struct page_fault_args *ctx)
{
    return report_stack(ctx);
}

bpf_section("tracepoint/exceptions/page_fault_kernel")
int tracepoint_page_fault_kernel(struct page_fault_args *ctx)
{
    return report_stack(ctx);
}
