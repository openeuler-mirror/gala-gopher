/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: algorithmofdish
 * Create: 2023-04-03
 * Description: the bpf-side prog of thread profiling probe
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "tprofiling.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(oncpu_m_enter_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} oncpu_enter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(trace_event_data_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} oncpu_stash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(trace_event_data_t));
    __uint(max_entries, 1);
} oncpu_stash_heap SEC(".maps");

static __always_inline trace_event_data_t *new_oncpu_trace_event()
{
    u32 zero = 0;
    trace_event_data_t *evt;

    evt = (trace_event_data_t *)bpf_map_lookup_elem(&oncpu_stash_heap, &zero);
    return evt;
}

static __always_inline void init_oncpu_event_common(trace_event_data_t *evt_data,
                                                    struct task_struct *task)
{
    evt_data->type = EVT_TYPE_ONCPU;
    evt_data->pid = BPF_CORE_READ(task, pid);
    evt_data->tgid = BPF_CORE_READ(task, tgid);
    bpf_core_read_str(evt_data->comm, sizeof(evt_data->comm), &task->comm);
}

static __always_inline void init_oncpu_data(oncpu_data_t *oncpu_d, oncpu_m_enter_t *oncpu_enter)
{
    oncpu_d->start_time = oncpu_enter->start_time;
    oncpu_d->end_time = oncpu_enter->end_time;
    oncpu_d->duration = oncpu_enter->end_time - oncpu_enter->start_time;
    oncpu_d->count = 1;
}

static __always_inline trace_event_data_t *create_oncpu_event(oncpu_m_enter_t *oncpu_enter, struct task_struct *task)
{
    trace_event_data_t *evt_data;

    evt_data = new_oncpu_trace_event();
    if (!evt_data) {
        return NULL;
    }
    init_oncpu_event_common(evt_data, task);
    init_oncpu_data(&evt_data->oncpu_d, oncpu_enter);

    return evt_data;
}

static __always_inline void emit_incomming_oncpu_event(oncpu_m_enter_t *oncpu_enter, struct task_struct *task,
    void *ctx)
{
    trace_event_data_t *evt_data = create_oncpu_event(oncpu_enter, task);

    if (!evt_data) {
        return;
    }
    bpfbuf_output(ctx, &event_map, evt_data, sizeof(trace_event_data_t));
}

static __always_inline void emit_oncpu_event_stashed(trace_event_data_t *evt_data, void *ctx)
{
    bpfbuf_output(ctx, &event_map, evt_data, sizeof(trace_event_data_t));
}

static __always_inline void stash_incomming_oncpu_event(oncpu_m_enter_t *oncpu_enter, struct task_struct *task)
{
    trace_event_data_t *evt_data = create_oncpu_event(oncpu_enter, task);

    if (!evt_data) {
        return;
    }
    bpf_map_update_elem(&oncpu_stash_map, &oncpu_enter->pid, evt_data, BPF_ANY);
}

static __always_inline void merge_incomming_oncpu_event(trace_event_data_t *evt_data, oncpu_m_enter_t *oncpu_enter)
{
    evt_data->oncpu_d.end_time = oncpu_enter->end_time;
    evt_data->oncpu_d.duration += oncpu_enter->end_time - oncpu_enter->start_time;
    evt_data->oncpu_d.count++;
}

static __always_inline void process_oncpu_event(oncpu_m_enter_t *oncpu_enter, struct task_struct *task,
                                                void *ctx)
{
    trace_event_data_t *evt_data;
    u32 pid;

    pid = BPF_CORE_READ(task, pid);
    evt_data = (trace_event_data_t *)bpf_map_lookup_elem(&oncpu_stash_map, &pid);

    if (evt_data == (void *)0) {
        if (can_emit(oncpu_enter->start_time, oncpu_enter->end_time)) {
            emit_incomming_oncpu_event(oncpu_enter, task, ctx);
        } else {
            stash_incomming_oncpu_event(oncpu_enter, task);
        }
        return;
    }

    if (can_emit(evt_data->oncpu_d.start_time, oncpu_enter->end_time)) {
        emit_oncpu_event_stashed(evt_data, ctx);
        bpf_map_delete_elem(&oncpu_stash_map, &pid);

        if (can_emit(oncpu_enter->start_time, oncpu_enter->end_time)) {
            emit_incomming_oncpu_event(oncpu_enter, task, ctx);
        } else {
            stash_incomming_oncpu_event(oncpu_enter, task);
        }
    } else {
        merge_incomming_oncpu_event(evt_data, oncpu_enter);
    }
}

static __always_inline void process_oncpu(struct task_struct *task)
{
    u32 pid, tgid;
    oncpu_m_enter_t oncpu_enter;

    pid = BPF_CORE_READ(task, pid);
    tgid = BPF_CORE_READ(task, tgid);
    if (!is_proc_enabled(tgid) || !is_thrd_enabled(pid, tgid)) {
        return;
    }

    __builtin_memset(&oncpu_enter, 0, sizeof(oncpu_enter));
    oncpu_enter.pid = pid;
    oncpu_enter.start_time = bpf_ktime_get_ns();
    (void)bpf_map_update_elem(&oncpu_enter_map, &oncpu_enter.pid, &oncpu_enter, BPF_ANY);
}

static __always_inline void process_offcpu(struct task_struct *task, void *ctx)
{
    u32 pid = BPF_CORE_READ(task, pid);
    oncpu_m_enter_t *oncpu_enter;

    oncpu_enter = (oncpu_m_enter_t *)bpf_map_lookup_elem(&oncpu_enter_map, &pid);
    if (oncpu_enter == (void *)0) {
        return;
    }
    oncpu_enter->end_time = bpf_ktime_get_ns();
    if (oncpu_enter->end_time < oncpu_enter->start_time + MIN_EXEC_DURATION) {
        (void)bpf_map_delete_elem(&oncpu_enter_map, &pid);
        return;
    }

    process_oncpu_event(oncpu_enter, task, ctx);

    (void)bpf_map_delete_elem(&oncpu_enter_map, &pid);
}

KRAWTRACE(sched_switch, bpf_raw_tracepoint_args)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *current = (struct task_struct *)ctx->args[2];
    process_offcpu(prev, (void *)ctx);
    process_oncpu(current);

    return 0;
}

KPROBE(finish_task_switch, pt_regs)
{
    struct task_struct *prev = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    process_offcpu(prev, (void *)ctx);
    process_oncpu(current);

    return 0;
}

char g_license[] SEC("license") = "Dual BSD/GPL";