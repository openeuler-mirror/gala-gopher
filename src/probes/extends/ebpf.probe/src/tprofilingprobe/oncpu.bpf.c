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
    __uint(value_size, sizeof(oncpu_data_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} oncpu_stash_map SEC(".maps");

static __always_inline void init_oncpu_event_common(trace_event_data_t *evt_data, u64 timestamp,
                                                    struct task_struct *task)
{
    evt_data->type = EVT_TYPE_ONCPU;
    evt_data->timestamp = timestamp;
    evt_data->pid = _(task->pid);
    evt_data->tgid = _(task->tgid);
    bpf_probe_read_str(evt_data->comm, sizeof(evt_data->comm), task->comm);
}

static __always_inline void emit_incomming_oncpu_event(oncpu_m_enter_t *oncpu_enter, struct task_struct *task,
                                                       struct pt_regs *ctx)
{
    trace_event_data_t evt_data = {0};

    init_oncpu_event_common(&evt_data, oncpu_enter->start_time, task);

    evt_data.oncpu_d.start_time = oncpu_enter->start_time;
    evt_data.oncpu_d.end_time = oncpu_enter->end_time;
    evt_data.oncpu_d.duration = oncpu_enter->end_time - oncpu_enter->start_time;
    evt_data.oncpu_d.count = 1;

    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &evt_data, sizeof(evt_data));
}

static __always_inline void emit_oncpu_event_stashed(oncpu_data_t *oncpu_stash, struct task_struct *task,
                                                     struct pt_regs *ctx)
{
    trace_event_data_t evt_data = {0};

    init_oncpu_event_common(&evt_data, oncpu_stash->start_time, task);
    evt_data.oncpu_d = *oncpu_stash;

    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &evt_data, sizeof(evt_data));
}

static __always_inline void stash_incomming_oncpu_event(oncpu_m_enter_t *oncpu_enter, struct task_struct *task,
                                                        struct pt_regs *ctx)
{
    oncpu_data_t oncpu_d = {0};
    
    oncpu_d.start_time = oncpu_enter->start_time;
    oncpu_d.end_time = oncpu_enter->end_time;
    oncpu_d.duration = oncpu_d.end_time - oncpu_d.start_time;
    oncpu_d.count = 1;

    bpf_map_update_elem(&oncpu_stash_map, &oncpu_enter->pid, &oncpu_d, BPF_ANY);
}

static __always_inline void process_oncpu_event(oncpu_m_enter_t *oncpu_enter, struct task_struct *task,
                                                struct pt_regs *ctx)
{
    oncpu_data_t *oncpu_stash;
    u32 pid;

    pid = _(task->pid);
    oncpu_stash = (oncpu_data_t *)bpf_map_lookup_elem(&oncpu_stash_map, &pid);

    if (oncpu_stash == (void *)0) {
        if (can_emit(oncpu_enter->start_time, oncpu_enter->end_time)) {
            emit_incomming_oncpu_event(oncpu_enter, task, ctx);
        } else {
            stash_incomming_oncpu_event(oncpu_enter, task, ctx);
        }
        return;
    }

    if (can_emit(oncpu_stash->start_time, oncpu_enter->end_time)) {
        emit_oncpu_event_stashed(oncpu_stash, task, ctx);
        bpf_map_delete_elem(&oncpu_stash_map, &pid);

        if (can_emit(oncpu_enter->start_time, oncpu_enter->end_time)) {
            emit_incomming_oncpu_event(oncpu_enter, task, ctx);
        } else {
            stash_incomming_oncpu_event(oncpu_enter, task, ctx);
        }
    } else {
        // merge event
        oncpu_stash->end_time = oncpu_enter->end_time;
        oncpu_stash->count++;
        oncpu_stash->duration += oncpu_enter->end_time - oncpu_enter->start_time;
    }
}

static __always_inline void process_oncpu(struct task_struct *task, profiling_setting_t *setting)
{
    u32 pid, tgid;
    oncpu_m_enter_t oncpu_enter;

    pid = _(task->pid);
    tgid = _(task->tgid);
    if (!is_proc_enabled(tgid, setting) || !is_thrd_enabled(pid, tgid)) {
        return;
    }

    __builtin_memset(&oncpu_enter, 0, sizeof(oncpu_enter));
    oncpu_enter.pid = pid;
    oncpu_enter.start_time = bpf_ktime_get_ns();
    (void)bpf_map_update_elem(&oncpu_enter_map, &oncpu_enter.pid, &oncpu_enter, BPF_ANY);
}

static __always_inline void process_offcpu(struct task_struct *task, struct pt_regs *ctx)
{
    u32 pid = _(task->pid);
    oncpu_m_enter_t *oncpu_enter;

    oncpu_enter = (oncpu_m_enter_t *)bpf_map_lookup_elem(&oncpu_enter_map, &pid);
    if (oncpu_enter == (void *)0) {
        return;
    }
    oncpu_enter->end_time = bpf_ktime_get_ns();
    if (oncpu_enter->end_time < oncpu_enter->start_time + NSEC_PER_MSEC) {
        (void)bpf_map_delete_elem(&oncpu_enter_map, &pid);
        return;
    }

    process_oncpu_event(oncpu_enter, task, ctx);

    (void)bpf_map_delete_elem(&oncpu_enter_map, &pid);
}

KPROBE(finish_task_switch, pt_regs)
{
    struct task_struct *prev = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    profiling_setting_t *setting;

    setting = get_tp_setting();
    if (setting == (void *)0) {
        return 0;
    }

    process_offcpu(prev, ctx);
    process_oncpu(current, setting);

    return 0;
}

char g_license[] SEC("license") = "Dual BSD/GPL";