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

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "tprofiling.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(offcpu_m_enter_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} offcpu_enter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(trace_event_data_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} offcpu_stash_map SEC(".maps");

static __always_inline void init_offcpu_event_common(trace_event_data_t *evt_data,
                                                    struct task_struct *task)
{
    evt_data->type = EVT_TYPE_OFFCPU;
    evt_data->pid = BPF_CORE_READ(task, pid);
    evt_data->tgid = BPF_CORE_READ(task, tgid);
    bpf_core_read_str(evt_data->comm, sizeof(evt_data->comm), &task->comm);
}

static __always_inline void init_offcpu_data(offcpu_data_t *offcpu_d, offcpu_m_enter_t *offcpu_enter,
    void *ctx, int ctx_is_prev)
{
    offcpu_d->start_time = offcpu_enter->start_time;
    offcpu_d->end_time = offcpu_enter->end_time;
    offcpu_d->duration = offcpu_enter->end_time - offcpu_enter->start_time;
    offcpu_d->count = 1;
    __builtin_memset(&offcpu_d->stats_stack, 0, sizeof(struct stats_stack_elem));


    if (ctx_is_prev == 0) {
        stats_append_stack(&offcpu_d->stats_stack, 0, ctx);
    } else {
        (void)__builtin_memcpy(&offcpu_d->stats_stack, &offcpu_enter->stats_stack, sizeof(struct stats_stack_elem));
    }
}

static __always_inline trace_event_data_t *create_offcpu_event(offcpu_m_enter_t *offcpu_enter, struct task_struct *task,
    void *ctx, int ctx_is_prev)
{
    trace_event_data_t *evt_data;

    evt_data = new_trace_event();
    if (!evt_data) {
        return NULL;
    }
    init_offcpu_event_common(evt_data, task);
    init_offcpu_data(&evt_data->offcpu_d, offcpu_enter, ctx, ctx_is_prev);

    return evt_data;
}

static __always_inline void emit_incomming_offcpu_event(offcpu_m_enter_t *offcpu_enter, struct task_struct *task,
    void *ctx, int ctx_is_prev)
{
    trace_event_data_t *evt_data = create_offcpu_event(offcpu_enter, task, ctx, ctx_is_prev);
    void *cur_event_map;

    if (!evt_data) {
        return;
    }
    cur_event_map = bpf_get_current_event_map();
    if (cur_event_map) {
        bpfbuf_output(ctx, cur_event_map, evt_data, sizeof(trace_event_data_t));
    }
}

static __always_inline void stash_incomming_offcpu_event(offcpu_m_enter_t *offcpu_enter, struct task_struct *task,
    void *ctx, int ctx_is_prev)
{
    trace_event_data_t *evt_data = create_offcpu_event(offcpu_enter, task, ctx, ctx_is_prev);

    if (!evt_data) {
        return;
    }
    bpf_map_update_elem(&offcpu_stash_map, &offcpu_enter->pid, evt_data, BPF_ANY);
}

static __always_inline void merge_incomming_offcpu_event(trace_event_data_t *evt_data, offcpu_m_enter_t *offcpu_enter)
{
    evt_data->offcpu_d.end_time = offcpu_enter->end_time;
    evt_data->offcpu_d.duration += offcpu_enter->end_time - offcpu_enter->start_time;
    evt_data->offcpu_d.count++;
}

static __always_inline void emit_event_stashed(trace_event_data_t *evt_data, void *ctx)
{
    void *cur_event_map;

    cur_event_map = bpf_get_current_event_map();
    if (cur_event_map) {
        bpfbuf_output(ctx, cur_event_map, evt_data, sizeof(trace_event_data_t));
    }
}

#define CAN_EMIT(aggr_dur, stime, etime) ((etime) >= ((stime) + (aggr_dur)) ? 1 : 0) 
static __always_inline void process_offcpu_event(offcpu_m_enter_t *offcpu_enter, struct task_struct *task,
                                                void *ctx, u64 min_aggr_dur, int ctx_is_prev)
{
    trace_event_data_t *evt_data;
    u32 pid;
    u64 aggr_dur = min_aggr_dur == 0 ? DFT_AGGR_DURATION : min_aggr_dur;

    pid = BPF_CORE_READ(task, pid);
    evt_data = (trace_event_data_t *)bpf_map_lookup_elem(&offcpu_stash_map, &pid);

    if (evt_data != (void *)0) {
        if (CAN_EMIT(aggr_dur, evt_data->offcpu_d.start_time, offcpu_enter->end_time)) {
            emit_event_stashed(evt_data, ctx);
            bpf_map_delete_elem(&offcpu_stash_map, &pid);
        } else {
            merge_incomming_offcpu_event(evt_data, offcpu_enter);
            return;
        }
    }

    if (CAN_EMIT(aggr_dur, offcpu_enter->start_time, offcpu_enter->end_time)) {
        emit_incomming_offcpu_event(offcpu_enter, task, ctx, ctx_is_prev);
    } else {
        stash_incomming_offcpu_event(offcpu_enter, task, ctx, ctx_is_prev);
    }
}

static __always_inline offcpu_m_enter_t *get_offcpu_enter(struct task_struct *task)
{
    u32 pid, tgid;
    pid = BPF_CORE_READ(task, pid);
    tgid = BPF_CORE_READ(task, tgid);

    offcpu_m_enter_t *offcpu_enter;
    offcpu_enter = (offcpu_m_enter_t *)bpf_map_lookup_elem(&offcpu_enter_map, &pid);
    if (offcpu_enter == (void *)0) {
        offcpu_m_enter_t offcpu_enter_tmp;
        if (!is_proc_enabled(tgid) || !is_thrd_enabled(pid, tgid)) {
            return 0;
        }

        __builtin_memset(&offcpu_enter_tmp, 0, sizeof(offcpu_enter_tmp));
        offcpu_enter_tmp.pid = pid;
        (void)bpf_map_update_elem(&offcpu_enter_map, &offcpu_enter_tmp.pid, &offcpu_enter_tmp, BPF_ANY);
        offcpu_enter = (offcpu_m_enter_t *)bpf_map_lookup_elem(&offcpu_enter_map, &pid);
    }

    return offcpu_enter;
}

static __always_inline void process_oncpu(struct task_struct *task, void *ctx, int ctx_is_prev)
{
    offcpu_m_enter_t *offcpu_enter;
    trace_setting_t *setting;

    offcpu_enter = get_offcpu_enter(task);
    if (offcpu_enter == (void *)0) {
        return;
    }

    setting = get_trace_setting();
    if (setting == (void *)0) {
        return;
    }

    offcpu_enter->end_time = bpf_ktime_get_ns();
    if (offcpu_enter->start_time == 0) {
        // This means that the start time of the offcpu event is before the probe is started.
        // Therefore, we set a fake start time because stack data needs to be reported.
        offcpu_enter->start_time = offcpu_enter->end_time - DFT_AGGR_DURATION;
        return;
    }

    if (offcpu_enter->end_time < offcpu_enter->start_time + setting->min_exec_dur) {
        // offcpu time is too short
        return;
    }

    process_offcpu_event(offcpu_enter, task, ctx, setting->min_aggr_dur, ctx_is_prev);
}

static __always_inline void process_offcpu(struct task_struct *task, int ctx_is_prev, void *ctx)
{
    offcpu_m_enter_t *offcpu_enter;

    offcpu_enter = get_offcpu_enter(task);
    if (offcpu_enter == (void *)0) {
        return;
    }

    offcpu_enter->start_time = bpf_ktime_get_ns();

    if (ctx_is_prev == 1 && offcpu_enter != (void *)0) {
        __builtin_memset(&offcpu_enter->stats_stack, 0, sizeof(struct stats_stack_elem));
        stats_append_stack(&offcpu_enter->stats_stack, 0, ctx);
    }
}

KRAWTRACE(sched_switch, bpf_raw_tracepoint_args)
{
    int ctx_is_prev = 1; // ctx is prev
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *current = (struct task_struct *)ctx->args[2];
    process_offcpu(prev, ctx_is_prev, (void *)ctx);
    process_oncpu(current, (void *)ctx, ctx_is_prev);

    return 0;
}

KPROBE(finish_task_switch, pt_regs)
{
    int ctx_is_prev = 0; // ctx is current
    struct task_struct *prev = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    process_offcpu(prev, ctx_is_prev, (void *)ctx);
    process_oncpu(current, (void *)ctx, ctx_is_prev);

    return 0;
}

char g_license[] SEC("license") = "Dual BSD/GPL";