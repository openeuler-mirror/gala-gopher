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

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif
#define BPF_PROG_USER
#include "bpf.h"
#include "tprofiling.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(pygc_m_enter_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} pygc_enter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(trace_event_data_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} pygc_stash_map SEC(".maps");

static __always_inline void init_pygc_data(pygc_data_t *pygc_d, pygc_m_enter_t *pygc_enter, char is_stat, void *ctx)
{
    pygc_d->start_time = pygc_enter->start_time;
    pygc_d->end_time = pygc_enter->end_time;
    pygc_d->duration = pygc_enter->end_time - pygc_enter->start_time;
    pygc_d->count = 1;
    __builtin_memset(&pygc_d->stats_stack, 0, sizeof(struct stats_stack_elem));
    if (is_stat) {
        stats_append_stack(&pygc_d->stats_stack, pygc_d->duration, ctx);
    }
}

static __always_inline trace_event_data_t *create_pygc_event(pygc_m_enter_t *pygc_enter, char is_stat, void *ctx)
{
    trace_event_data_t *evt_data;

    evt_data = new_trace_event();
    if (!evt_data) {
        return NULL;
    }
    init_trace_event_common(evt_data, EVT_TYPE_PYGC);
    init_pygc_data(&evt_data->pygc_d, pygc_enter, is_stat, ctx);

    return evt_data;
}

static __always_inline void emit_incomming_pygc_event(pygc_m_enter_t *pygc_enter, void *ctx)
{
    trace_event_data_t *evt_data = create_pygc_event(pygc_enter, 1, ctx);
    void *cur_event_map;

    if (!evt_data) {
        return;
    }
    cur_event_map = bpf_get_current_event_map();
    if (cur_event_map) {
        bpfbuf_output(ctx, cur_event_map, evt_data, sizeof(trace_event_data_t));
    }
}

static __always_inline void emit_pygc_event_stashed(trace_event_data_t *evt_data, void *ctx)
{
    void *cur_event_map;

    cur_event_map = bpf_get_current_event_map();
    if (cur_event_map) {
        bpfbuf_output(ctx, cur_event_map, evt_data, sizeof(trace_event_data_t));
    }
}

static __always_inline void stash_incomming_pygc_event(pygc_m_enter_t *pygc_enter, void *ctx)
{
    trace_event_data_t *evt_data = create_pygc_event(pygc_enter, 0, ctx);

    if (!evt_data) {
        return;
    }
    bpf_map_update_elem(&pygc_stash_map, &pygc_enter->pid, evt_data, BPF_ANY);
}

static __always_inline void merge_incomming_pygc_event(trace_event_data_t *evt_data, pygc_m_enter_t *pygc_enter)
{
    evt_data->pygc_d.end_time = pygc_enter->end_time;
    evt_data->pygc_d.duration += pygc_enter->end_time - pygc_enter->start_time;
    evt_data->pygc_d.count++;
}

static __always_inline void process_pygc_event(pygc_m_enter_t *pygc_enter, void *ctx)
{
    trace_event_data_t *evt_data;

    evt_data = (trace_event_data_t *)bpf_map_lookup_elem(&pygc_stash_map, &pygc_enter->pid);

    if (evt_data == (void *)0) {
        if (can_emit(pygc_enter->start_time, pygc_enter->end_time)) {
            emit_incomming_pygc_event(pygc_enter, ctx);
        } else {
            stash_incomming_pygc_event(pygc_enter, ctx);
        }
        return;
    }

    if (can_emit(evt_data->pygc_d.start_time, pygc_enter->end_time)) {
        emit_pygc_event_stashed(evt_data, ctx);
        bpf_map_delete_elem(&pygc_stash_map, &pygc_enter->pid);

        if (can_emit(pygc_enter->start_time, pygc_enter->end_time)) {
            emit_incomming_pygc_event(pygc_enter, ctx);
        } else {
            stash_incomming_pygc_event(pygc_enter, ctx);
        }
    } else {
        merge_incomming_pygc_event(evt_data, pygc_enter);
    }
}

UPROBE(collect_with_callback, pt_regs)
{
    pygc_m_enter_t pygc_enter;
    u64 ptid = bpf_get_current_pid_tgid();

    // maybe delete?
    if (!is_proc_thrd_enabled()) {
        return 0;
    }

    __builtin_memset(&pygc_enter, 0, sizeof(pygc_enter));
    pygc_enter.pid = (u32)ptid;
    pygc_enter.start_time = bpf_ktime_get_ns();
    (void)bpf_map_update_elem(&pygc_enter_map, &pygc_enter.pid, &pygc_enter, BPF_ANY);
    return 0;
}

URETPROBE(collect_with_callback, pt_regs)
{
    pygc_m_enter_t *pygc_enter;
    u32 pid = bpf_get_current_pid_tgid();
    trace_setting_t *setting;

    pygc_enter = (pygc_m_enter_t *)bpf_map_lookup_elem(&pygc_enter_map, &pid);
    if (!pygc_enter) {
        return 0;
    }
    setting = get_trace_setting();
    if (!setting) {
        goto out;
    }
    pygc_enter->end_time = bpf_ktime_get_ns();
    if (pygc_enter->end_time < pygc_enter->start_time + setting->min_exec_dur) {
        goto out;
    }
    process_pygc_event(pygc_enter, ctx);
out:
    (void)bpf_map_delete_elem(&pygc_enter_map, &pid);
    return 0;
}

char g_license[] SEC("license") = "Dual BSD/GPL";