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

#ifndef __PY_STACK_BPF_H__
#define __PY_STACK_BPF_H__

#define BPF_PROG_KERN

#pragma once
#include "py_stack_bpf_comm.h"
#include "stack.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct py_sample));
    __uint(max_entries, 1);
} py_sample_heap SEC(".maps");

static __always_inline u64 get_py_symbol_id(struct py_symbol *sym, struct py_sample *sample)
{
    u64 *sym_id_ptr;
    u64 sym_id;

    sym_id_ptr = bpf_map_lookup_elem(&py_symbols, sym);
    if (sym_id_ptr) {
        return *sym_id_ptr;
    }

    sym_id = sample->py_symbol_counter * sample->nr_cpus + sample->cpu_id;
    sample->py_symbol_counter++;
    bpf_map_update_elem(&py_symbols, sym, &sym_id, BPF_ANY);
    bpf_map_update_elem(&py_symbol_ids, &sym_id, sym, BPF_ANY);
    return sym_id;
}

static __always_inline int get_py_stack(struct py_sample *py_sample, struct py_proc_data *py_proc_data)
{
    struct py_raw_trace_s *py_event = &py_sample->event;
    void *py_runtime = (void *)py_proc_data->py_runtime_addr;
    void *py_state = (void *)0;
    void *py_frame = (void *)0;
    struct py_symbol py_sym;
    u64 sym_id;
    int ret;

    ret = bpf_probe_read_user(&py_state, sizeof(void *), py_runtime + py_proc_data->offsets.tstate_curr);
    if (ret < 0) {
        return -1;
    }
    ret = bpf_probe_read_user(&py_frame, sizeof(void *), py_state + py_proc_data->offsets.state.frame);
    if (ret < 0) {
        return -1;
    }

    py_event->py_stack.stack_len = 0;
#pragma unroll
    for (int i = 0; i < MAX_PYTHON_STACK_DEPTH_16; i++) {
        // TODO: consider stack truncation scene
        __builtin_memset(&py_sym, 0, sizeof(py_sym));
        ret = get_py_frame_info(&py_sym, &py_frame, &py_proc_data->offsets);
        if (ret) {
            break;
        }
        sym_id = get_py_symbol_id(&py_sym, py_sample);
        py_event->py_stack.stack[py_event->py_stack.stack_len & (MAX_PYTHON_STACK_DEPTH_MAX - 1)] = sym_id;
        py_event->py_stack.stack_len++;
    }

    return 0;
}

static __always_inline struct py_sample *get_py_sample()
{
    u32 zero = 0;

    return (struct py_sample *)bpf_map_lookup_elem(&py_sample_heap, &zero);
}

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

#endif
