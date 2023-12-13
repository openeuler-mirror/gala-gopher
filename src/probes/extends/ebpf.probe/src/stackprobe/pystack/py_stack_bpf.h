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
 * Author: algorithmofdish
 * Create: 2023-11-16
 * Description: python stack bpf header
 ******************************************************************************/
#ifndef __PY_STACK_BPF_H__
#define __PY_STACK_BPF_H__

#pragma once
#include "bpf.h"
#include "py_stack.h"
#include "../stack.h"

#define __MAX_PY_SYMBOLS_NUM 10000

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct py_proc_data));
    __uint(max_entries, MAX_PYTHON_PROG_NUM);
} py_proc_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct py_symbol));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, __MAX_PY_SYMBOLS_NUM);
} py_symbols SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct py_symbol));
    __uint(max_entries, __MAX_PY_SYMBOLS_NUM);
} py_symbol_ids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct py_sample));
    __uint(max_entries, 1);
} py_sample_heap SEC(".maps");

static __always_inline void check_py_func_first_arg(void *py_code, struct py_offset *offsets,
    char *is_self, char *is_cls)
{
    void *first_arg = (void *)0;
    char first_arg_name[5] = {0};
    char self[4] = {'s', 'e', 'l', 'f'};
    char cls[4] = {'c', 'l', 's', '\0'};

    bpf_probe_read_user(&first_arg, sizeof(void *), py_code + offsets->code_obj.co_varnames);
    bpf_probe_read_user(&first_arg, sizeof(void *), first_arg + offsets->obj.tuple_obj_item);
    bpf_probe_read_user_str(&first_arg_name, sizeof(first_arg_name), first_arg + offsets->obj.string_data);

    if (*(u32 *)self == *(u32 *)first_arg_name && first_arg_name[4] == '\0') {
        *is_self = 1;
    } else if (*(u32 *)cls == *(u32 *)first_arg_name) {
        *is_cls = 1;
    }
}

static __always_inline int get_py_symbol_info(struct py_symbol *py_sym, void *py_frame,
    void *py_code, struct py_offset *offsets)
{
    void *ptr = (void *)0;
    char is_first_self = 0;
    char is_first_cls = 0;

    check_py_func_first_arg(py_code, offsets, &is_first_self, &is_first_cls);
    if (is_first_self || is_first_cls) {
        bpf_probe_read_user(&ptr, sizeof(void *), py_frame + offsets->frame_obj.f_localsplus);
        if (is_first_self) {
            bpf_probe_read_user(&ptr, sizeof(void *), ptr + offsets->obj.obj_type);
        }
        bpf_probe_read_user(&ptr, sizeof(void *), ptr + offsets->obj.type_obj_name);
        bpf_probe_read_user_str(&py_sym->class_name, sizeof(py_sym->class_name), ptr);
    }

    ptr = (void *)0;
    bpf_probe_read_user(&ptr, sizeof(void *), py_code + offsets->code_obj.co_name);
    bpf_probe_read_user_str(&py_sym->func_name, sizeof(py_sym->func_name), ptr + offsets->obj.string_data);
    return 0;
}

static __always_inline int get_py_frame_info(struct py_symbol *py_sym, void **py_frame_ptr,
    struct py_offset *offsets)
{
    void *py_frame = *py_frame_ptr;
    void *py_code = (void *)0;
    int ret;

    if (!py_frame) {
        return -1;
    }

    ret = bpf_probe_read_user(&py_code, sizeof(void *), py_frame + offsets->frame_obj.f_code);
    if (ret < 0) {
        return -1;
    }

    ret = get_py_symbol_info(py_sym, py_frame, py_code, offsets);
    if (ret) {
        return -1;
    }

    ret = bpf_probe_read_user(py_frame_ptr, sizeof(void *), py_frame + offsets->frame_obj.f_back);
    if (ret) {
        return -1;
    }

    return 0;
}

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
