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
#ifndef __PY_STACK_BPF_COMM_H__
#define __PY_STACK_BPF_COMM_H__

#define BPF_PROG_KERN

#pragma once
#include "bpf.h"
#include "py_stack.h"

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

#endif
