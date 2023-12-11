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
 * Description: python stack defined
 ******************************************************************************/
#ifndef __GOPHER_PY_STACK_H__
#define __GOPHER_PY_STACK_H__

#pragma once

#include "common.h"

#define MAX_PYTHON_PROG_NUM 1000

#define MAX_PYTHON_STACK_DEPTH_32 32
#define MAX_PYTHON_STACK_DEPTH_16 16
#define MAX_PYTHON_STACK_DEPTH_MAX (MAX_PYTHON_STACK_DEPTH_32)
#define MAX_PYTHON_SYMBOL_SIZE 64

struct py_stack {
    u32 stack_len;
    u64 stack[MAX_PYTHON_STACK_DEPTH_MAX];  // each element is a symbol id
};

struct py_symbol {
    char class_name[MAX_PYTHON_SYMBOL_SIZE];
    char func_name[MAX_PYTHON_SYMBOL_SIZE];
    // get python filename?
};

// offsets of struct PyThreadState
struct py_offset_thrd_state {
    u64 frame;              // offsetof(PyThreadState, ob_type)
};

// offsets of struct PyFrameObject
struct py_offset_frame_obj {
    u64 f_back;             // offsetof(PyFrameObject, f_back)
    u64 f_code;             // offsetof(PyFrameObject, f_code)
    u64 f_localsplus;       // offsetof(PyFrameObject, f_localsplus)
};

// offsets of struct PyCodeObject
struct py_offset_code_obj {
    u64 co_varnames;        // offsetof(PyCodeObject, co_varnames)
    u64 co_name;            // offsetof(PyCodeObject, co_name)
};

// offsets of struct PyObject,PyTypeObject,PyTupleObject,PyASCIIObject
struct py_offset_obj {
    u64 obj_type;           // offsetof(PyObject, ob_type)
    u64 type_obj_name;      // offsetof(PyTypeObject, tp_name)
    u64 tuple_obj_item;     // offsetof(PyTupleObject, ob_item)
    u64 var_obj_size;       // offsetof(PyVarObject, ob_size)
    u64 string_data;        // sizeof(PyASCIIObject)
};

// offsets of python structures
struct py_offset {
    u64 tstate_curr;        // offsetof(_PyRuntimeState, gilstate, tstate_current)
    struct py_offset_thrd_state state;
    struct py_offset_frame_obj frame_obj;
    struct py_offset_code_obj code_obj;
    struct py_offset_obj obj;
};

struct py_proc_data {
    u64 py_runtime_addr;    // virtual address of cpython variable `_PyRuntime`
    struct py_offset offsets;
};

#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
int try_init_py_proc_data(int pid, struct py_proc_data *data, const char *debug_dir);
#endif

#endif
