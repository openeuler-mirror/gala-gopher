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
 * Description: the header file of thread profiling probe
 ******************************************************************************/
#ifndef __BPF_PROG_H__
#define __BPF_PROG_H__

#pragma once

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common.h"
#include "args.h"
#include "ipc.h"

#define RM_TPROFILING_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__tprofiling*"

#define PROC_FILTER_MAP_PATH   "/sys/fs/bpf/gala-gopher/__tprofiling_proc_filter"
#define THRD_BL_MAP_PATH       "/sys/fs/bpf/gala-gopher/__tprofiling_thrd_bl"
#define STACK_MAP_PATH         "/sys/fs/bpf/gala-gopher/__tprofiling_stack"
#define PY_PROC_MAP_PATH        "/sys/fs/bpf/gala-gopher/__tprofiling_py_proc"
#define PY_STACK_MAP_PATH         "/sys/fs/bpf/gala-gopher/__tprofiling_py_stack"
#define STACK_PY_SYMBOL_IDS_MAP_PATH         "/sys/fs/bpf/gala-gopher/__tprofiling_py_symb"
#define STACK_PY_SAMPLE_HEAP_MAP_PATH         "/sys/fs/bpf/gala-gopher/__tprofiling_py_sample_heap"
#define SYSCALL_ENTER_MAP_PATH "/sys/fs/bpf/gala-gopher/__tprofiling_syscall_enter"
#define SYSCALL_STASH_MAP_PATH "/sys/fs/bpf/gala-gopher/__tprofiling_syscall_stash"
#define SYSCALL_EVENT_MAP_PATH "/sys/fs/bpf/gala-gopher/__tprofiling_syscall_event"

#define ONCPU_EVENT_MAP_PATH   "/sys/fs/bpf/gala-gopher/__tprofiling_oncpu_event"

#define TPROFILING_PROBE_ONCPU          (u32)(1 << 0)
#define TPROFILING_PROBE_SYSCALL_FILE   (u32)(1 << 1)
#define TPROFILING_PROBE_SYSCALL_NET    (u32)(1 << 2)
#define TPROFILING_PROBE_SYSCALL_SCHED  (u32)(1 << 3)
#define TPROFILING_PROBE_SYSCALL_LOCK   (u32)(1 << 4)

#define TPROFILING_PROBE_SYSCALL_ALL \
    (u32)(TPROFILING_PROBE_SYSCALL_FILE | TPROFILING_PROBE_SYSCALL_NET \
          | TPROFILING_PROBE_SYSCALL_SCHED | TPROFILING_PROBE_SYSCALL_LOCK)
#define TPROFILING_PROBE_ALL (u32)(TPROFILING_PROBE_ONCPU | TPROFILING_PROBE_SYSCALL_ALL)

#define MAP_SET_COMMON_PIN_PATHS(probe_name, load) \
    MAP_SET_PIN_PATH(probe_name, proc_filter_map, PROC_FILTER_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, thrd_bl_map, THRD_BL_MAP_PATH, load); \

#define LOAD_SYSCALL_PROBE(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_SET_COMMON_PIN_PATHS(probe_name, load); \
    MAP_SET_PIN_PATH(probe_name, event_map, SYSCALL_EVENT_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, stack_map, STACK_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, py_proc_map, PY_PROC_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, py_stack_cached, PY_STACK_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, py_symbol_ids, STACK_PY_SYMBOL_IDS_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, py_sample_heap, STACK_PY_SAMPLE_HEAP_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, syscall_enter_map, SYSCALL_ENTER_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, syscall_stash_map, SYSCALL_STASH_MAP_PATH, load); \
    MAP_INIT_BPF_BUFFER(probe_name, event_map, buffer, load); \
    LOAD_ATTACH(tprofiling, probe_name, end, load)

#define LOAD_ONCPU_PROBE(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_SET_COMMON_PIN_PATHS(probe_name, load); \
    MAP_SET_PIN_PATH(probe_name, event_map, ONCPU_EVENT_MAP_PATH, load); \
    MAP_INIT_BPF_BUFFER(probe_name, event_map, buffer, load);

#define LOAD_SYSCALL_BPF_PROG(type) \
    static int __load_syscall_##type##_bpf_prog(struct bpf_prog_s *prog, char is_load) \
    { \
        int ret = 0; \
        struct bpf_buffer *buffer = NULL; \
        \
        LOAD_SYSCALL_PROBE(syscall_##type, err, is_load, buffer); \
        if (is_load) { \
            prog->skels[prog->num].skel = syscall_##type##_skel; \
            prog->skels[prog->num].fn = (skel_destroy_fn)syscall_##type##_bpf__destroy; \
            prog->custom_btf_paths[prog->num] = syscall_##type##_open_opts.btf_custom_path; \
            ret = bpf_buffer__open(buffer, perf_event_handler, NULL, NULL); \
            if (ret) { \
                TP_ERROR("Open bpf_buffer failed in syscall_"#type".\n"); \
                bpf_buffer__free(buffer); \
                goto err; \
            } \
            prog->buffers[prog->num] = buffer; \
            prog->num++; \
        } \
        \
        return ret; \
    err: \
        UNLOAD(syscall_##type); \
        CLEANUP_CUSTOM_BTF(syscall_##type); \
        return -1; \
    }

struct bpf_prog_s* load_syscall_bpf_prog(struct ipc_body_s *ipc_body);
struct bpf_prog_s* load_oncpu_bpf_prog(struct ipc_body_s *ipc_body);

#endif