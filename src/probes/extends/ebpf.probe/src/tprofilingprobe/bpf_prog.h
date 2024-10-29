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

#define SETTING_MAP_PATH                "/sys/fs/bpf/gala-gopher/__tprofiling_setting"
#define PROC_FILTER_MAP_PATH            "/sys/fs/bpf/gala-gopher/__tprofiling_proc_filter"
#define THRD_BL_MAP_PATH                "/sys/fs/bpf/gala-gopher/__tprofiling_thrd_bl"
#define STACK_MAP_A_PATH                "/sys/fs/bpf/gala-gopher/__tprofiling_stack_a"
#define STACK_MAP_B_PATH                "/sys/fs/bpf/gala-gopher/__tprofiling_stack_b"
#define PY_PROC_MAP_PATH                "/sys/fs/bpf/gala-gopher/__tprofiling_py_proc"
#define PY_STACK_MAP_A_PATH             "/sys/fs/bpf/gala-gopher/__tprofiling_py_stack_a"
#define PY_STACK_MAP_B_PATH             "/sys/fs/bpf/gala-gopher/__tprofiling_py_stack_b"
#define STACK_PY_SYMBOL_IDS_MAP_PATH    "/sys/fs/bpf/gala-gopher/__tprofiling_py_symb"
#define STACK_PY_SAMPLE_HEAP_MAP_PATH   "/sys/fs/bpf/gala-gopher/__tprofiling_py_sample_heap"
#define SYSCALL_ENTER_MAP_PATH          "/sys/fs/bpf/gala-gopher/__tprofiling_syscall_enter"
#define SYSCALL_STASH_MAP_PATH          "/sys/fs/bpf/gala-gopher/__tprofiling_syscall_stash"

#define PERF_EVENT_MAP_A_PATH           "/sys/fs/bpf/gala-gopher/__tprofiling_perf_event_a"
#define PERF_EVENT_MAP_B_PATH           "/sys/fs/bpf/gala-gopher/__tprofiling_perf_event_b"

#define MAP_SET_COMMON_PIN_PATHS(probe_name, load) \
    MAP_SET_PIN_PATH(probe_name, setting_map, SETTING_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, proc_filter_map, PROC_FILTER_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, thrd_bl_map, THRD_BL_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, event_map_a, PERF_EVENT_MAP_A_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, event_map_b, PERF_EVENT_MAP_B_PATH, load); \

#define MAP_SET_PYSTACK_PIN_PATHS(probe_name, load) \
    MAP_SET_PIN_PATH(probe_name, py_proc_map, PY_PROC_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, py_stack_a, PY_STACK_MAP_A_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, py_stack_b, PY_STACK_MAP_B_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, py_symbol_ids, STACK_PY_SYMBOL_IDS_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, py_sample_heap, STACK_PY_SAMPLE_HEAP_MAP_PATH, load); \

#define LOAD_PROBE_COMMON(probe_name, end, load, pbMgmt) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_SET_COMMON_PIN_PATHS(probe_name, load); \
    MAP_INIT_BPF_BUFFER_SHARED(probe_name, event_map_a, &(pbMgmt)->perf_buffer_a, load); \
    MAP_INIT_BPF_BUFFER_SHARED(probe_name, event_map_b, &(pbMgmt)->perf_buffer_b, load); \

#define LOAD_PROBE_COMMON_WITH_STACK(probe_name, end, load, pbMgmt) \
    LOAD_PROBE_COMMON(probe_name, end, load, pbMgmt); \
    MAP_SET_PIN_PATH(probe_name, stack_map_a, STACK_MAP_A_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, stack_map_b, STACK_MAP_B_PATH, load); \
    MAP_SET_PYSTACK_PIN_PATHS(probe_name, load)

#define LOAD_SYSCALL_PROBE(probe_name, end, load, pbMgmt) \
    LOAD_PROBE_COMMON_WITH_STACK(probe_name, end, load, pbMgmt); \
    MAP_SET_PIN_PATH(probe_name, syscall_enter_map, SYSCALL_ENTER_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, syscall_stash_map, SYSCALL_STASH_MAP_PATH, load); \
    LOAD_ATTACH(tprofiling, probe_name, end, load)

#define LOAD_ONCPU_PROBE(probe_name, end, load, pbMgmt) \
    LOAD_PROBE_COMMON(probe_name, end, load, pbMgmt)

#define LOAD_PYGC_PROBE(probe_name, end, load, pbMgmt) \
    LOAD_PROBE_COMMON_WITH_STACK(probe_name, end, load, pbMgmt); \
    LOAD_ATTACH(tprofiling, probe_name, end, load);

#define LOAD_PTHRD_SYNC_PROBE(probe_name, end, load, pbMgmt) \
    LOAD_PROBE_COMMON_WITH_STACK(probe_name, end, load, pbMgmt); \
    LOAD_ATTACH(tprofiling, probe_name, end, load);

#define LOAD_MEM_GLIBC_PROBE(probe_name, end, load, pbMgmt) \
    LOAD_PROBE_COMMON_WITH_STACK(probe_name, end, load, pbMgmt); \
    LOAD_ATTACH(tprofiling, probe_name, end, load);

#define LOAD_ONCPU_SAMPLE_PROBE(probe_name, end, load, pbMgmt) \
    LOAD_PROBE_COMMON_WITH_STACK(probe_name, end, load, pbMgmt); \
    LOAD_ATTACH(tprofiling, probe_name, end, load);

#define LOAD_SYSCALL_BPF_PROG(type) \
    static int __load_syscall_##type##_bpf_prog(struct bpf_prog_s *prog, char is_load) \
    { \
        int ret = 0; \
        \
        LOAD_SYSCALL_PROBE(syscall_##type, err, is_load, &tprofiler.pbMgmt); \
        if (is_load) { \
            prog->skels[prog->num].skel = syscall_##type##_skel; \
            prog->skels[prog->num].fn = (skel_destroy_fn)syscall_##type##_bpf__destroy; \
            prog->custom_btf_paths[prog->num] = syscall_##type##_open_opts.btf_custom_path; \
            \
            ret = open_profiling_bpf_buffer(&tprofiler.pbMgmt); \
            if (ret) { \
                goto err; \
            } \
            prog->num++; \
        } \
        \
        return ret; \
    err: \
        UNLOAD(syscall_##type); \
        CLEANUP_CUSTOM_BTF(syscall_##type); \
        return -1; \
    }

int load_profiling_bpf_progs(struct ipc_body_s *ipc_body);
void unload_profiling_bpf_prog();
void reattach_uprobes(struct ipc_body_s *ipc_body);
void clean_proc_link_tbl();

#endif