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

#define RM_TPROFILING_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__tprofiling*"

#define SETTING_MAP_PATH       "/sys/fs/bpf/gala-gopher/__tprofiling_setting"
#define PROC_FILTER_MAP_PATH   "/sys/fs/bpf/gala-gopher/__tprofiling_proc_filter"
#define THRD_BL_MAP_PATH       "/sys/fs/bpf/gala-gopher/__tprofiling_thrd_bl"
#define STACK_MAP_PATH         "/sys/fs/bpf/gala-gopher/__tprofiling_stack"
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
    MAP_SET_PIN_PATH(probe_name, setting_map, SETTING_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, proc_filter_map, PROC_FILTER_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, thrd_bl_map, THRD_BL_MAP_PATH, load); \

#define LOAD_SYSCALL_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_COMMON_PIN_PATHS(probe_name, load); \
    MAP_SET_PIN_PATH(probe_name, event_map, SYSCALL_EVENT_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, stack_map, STACK_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, syscall_enter_map, SYSCALL_ENTER_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, syscall_stash_map, SYSCALL_STASH_MAP_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

#define LOAD_ONCPU_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_COMMON_PIN_PATHS(probe_name, load); \
    MAP_SET_PIN_PATH(probe_name, event_map, ONCPU_EVENT_MAP_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

#define LOAD_SYSCALL_BPF_PROG(type) \
    static int __load_syscall_##type##_bpf_prog(struct bpf_prog_s *prog, char is_load) \
    { \
        int ret = 0; \
        \
        LOAD_SYSCALL_PROBE(syscall_##type, err, is_load); \
        if (is_load) { \
            prog->skels[prog->num].skel = syscall_##type##_skel; \
            prog->skels[prog->num].fn = (skel_destroy_fn)syscall_##type##_bpf__destroy; \
            prog->num++; \
            \
            ret = load_syscall_create_pb(prog, GET_MAP_FD(syscall_##type, event_map)); \
        } \
        \
        return ret; \
    err: \
        UNLOAD(syscall_##type); \
        return -1; \
    }

struct bpf_prog_s* load_syscall_bpf_prog(struct probe_params *params);
struct bpf_prog_s* load_oncpu_bpf_prog(struct probe_params *params);

#endif