/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2022-07-13
 * Description: proc syscall
 ******************************************************************************/
#ifndef __PROC_SYSCALL_H__
#define __PROC_SYSCALL_H__

#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "task.h"
#include "proc.h"
#include "proc_map.h"

static __always_inline __maybe_unused void store_syscall_op_start_ts(void)
{
    struct proc_data_s *proc;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return;
    }

    proc->syscall.syscall_start_ts = bpf_ktime_get_ns();
}

static __always_inline __maybe_unused struct proc_data_s* get_syscall_op_us(u64 *res)
{
    struct proc_data_s *proc;
    u64 ts = bpf_ktime_get_ns(), delta = 0;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return NULL;
    }

    if (proc->syscall.syscall_start_ts == 0) {
        return NULL;
    }

    if (ts > proc->syscall.syscall_start_ts) {
        delta = ts - proc->syscall.syscall_start_ts;
        proc->syscall.syscall_start_ts = 0;
        *res = delta;
        return proc;
    } else {
        proc->syscall.syscall_start_ts = 0;
        return NULL;
    }
}

#define KPROBE_SYSCALL(arch, func, field, flags) \
        KRETPROBE(arch##func, pt_regs) \
        { \
            u64 res; \
            struct proc_data_s *proc = get_syscall_op_us(&res); \
            \
            if (proc && (res > proc->syscall.ns_##field)) { \
                proc->syscall.ns_##field = res; \
                report_proc(ctx, proc, flags); \
            } \
            return 0; \
        } \
        \
        KPROBE(arch##func, pt_regs) \
        { \
            store_syscall_op_start_ts(); \
            return 0; \
        }

#define TP_SYSCALL(func, field, flags) \
        bpf_section("tracepoint/syscalls/sys_exit_" #func) \
        int function_sys_exit_##func(void *ctx) \
        { \
            u64 res; \
            struct proc_data_s *proc = get_syscall_op_us(&res); \
            \
            if (proc && (res > proc->syscall.ns_##field)) { \
                proc->syscall.ns_##field = res; \
                report_proc(ctx, proc, flags); \
            } \
            return 0; \
        } \
        \
        bpf_section("tracepoint/syscalls/sys_enter_" #func) \
        int function_sys_enter_##func(void *ctx) \
        { \
            store_syscall_op_start_ts(); \
            return 0; \
        }

#endif
