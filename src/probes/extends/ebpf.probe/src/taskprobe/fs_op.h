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
 * Description: File system operation
 ******************************************************************************/
#ifndef __FS_OP_H__
#define __FS_OP_H__

#pragma once

#include "bpf.h"
#include "proc_map.h"
#include "proc.h"

static __always_inline __maybe_unused struct proc_data_s* get_delta(u64 *res)
{
    struct proc_data_s *proc;
    u64 ts = bpf_ktime_get_ns(), delta = 0;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return NULL;
    }

    if (proc->fs_op_start_ts == 0) {
        return NULL;
    }

    if (ts > proc->fs_op_start_ts) {
        delta = ts - proc->fs_op_start_ts;
        proc->fs_op_start_ts = 0;
        *res = delta;
        return proc;
    } else {
        proc->fs_op_start_ts = 0;
        return NULL;
    }
}

static __always_inline __maybe_unused void store_start_ts(void)
{
    struct proc_data_s *proc;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return;
    }

    proc->fs_op_start_ts = bpf_ktime_get_ns();
}

#define KPROBE_FS_OP(func, fs, field, flags) \
    KRETPROBE(func, pt_regs)\
    { \
        u64 res; \
        struct proc_data_s *proc = get_delta(&res); \
        \
        if (proc && (res > proc->op_##fs.ns_##field)) { \
            proc->op_##fs.ns_##field = res; \
            report_proc(ctx, proc, flags); \
        } \
    } \
    \
    KPROBE(func, pt_regs) \
    { \
        store_start_ts(); \
    }

#endif
