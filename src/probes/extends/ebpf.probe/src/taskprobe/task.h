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
 * Author: dowzyx
 * Create: 2022-06-10
 * Description: basic task struct
 ******************************************************************************/
#ifndef __GOPHER_TASK_H__
#define __GOPHER_TASK_H__

#pragma once

#include "args.h"
#include "bpf.h"

#define TASK_PROBE_SYSCALL          (u32)(1)
#define TASK_PROBE_IO_SYSCALL       (u32)(1 << 1)
#define TASK_PROBE_NET_SYSCALL      (u32)(1 << 2)
#define TASK_PROBE_SCHED_SYSCALL    (u32)(1 << 3)
#define TASK_PROBE_FORK_SYSCALL     (u32)(1 << 4)
#define TASK_PROBE_EXT4_OP          (u32)(1 << 5)
#define TASK_PROBE_OVERLAY_OP       (u32)(1 << 6)
#define TASK_PROBE_TMPFS_OP         (u32)(1 << 7)
#define TASK_PROBE_PAGE_OP          (u32)(1 << 8)
#define TASK_PROBE_DNS_OP           (u32)(1 << 9)
#define TASK_PROBE_THREAD_IO        (u32)(1 << 10)
#define TASK_PROBE_THREAD_CPU       (u32)(1 << 11)

#define TASK_PROBE_ALL       (u32)(TASK_PROBE_SYSCALL | TASK_PROBE_IO_SYSCALL \
                | TASK_PROBE_NET_SYSCALL | TASK_PROBE_SCHED_SYSCALL \
                | TASK_PROBE_FORK_SYSCALL | TASK_PROBE_EXT4_OP | TASK_PROBE_OVERLAY_OP \
                | TASK_PROBE_TMPFS_OP | TASK_PROBE_PAGE_OP | TASK_PROBE_DNS_OP \
                | TASK_PROBE_THREAD_IO | TASK_PROBE_THREAD_CPU)

static __always_inline __maybe_unused char is_load_probe(struct probe_params *args, u32 probe)
{
    if (args->load_probe & probe) {
        return 1;
    }
    return 0;
}

#endif
