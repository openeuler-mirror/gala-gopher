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
 * Description: syscall bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "task.h"
#include "proc_syscall.h"
#include "output_proc.h"

char g_linsence[] SEC("license") = "GPL";

TP_SYSCALL(sched_yield, sched_yield, TASK_PROBE_SCHED_SYSCALL)
TP_SYSCALL(futex, futex, TASK_PROBE_SCHED_SYSCALL)
#if defined(__TARGET_ARCH_x86)
TP_SYSCALL(epoll_wait, epoll_wait, TASK_PROBE_SCHED_SYSCALL)
#elif defined(__TARGET_ARCH_arm64)
KPROBE_SYSCALL(__arm64_sys_, epoll_wait, epoll_wait, TASK_PROBE_SCHED_SYSCALL)
#endif
TP_SYSCALL(epoll_pwait, epoll_pwait, TASK_PROBE_SCHED_SYSCALL)
