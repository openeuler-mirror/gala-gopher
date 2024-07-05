
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
 * Description: the bpf-side prog of thread profiling probe
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "syscall.bpf.h"
#include "syscall_tp_args.h"

char g_license[] SEC("license") = "GPL";

SET_TP_SYSCALL_PARAMS(sched_yield) { return; }

SET_SYSCALL_META(sched_yield)
{
    scm->nr = SYSCALL_SCHED_YIELD_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(nanosleep) { return; }

SET_SYSCALL_META(nanosleep)
{
    scm->nr = SYSCALL_NANOSLEEP_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(clock_nanosleep) { return; }

SET_SYSCALL_META(clock_nanosleep)
{
    scm->nr = SYSCALL_CLOCK_NANOSLEEP_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(wait4) { return; }

SET_SYSCALL_META(wait4)
{
    scm->nr = SYSCALL_WAIT4_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_riscv)
#ifndef __TARGET_ARCH_riscv
SET_SYSCALL_PARAMS(waitpid) { return; }

SET_SYSCALL_META(waitpid)
{
    scm->nr = SYSCALL_WAITPID_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}
#endif


SET_TP_SYSCALL_PARAMS(select) { return; }

SET_SYSCALL_META(select)
{
    scm->nr = SYSCALL_SELECT_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(poll) { return; }

SET_SYSCALL_META(poll)
{
    scm->nr = SYSCALL_POLL_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(epoll_wait) { return; }

SET_SYSCALL_META(epoll_wait)
{
    scm->nr = SYSCALL_EPOLL_WAIT_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

#elif defined(__TARGET_ARCH_arm64)
SET_SYSCALL_PARAMS(select) { return; }

SET_SYSCALL_META(select)
{
    scm->nr = SYSCALL_SELECT_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_SYSCALL_PARAMS(poll) { return; }

SET_SYSCALL_META(poll)
{
    scm->nr = SYSCALL_POLL_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_SYSCALL_PARAMS(epoll_wait) { return; }

SET_SYSCALL_META(epoll_wait)
{
    scm->nr = SYSCALL_EPOLL_WAIT_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

#endif

SET_TP_SYSCALL_PARAMS(pselect6) { return; }

SET_SYSCALL_META(pselect6)
{
    scm->nr = SYSCALL_PSELECT6_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(ppoll) { return; }

SET_SYSCALL_META(ppoll)
{
    scm->nr = SYSCALL_PPOLL_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

TP_SYSCALL(sched_yield)
TP_SYSCALL(nanosleep)
TP_SYSCALL(clock_nanosleep)
TP_SYSCALL(wait4)
#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_riscv)
#ifndef __TARGET_ARCH_riscv
KPROBE_SYSCALL(__x64_sys_, waitpid)
#endif
TP_SYSCALL(select)
TP_SYSCALL(poll)
TP_SYSCALL(epoll_wait)
#elif defined(__TARGET_ARCH_arm64)
KPROBE_SYSCALL(__arm64_sys_, select)
KPROBE_SYSCALL(__arm64_sys_, poll)
KPROBE_SYSCALL(__arm64_sys_, epoll_wait)
#endif
TP_SYSCALL(pselect6)
TP_SYSCALL(ppoll)
