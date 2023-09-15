
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

char g_license[] SEC("license") = "GPL";

SET_SYSCALL_PARAMS(sched_yield) { return; }

SET_SYSCALL_META(sched_yield)
{
    scm->nr = SYSCALL_SCHED_YIELD_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_SYSCALL_PARAMS(nanosleep) { return; }

SET_SYSCALL_META(nanosleep)
{
    scm->nr = SYSCALL_NANOSLEEP_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_SYSCALL_PARAMS(clock_nanosleep) { return; }

SET_SYSCALL_META(clock_nanosleep)
{
    scm->nr = SYSCALL_CLOCK_NANOSLEEP_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_SYSCALL_PARAMS(wait4) { return; }

SET_SYSCALL_META(wait4)
{
    scm->nr = SYSCALL_WAIT4_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

#if defined(__TARGET_ARCH_x86)
SET_SYSCALL_PARAMS(waitpid) { return; }

SET_SYSCALL_META(waitpid)
{
    scm->nr = SYSCALL_WAITPID_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}
#endif

SET_SYSCALL_PARAMS(select) { return; }

SET_SYSCALL_META(select)
{
    scm->nr = SYSCALL_SELECT_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_SYSCALL_PARAMS(pselect6) { return; }

SET_SYSCALL_META(pselect6)
{
    scm->nr = SYSCALL_PSELECT6_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_SYSCALL_PARAMS(poll) { return; }

SET_SYSCALL_META(poll)
{
    scm->nr = SYSCALL_POLL_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_SYSCALL_PARAMS(ppoll) { return; }

SET_SYSCALL_META(ppoll)
{
    scm->nr = SYSCALL_PPOLL_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_SYSCALL_PARAMS(epoll_wait) { return; }

SET_SYSCALL_META(epoll_wait)
{
    scm->nr = SYSCALL_EPOLL_WAIT_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

#if defined(__TARGET_ARCH_x86)
KPROBE_SYSCALL(__x64_sys_, sched_yield)
KPROBE_SYSCALL(__x64_sys_, nanosleep)
KPROBE_SYSCALL(__x64_sys_, clock_nanosleep)
KPROBE_SYSCALL(__x64_sys_, wait4)
KPROBE_SYSCALL(__x64_sys_, waitpid)
KPROBE_SYSCALL(__x64_sys_, select)
KPROBE_SYSCALL(__x64_sys_, pselect6)
KPROBE_SYSCALL(__x64_sys_, poll)
KPROBE_SYSCALL(__x64_sys_, ppoll)
KPROBE_SYSCALL(__x64_sys_, epoll_wait)
#elif defined(__TARGET_ARCH_arm64)
KPROBE_SYSCALL(__arm64_sys_, sched_yield)
KPROBE_SYSCALL(__arm64_sys_, nanosleep)
KPROBE_SYSCALL(__arm64_sys_, clock_nanosleep)
KPROBE_SYSCALL(__arm64_sys_, wait4)
KPROBE_SYSCALL(__arm64_sys_, select)
KPROBE_SYSCALL(__arm64_sys_, pselect6)
KPROBE_SYSCALL(__arm64_sys_, poll)
KPROBE_SYSCALL(__arm64_sys_, ppoll)
KPROBE_SYSCALL(__arm64_sys_, epoll_wait)
#endif