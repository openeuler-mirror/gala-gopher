/*
 * bpf code runs in the Linux kernel
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "syscall.bpf.h"
#include "syscall_tp_args.h"

char g_license[] SEC("license") = "GPL";

SET_TP_SYSCALL_PARAMS(sched_yield) { sce->nr = SYSCALL_SCHED_YIELD_ID; }

SET_SYSCALL_META(sched_yield)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(nanosleep) { sce->nr = SYSCALL_NANOSLEEP_ID; }

SET_SYSCALL_META(nanosleep)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(clock_nanosleep) { sce->nr = SYSCALL_CLOCK_NANOSLEEP_ID; }

SET_SYSCALL_META(clock_nanosleep)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(wait4) { sce->nr = SYSCALL_WAIT4_ID; }

SET_SYSCALL_META(wait4)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_riscv)
#ifndef __TARGET_ARCH_riscv
SET_SYSCALL_PARAMS(waitpid) { sce->nr = SYSCALL_WAITPID_ID; }

SET_SYSCALL_META(waitpid)
{
    scm->flag = SYSCALL_FLAG_STACK;
}
#endif

SET_TP_SYSCALL_PARAMS(select) { sce->nr = SYSCALL_SELECT_ID; }

SET_SYSCALL_META(select)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(poll) { sce->nr = SYSCALL_POLL_ID; }

SET_SYSCALL_META(poll)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(epoll_wait) { sce->nr = SYSCALL_EPOLL_WAIT_ID; }

SET_SYSCALL_META(epoll_wait)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

#elif defined(__TARGET_ARCH_arm64)
SET_SYSCALL_PARAMS(select) { sce->nr = SYSCALL_SELECT_ID; }

SET_SYSCALL_META(select)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_SYSCALL_PARAMS(poll) { sce->nr = SYSCALL_POLL_ID; }

SET_SYSCALL_META(poll)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_SYSCALL_PARAMS(epoll_wait) { sce->nr = SYSCALL_EPOLL_WAIT_ID; }

SET_SYSCALL_META(epoll_wait)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

#endif

SET_TP_SYSCALL_PARAMS(pselect6) { sce->nr = SYSCALL_PSELECT6_ID; }

SET_SYSCALL_META(pselect6)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(ppoll) { sce->nr = SYSCALL_PPOLL_ID; }

SET_SYSCALL_META(ppoll)
{
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
