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
#include "task.h"
#include "proc_syscall.h"
#include "output_proc.h"

char g_linsence[] SEC("license") = "GPL";

#if defined(__TARGET_ARCH_x86)
TP_SYSCALL(fork, fork, TASK_PROBE_FORK_SYSCALL)
TP_SYSCALL(vfork, vfork, TASK_PROBE_FORK_SYSCALL)
#elif defined(__TARGET_ARCH_arm64)
KPROBE_SYSCALL(__arm64_sys_, fork, fork, TASK_PROBE_FORK_SYSCALL)
KPROBE_SYSCALL(__arm64_sys_, vfork, vfork, TASK_PROBE_FORK_SYSCALL)
#endif
TP_SYSCALL(clone, clone, TASK_PROBE_FORK_SYSCALL)
