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

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_ioctl/format
struct sys_enter_ioctl_args {
    unsigned long long __unused__;
    long __syscall_nr;
    unsigned long fd;
    unsigned long cmd;
    unsigned long arg;
};

bpf_section("tracepoint/syscalls/sys_exit_ioctl")
int function_sys_exit_ioctl(void *ctx)
{
    u64 res;
    struct proc_data_s *proc = get_syscall_op_us(&res);
    if (proc && (res > proc->syscall.ns_ioctl)) {
        proc->syscall.ns_ioctl = res;
        report_proc(ctx, proc, TASK_PROBE_IOCTL_SYSCALL);
    }
    return 0;
}

bpf_section("tracepoint/syscalls/sys_enter_ioctl")
int function_sys_enter_ioctl(struct sys_enter_ioctl_args *ctx)
{
    struct proc_data_s *proc;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return 0;
    }

    proc->syscall.syscall_start_ts = bpf_ktime_get_ns();
    proc->syscall.ioctl_fd = ctx->fd;
    proc->syscall.ioctl_cmd = ctx->cmd;

    return 0;
}

