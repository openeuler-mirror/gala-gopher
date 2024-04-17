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
 * Author: wo_cow
 * Create: 2024-02-21
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

