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
#include "proc_map.h"
#include "output_proc.h"

char g_linsence[] SEC("license") = "GPL";

#define SYSCALL_ID_MIN 1
#define SYSCALL_ID_MAX 512


struct sys_exit_args {
    unsigned long regs;
    long ret;
};

#define TS_COMPAT   0x0002  /* 32bit syscall active (64BIT) */
static __always_inline bool is_ia32_task(void)
{
#if defined(__TARGET_ARCH_x86)
    struct task_struct *task;
    u32 status;

    task = (struct task_struct *)bpf_get_current_task();

    status = _(task->thread_info.status);

    return status & TS_COMPAT;
#else
    return 0;
#endif
}


static __always_inline long get_syscall_id(void *ctx)
{
    struct sys_exit_args *args = (struct sys_exit_args *)ctx;
    long id;

    struct pt_regs *regs = (struct pt_regs *)args->regs;

#if defined(__TARGET_ARCH_x86)
    id = _(regs->orig_ax);
#elif defined(__TARGET_ARCH_arm64)
    id = _(regs->syscallno);
#else
    id = 0;
#endif
    return id;
}

static __always_inline long get_syscall_ret(void *ctx)
{
    struct sys_exit_args *args = (struct sys_exit_args *)ctx;

    return args->ret;
}

KRAWTRACE(sys_exit, sys_exit_args)
{
    struct proc_data_s *proc;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return 0;
    }

    if (is_ia32_task()) {
        return 0;
    }

    long id = get_syscall_id(ctx);
    if (id < SYSCALL_ID_MIN || id > SYSCALL_ID_MAX) {
        return 0;
    }

    long ret = get_syscall_ret(ctx);
    if (ret >= 0) {
        return 0;
    }

    __sync_fetch_and_add(&(proc->syscall.failed), 1);
    proc->syscall.last_ret_code = ret;
    proc->syscall.last_syscall_id = id;
    report_proc(ctx, proc, TASK_PROBE_SYSCALL);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int bpf_trace_sys_exit_func(struct trace_event_raw_sys_exit *ctx)
{
    struct proc_data_s *proc;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return 0;
    }

    if (is_ia32_task()) {
        return 0;
    }

    long id = (long)ctx->id;
    if (id < SYSCALL_ID_MIN || id > SYSCALL_ID_MAX) {
        return 0;
    }

    long ret = (long)ctx->ret;
    if (ret >= 0) {
        return 0;
    }

    __sync_fetch_and_add(&(proc->syscall.failed), 1);
    proc->syscall.last_ret_code = ret;
    proc->syscall.last_syscall_id = id;
    report_proc(ctx, proc, TASK_PROBE_SYSCALL);
    return 0;
}

