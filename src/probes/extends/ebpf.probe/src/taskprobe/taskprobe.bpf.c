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
 * Author: sinever
 * Create: 2021-10-25
 * Description: task_probe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "args_map.h"
#include "thread_map.h"
#include "proc_map.h"

char g_linsence[] SEC("license") = "GPL";

#if (CURRENT_KERNEL_VERSION > KERNEL_VERSION(4, 18, 0))
KRAWTRACE(sched_process_exit, bpf_raw_tracepoint_args)
{
    struct task_struct* task = (struct task_struct*)ctx->args[0];
    int pid = _(task->pid);
    int tgid = _(task->tgid);

    if (pid == tgid) {
        proc_put_entry((u32)tgid);
    }

    (void)thread_put(pid);
    return 0;
}
#else
SEC("tracepoint/sched/sched_process_exit")
int bpf_trace_sched_process_exit_func(struct trace_event_raw_sched_process_template *ctx)
{
    int pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if (pid == tgid) {
        proc_put_entry((u32)tgid);
    }

    (void)thread_put(pid);
    return 0;
}
#endif
