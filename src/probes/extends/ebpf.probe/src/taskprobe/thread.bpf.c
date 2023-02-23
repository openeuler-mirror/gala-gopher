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
 * Author: luzhihao
 * Create: 2022-11-25
 * Description: thread bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "args_map.h"
#include "thread_map.h"
#include "proc_map.h"
#include "output_thread.h"

char g_linsence[] SEC("license") = "GPL";

static __always_inline int get_task_pgid(const struct task_struct *cur_task)
{
    int pgid = 0;

    /* ns info from thread_pid */
    struct pid *thread_pid = _(cur_task->thread_pid);
    struct pid_namespace *ns_info = (struct pid_namespace *)0;
    if (thread_pid != 0) {
        int l = _(thread_pid->level);
        struct upid thread_upid = _(thread_pid->numbers[l]);
        ns_info = thread_upid.ns;
    }

    /* upid info from signal */
    struct signal_struct* signal = _(cur_task->signal);
    struct pid *pid_p = (struct pid *)0;
    bpf_probe_read(&pid_p, sizeof(struct pid *), &signal->pids[PIDTYPE_PGID]);
    int level = _(pid_p->level);
    struct upid upid = _(pid_p->numbers[level]);
    if (upid.ns == ns_info) {
        pgid = upid.nr;
    }

    return pgid;
}

KRAWTRACE(sched_wakeup_new, bpf_raw_tracepoint_args)
{
    u32 tgid, pid;
    struct task_struct* parent;
    struct task_struct* task = (struct task_struct*)ctx->args[0];

    tgid = _(task->tgid);
    pid = _(task->pid);
    if (pid == tgid) {
        return 0;
    }
    if (get_proc_entry(tgid) && !get_thread(pid)) {
        struct thread_data thr = {0};
        thr.id.pid = pid;
        thr.id.tgid = tgid;
        parent = _(task->parent);
        if (parent) {
            thr.id.ppid = _(parent->pid);
        }
        thr.id.pgid = get_task_pgid(task);
        (void)thread_add(thr.id.pid, &thr);
    }
    return 0;
}
