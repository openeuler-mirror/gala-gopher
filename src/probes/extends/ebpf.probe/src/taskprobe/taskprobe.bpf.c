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
#include "taskprobe.h"
#include "args_map.h"
#include "task_map.h"
#include "proc_map.h"

char g_linsence[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") probe_proc_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct probe_process),
    .value_size = sizeof(int),
    .max_entries = PROBE_PROC_MAP_ENTRY_SIZE,
};

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

static __always_inline int is_task_in_probe_range(const char *comm)
{
    int flag = 0;
    struct probe_process pname = {0};

    __builtin_memcpy(pname.name, comm, TASK_COMM_LEN);

    char *buf = (char *)bpf_map_lookup_elem(&probe_proc_map, &pname);
    if (buf != (char *)0) {
        flag = *buf;
    }
    return flag;
}

KRAWTRACE(sched_process_fork, bpf_raw_tracepoint_args)
{
    int pid, tgid;
    char comm[TASK_COMM_LEN];

    struct task_struct* child = (struct task_struct*)ctx->args[1];

    (void)bpf_probe_read_str(&comm,
        TASK_COMM_LEN * sizeof(char), (char *)child->comm);

    if (is_task_in_probe_range((const char *)comm)) {
        /* Add child task info to task_map */
        pid = _(child->pid);
        tgid = _(child->tgid);

        if (pid == tgid) {
            proc_add_entry((u32)tgid, (const char *)comm);
        }
    }
}

KRAWTRACE(sched_wakeup_new, bpf_raw_tracepoint_args)
{
    struct task_data data = {0};
    struct task_struct* parent;
    struct task_struct* task = (struct task_struct*)ctx->args[0];

    (void)bpf_probe_read_str(&(data.id.comm),
        TASK_COMM_LEN * sizeof(char), (char *)task->comm);

    if (is_task_in_probe_range((const char *)data.id.comm)) {
        /* Add child task info to task_map */

        data.id.pid = _(task->pid);
        data.id.tgid = _(task->tgid);
        parent = _(task->parent);
        if (parent) {
            data.id.ppid = _(parent->pid);
        }
        data.id.pgid = get_task_pgid(task);
        (void)task_add(data.id.pid, &data);
    }
}

KRAWTRACE(sched_process_exit, bpf_raw_tracepoint_args)
{
    struct task_struct* task = (struct task_struct*)ctx->args[0];
    int pid = _(task->pid);
    int tgid = _(task->tgid);

    if (pid == tgid) {
        proc_put_entry((u32)tgid);
    }

    (void)task_put(pid);
}

KRAWTRACE(task_rename, bpf_raw_tracepoint_args)
{
    struct task_struct* task = (struct task_struct *)ctx->args[0];
    const char *comm = (const char *)ctx->args[1];
    int pid = _(task->pid);
    int tgid = _(task->tgid);

    struct task_data *val = (struct task_data *)get_task(pid);
    if (val) {
        bpf_probe_read_str(&(val->id.comm), TASK_COMM_LEN * sizeof(char), (char *)comm);
    }
    if ((pid == tgid) && val) {
        struct proc_data_s* proc = get_proc_entry((u32)tgid);
        if (proc) {
            __builtin_memcpy(proc->comm, val->id.comm, TASK_COMM_LEN);
        }
    }
}
