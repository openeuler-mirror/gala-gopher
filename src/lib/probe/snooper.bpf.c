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
 * Create: 2023-04-10
 * Description: snooper bpf code
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "common.h"
#include "snooper_bpf.h"

#include "__bpf_kern.h"
#include "__compat.h"

char g_linsence[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 *1024);
} snooper_proc_channel SEC(".maps");

static __always_inline void process_new_forked_task(struct task_struct *child, void *ctx)
{
    struct snooper_proc_evt_s event = {0};
    pid_t pid = _(child->pid);
    pid_t tgid = _(child->tgid);

    if (pid != tgid) {
        return;
    }

    event.pid = pid;
    event.proc_event = PROC_EXEC;
    bpf_core_read_str(event.filename, sizeof(child->comm), &child->comm);

    bpfbuf_output(ctx, &snooper_proc_channel, &event, sizeof(event));
}

KRAWTRACE(sched_process_fork, bpf_raw_tracepoint_args)
{
    struct task_struct *child = (struct task_struct *)ctx->args[1];

    process_new_forked_task(child, ctx);
    return 0;
}

KPROBE(wake_up_new_task, pt_regs)
{
    struct task_struct *child = (struct task_struct *)PT_REGS_PARM1(ctx);

    process_new_forked_task(child, ctx);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int bpf_trace_sched_process_fork_func(struct trace_event_raw_sched_process_fork *ctx)
{
    struct snooper_proc_evt_s event = {0};

    event.pid = ctx->child_pid;
    event.proc_event = PROC_EXEC;
    bpf_core_read_str(event.filename, sizeof(ctx->child_comm), &ctx->child_comm);

    bpfbuf_output(ctx, &snooper_proc_channel, &event, sizeof(event));
    return 0;
}

KRAWTRACE(sched_process_exec, bpf_raw_tracepoint_args)
{
    struct snooper_proc_evt_s event = {0};
    struct task_struct* task = (struct task_struct *)ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
    pid_t pid = _(task->pid);
    const char *filename = _(bprm->filename);

    event.pid = (u32)pid;
    event.proc_event = PROC_EXEC;
    bpf_core_read(&event.filename, PATH_LEN, filename);

    bpfbuf_output(ctx, &snooper_proc_channel, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int bpf_trace_sched_process_exec_func(struct trace_event_raw_sched_process_exec *ctx)
{
    struct snooper_proc_evt_s event = {0};
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.proc_event = PROC_EXEC;
    bpf_core_read_str(&event.filename, sizeof(event.filename), (void *)ctx + fname_off);

    bpfbuf_output(ctx, &snooper_proc_channel, &event, sizeof(event));
    return 0;
}

KRAWTRACE(sched_process_exit, bpf_raw_tracepoint_args)
{
    struct snooper_proc_evt_s event = {0};
    struct task_struct* task = (struct task_struct *)ctx->args[0];
    pid_t pid = _(task->pid);
    pid_t tgid = _(task->tgid);

    /* ignore thread exit */
    if (pid != tgid) {
        return 0;
    }

    event.pid = (u32)pid;
    event.proc_event = PROC_EXIT;

    bpfbuf_output(ctx, &snooper_proc_channel, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int bpf_trace_sched_process_exit_func(struct trace_event_raw_sched_process_template *ctx)
{
    struct snooper_proc_evt_s event = {0};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.proc_event = PROC_EXIT;

    bpfbuf_output(ctx, &snooper_proc_channel, &event, sizeof(event));
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 *1024);
} snooper_cgrp_channel SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct snooper_cgrp_evt_s));
    __uint(max_entries, 1);
} tmp_map SEC(".maps");

static __always_inline int check_root_id(struct cgroup *cgrp)
{
    if (!cgrp)
        return 0;

    struct cgroup_root *root =  _(cgrp->root);
    if (!root)
        return 0;

    int root_id = _(root->hierarchy_id);
    return root_id == 1 ? 1 : 0;
}

static __always_inline void report_cgrp_change(void *ctx, enum cgrp_event_t cgrp_event, const char *path)
{
    u32 key = 0;
    struct snooper_cgrp_evt_s *msg_data = bpf_map_lookup_elem(&tmp_map, &key);

    if (!msg_data)
        return;

    msg_data->cgrp_event = cgrp_event;
    bpf_core_read_str(msg_data->cgrp_path, MAX_CGRP_PATH, path);

    (void)bpfbuf_output(ctx, &snooper_cgrp_channel, msg_data, sizeof(struct snooper_cgrp_evt_s));
}

KRAWTRACE(cgroup_mkdir, bpf_raw_tracepoint_args)
{
    struct cgroup *cgrp = (struct cgroup *)ctx->args[0];

    if (!check_root_id(cgrp))
        return 0;

    const char *path = (const char *)ctx->args[1];
    report_cgrp_change(ctx, CGRP_MK, path);
    return 0;
}

SEC("tracepoint/cgroup/cgroup_mkdir")
int bpf_trace_cgroup_mkdir_func(struct trace_event_raw_cgroup *ctx)
{
    int root_id = (int)ctx->root; // cgrp->root->hierarchy_id

    if (root_id != 1)
        return 0;

    const char *path = (const char *)(u64)ctx->__data_loc_path;
    report_cgrp_change(ctx, CGRP_MK, path);
    return 0;
}

KRAWTRACE(cgroup_rmdir, bpf_raw_tracepoint_args)
{
    struct cgroup *cgrp = (struct cgroup *)ctx->args[0];
    if (!check_root_id(cgrp))
        return 0;

    const char *path = (const char *)ctx->args[1];
    report_cgrp_change(ctx, CGRP_RM, path);
    return 0;
}

SEC("tracepoint/cgroup/cgroup_rmdir")
int bpf_trace_cgroup_rmdir_func(struct trace_event_raw_cgroup *ctx)
{
    const char *path = (const char *)(u64)ctx->__data_loc_path;
    report_cgrp_change(ctx, CGRP_RM, path);
    return 0;
}

