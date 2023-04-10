/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
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

#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#define CURRENT_KERNEL_VERSION KERNEL_VERSION(KER_VER_MAJOR, KER_VER_MINOR, KER_VER_PATCH)

#define LIBBPF_VERSION(a, b) (((a) << 8) + (b))
#define CURRENT_LIBBPF_VERSION LIBBPF_VERSION(LIBBPF_VER_MAJOR, LIBBPF_VER_MINOR)

#include "__bpf_kern.h"

char g_linsence[] SEC("license") = "GPL";

#define BPF_F_INDEX_MASK    0xffffffffULL
#define BPF_F_ALL_CPU   BPF_F_INDEX_MASK

#ifndef __PERF_OUT_MAX
#define __PERF_OUT_MAX (64)
#endif
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, __PERF_OUT_MAX);
} snooper_proc_channel SEC(".maps");

struct proc_exec_evt {
    char filename[PATH_LEN];
    u32 pid;
};

KRAWTRACE(sched_process_exec, bpf_raw_tracepoint_args)
{
    struct proc_exec_evt event = {0};
    struct task_struct* task = (struct task_struct *)ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
    pid_t pid = _(task->pid);
    const char *filename = _(bprm->filename);

    event.pid = (u32)pid;
    bpf_probe_read(&event.filename, PATH_LEN, filename);

    bpf_perf_event_output(ctx, &snooper_proc_channel, BPF_F_ALL_CPU,
                          &event, sizeof(event));
    return 0;
}

enum cgrp_event_t {
    CGRP_MK,
    CGRP_RM,
};
#define MAX_CGRP_PATH 512

struct cgroup_msg_data_t {
    enum cgrp_event_t cgrp_event;
    char cgrp_path[MAX_CGRP_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, __PERF_OUT_MAX);
} snooper_cgrp_channel SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct cgroup_msg_data_t));
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
    struct cgroup_msg_data_t *msg_data = bpf_map_lookup_elem(&tmp_map, &key);

    if (!msg_data)
        return;

    msg_data->cgrp_event = cgrp_event;
    bpf_probe_read_str(msg_data->cgrp_path, MAX_CGRP_PATH, path);

    (void)bpf_perf_event_output(ctx, &snooper_cgrp_channel, BPF_F_ALL_CPU, msg_data, sizeof(struct cgroup_msg_data_t));
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

KRAWTRACE(cgroup_rmdir, bpf_raw_tracepoint_args)
{
    struct cgroup *cgrp = (struct cgroup *)ctx->args[0];
    if (!check_root_id(cgrp))
        return 0;

    const char *path = (const char *)ctx->args[1];
    report_cgrp_change(ctx, CGRP_RM, path);
    return 0;
}

