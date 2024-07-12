/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 */
#ifndef __SLI_H__
#define __SLI_H__

#pragma once

#ifdef BPF_PROG_KERN

#include "sli_obj.h"


#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(cpu_cgrp_inode_t));
    __uint(value_size, sizeof(struct sli_cpu_obj_s));
    __uint(max_entries, 1000);
} sli_cpu_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(cpu_cgrp_inode_t));
    __uint(value_size, sizeof(struct sli_mem_obj_s));
    __uint(max_entries, 1000);
} sli_mem_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32)); // const value 0
    __uint(value_size, sizeof(struct sli_args_s));
    __uint(max_entries, 1);
} sli_args_map SEC(".maps");

#define __DEFAULT_REPORT_PERIOD (__u64)((__u64)60 * 1000000000)
static __always_inline u64 get_report_period()
{
    u32 key = 0;
    u64 period = __DEFAULT_REPORT_PERIOD;

    struct sli_args_s *args;
    args = (struct sli_args_s *)bpf_map_lookup_elem(&sli_args_map, &key);
    if (args != NULL && args->report_period != 0) {
        period = args->report_period;
    }

    return period;
}

static __always_inline __maybe_unused void create_sli_cpu(cpu_cgrp_inode_t ino)
{
    struct sli_cpu_obj_s obj = {0};
    bpf_map_update_elem(&sli_cpu_map, &ino, &obj, BPF_ANY);
    return;
}
static __always_inline __maybe_unused struct sli_cpu_obj_s* lkup_sli_cpu(cpu_cgrp_inode_t ino)
{
    return (struct sli_cpu_obj_s *)bpf_map_lookup_elem(&sli_cpu_map, &ino);
}

static __always_inline __maybe_unused void delete_sli_cpu(cpu_cgrp_inode_t ino)
{
    bpf_map_delete_elem(&sli_cpu_map, &ino);
}

static __always_inline __maybe_unused void create_sli_mem(cpu_cgrp_inode_t ino)
{
    struct sli_mem_obj_s obj = {0};
    bpf_map_update_elem(&sli_mem_map, &ino, &obj, BPF_ANY);
    return;
}
static __always_inline __maybe_unused struct sli_mem_obj_s* lkup_sli_mem(cpu_cgrp_inode_t ino)
{
    return (struct sli_mem_obj_s *)bpf_map_lookup_elem(&sli_mem_map, &ino);
}

static __always_inline __maybe_unused void delete_sli_mem(cpu_cgrp_inode_t ino)
{
    bpf_map_delete_elem(&sli_mem_map, &ino);
}

static __always_inline __maybe_unused int get_current_cpuacct_ino(cpu_cgrp_inode_t *ino, struct task_struct *task)
{
    cpu_cgrp_inode_t cpuacct_ino;

    struct css_set *cgroups = _(task->cgroups);
    if (cgroups == NULL) {
        goto end;
    }
    struct cgroup_subsys_state *css = _(cgroups->subsys[cpuacct_cgrp_id]);
    if (css == NULL) {
        goto end;
    }

    int level = BPF_CORE_READ(css, cgroup, level);
    if (level == 0) {
        // root level cgroup
        *ino = CPUACCT_GLOBAL_CGPID;
        return 0;
    }

    struct kernfs_node *kn = BPF_CORE_READ(css, cgroup, kn);
    if (kn == NULL) {
        goto end;
    }

    bpf_core_read(&cpuacct_ino, sizeof(u64), &(kn->id));
    *ino = cpuacct_ino;

    return 0;
end:
    return -1;
}

static __always_inline __maybe_unused struct sli_cpu_obj_s* get_sli_cpu(struct task_struct *task)
{
    cpu_cgrp_inode_t ino;
    if (get_current_cpuacct_ino(&ino, task)) {
        return NULL;
    }

    return lkup_sli_cpu(ino);
}

static __always_inline __maybe_unused struct sli_mem_obj_s* get_sli_mem(struct task_struct *task)
{
    cpu_cgrp_inode_t ino;
    if (get_current_cpuacct_ino(&ino, task)) {
        return NULL;
    }

    return lkup_sli_mem(ino);
}


static __always_inline __maybe_unused char is_report_tmout(u64 *last_report)
{
    if (*last_report == 0) {
        return 1;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 report_period = get_report_period();
    if ((ts > *last_report) && ((ts - *last_report) >= report_period)) {
        return 1;
    }
    return 0;
}


#endif
#endif
