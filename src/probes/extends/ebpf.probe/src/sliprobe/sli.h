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
        goto end;
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
