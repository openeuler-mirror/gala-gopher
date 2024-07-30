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

#include "sli.h"

char g_linsence[] SEC("license") = "GPL";

#define PF_IDLE			0x00000002	/* I am an IDLE thread */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */

struct task_sched_s {
    u32 task_switch;                /* The count of task switch */
    u64 utime;                      /* Userspace execution time of process */
    u64 kernel_exec_start;          /* Timestamps of task that was running in the kernel space */
    u64 last_run_delay;
    char is_report;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(cpu_cgrp_inode_t));
    __uint(value_size, sizeof(struct sli_cpu_obj_s));
    __uint(max_entries, 1000);
} sli_cpu_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct task_struct *));
    __uint(value_size, sizeof(struct task_sched_s));
    __uint(max_entries, 1000);
} task_sched_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} sli_cpu_channel_map SEC(".maps");

static __always_inline struct sli_cpu_obj_s* lkup_sli_cpu(cpu_cgrp_inode_t ino)
{
    return (struct sli_cpu_obj_s *)bpf_map_lookup_elem(&sli_cpu_map, &ino);
}

static __always_inline struct sli_cpu_obj_s* get_sli_cpu(struct task_struct *task)
{
    cpu_cgrp_inode_t ino;
    if (get_current_cpuacct_ino(&ino, task)) {
        return NULL;
    }

    return lkup_sli_cpu(ino);
}

static __always_inline void report_sli_cpu(void *ctx, struct sli_cpu_obj_s* sli_cpu)
{
    if (is_report_tmout(&(sli_cpu->last_report))) {
        (void)bpfbuf_output(ctx,
                            &sli_cpu_channel_map,
                            sli_cpu,
                            sizeof(struct sli_cpu_obj_s));
        sli_cpu->last_report = bpf_ktime_get_ns();
        __builtin_memset(&(sli_cpu->sli), 0, sizeof(struct sli_cpu_s));
    }
}

static __always_inline struct task_sched_s* lkup_task_sched(struct task_struct *task)
{
    return (struct task_sched_s *)bpf_map_lookup_elem(&task_sched_map, &task);
}

static __always_inline struct task_sched_s* get_task_sched(struct task_struct *task)
{
    struct task_sched_s *sched = lkup_task_sched(task);
    if (sched) {
        return sched;
    }

    struct task_sched_s sched_obj = {0};
    bpf_map_update_elem(&task_sched_map, &task, &sched_obj, BPF_ANY);
    return lkup_task_sched(task);
}

static __always_inline char in_iowait(struct task_struct *task)
{
    u64 is_iowait = BPF_CORE_READ_BITFIELD_PROBED(task, in_iowait);
    return (char)is_iowait;
}

static __always_inline char is_filter_task(struct task_struct *task)
{
    unsigned int flags = BPF_CORE_READ(task, flags);
    return (char)((flags & PF_IDLE) || (flags & PF_KTHREAD));
}

KRAWTRACE(sched_stat_wait, bpf_raw_tracepoint_args)
{
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    u64 delay = (u64)ctx->args[1];

    if (is_filter_task(task)) {
        return 0;
    }

    struct sli_cpu_obj_s* sli_cpu = get_sli_cpu(task);
    if (sli_cpu == NULL) {
        return -1;
    }

    enum sli_cpu_lat_t idx = get_sli_cpu_lat_type(delay);

    sli_cpu->sli.cpu_lats[SLI_CPU_WAIT].cnt[idx]++;
    sli_cpu->sli.lat_ns[SLI_CPU_WAIT] += delay;

    report_sli_cpu(ctx, sli_cpu);
    return 0;
}

KRAWTRACE(sched_stat_sleep, bpf_raw_tracepoint_args)
{
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    u64 delay = (u64)ctx->args[1];

    if (is_filter_task(task)) {
        return 0;
    }

    struct sli_cpu_obj_s* sli_cpu = get_sli_cpu(task);
    if (sli_cpu == NULL) {
        return -1;
    }

    enum sli_cpu_lat_t idx = get_sli_cpu_lat_type(delay);

    sli_cpu->sli.cpu_lats[SLI_CPU_SLEEP].cnt[idx]++;
    sli_cpu->sli.lat_ns[SLI_CPU_SLEEP] += delay;

    report_sli_cpu(ctx, sli_cpu);
    return 0;
}

KRAWTRACE(sched_stat_blocked, bpf_raw_tracepoint_args)
{
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    u64 delay = (u64)ctx->args[1];

    if (is_filter_task(task)) {
        return 0;
    }

    struct sli_cpu_obj_s* sli_cpu = get_sli_cpu(task);
    if (sli_cpu == NULL) {
        return -1;
    }

    enum sli_cpu_lat_t idx = get_sli_cpu_lat_type(delay);

    if (in_iowait(task)) {
        sli_cpu->sli.cpu_lats[SLI_CPU_IOWAIT].cnt[idx]++;
        sli_cpu->sli.lat_ns[SLI_CPU_IOWAIT] += delay;
    } else {
        sli_cpu->sli.cpu_lats[SLI_CPU_BLOCK].cnt[idx]++;
        sli_cpu->sli.lat_ns[SLI_CPU_BLOCK] += delay;
    }

    report_sli_cpu(ctx, sli_cpu);
    return 0;
}

KRAWTRACE(sched_switch, bpf_raw_tracepoint_args)
{
    u64 delay = 0, now = 0;
    enum sli_cpu_lat_t idx;
    struct task_struct *next_task = (struct task_struct *)ctx->args[2];

    if (is_filter_task(next_task)) {
        return 0;
    }

    struct sli_cpu_obj_s* sli_cpu = get_sli_cpu(next_task);
    if (sli_cpu == NULL) {
        return -1;
    }

    now = bpf_ktime_get_ns();

    struct task_sched_s *sched = get_task_sched(next_task);
    if (sched == NULL) {
        return -1;
    }
    u64 new_run_delay = BPF_CORE_READ(next_task, sched_info.run_delay);

    if (sched->last_run_delay == 0) {
        sched->last_run_delay = new_run_delay;
    } else if (new_run_delay > sched->last_run_delay) {
        delay = new_run_delay - sched->last_run_delay;
        sched->last_run_delay = new_run_delay;
        idx = get_sli_cpu_lat_type(delay);

        sli_cpu->sli.cpu_lats[SLI_CPU_RUNDELAY].cnt[idx]++;
        sli_cpu->sli.lat_ns[SLI_CPU_RUNDELAY] += delay;

        sched->is_report = 1;
    }

    u32 task_switch = _(next_task->nvcsw) + _(next_task->nivcsw);
    u64 utime = _(next_task->utime);
    if (!sched->kernel_exec_start
        || sched->task_switch != task_switch
        || sched->utime != utime) {

        goto end;
    }
    if (now > sched->kernel_exec_start) {
        delay = now - sched->kernel_exec_start;
        idx = get_sli_cpu_lat_type(delay);

        sli_cpu->sli.cpu_lats[SLI_CPU_LONGSYS].cnt[idx]++;
        sli_cpu->sli.lat_ns[SLI_CPU_LONGSYS] += delay;
        sched->is_report = 1;
        goto end2;
    }

end:
    if (sched->is_report) {
        sched->is_report = 0;
        report_sli_cpu(ctx, sli_cpu);
    }

end2:
    sched->utime = utime;
    sched->kernel_exec_start = now;
    sched->task_switch = task_switch;
    return 0;
}

