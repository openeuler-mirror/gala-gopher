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

struct task_mem_s {
    u64 start_ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(cpu_cgrp_inode_t));
    __uint(value_size, sizeof(struct sli_mem_obj_s));
    __uint(max_entries, 1000);
} sli_mem_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct task_struct *));
    __uint(value_size, sizeof(struct task_mem_s));
    __uint(max_entries, 1000);
} task_mem_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} sli_mem_channel_map SEC(".maps");

static __always_inline struct sli_mem_obj_s* lkup_sli_mem(cpu_cgrp_inode_t ino)
{
    return (struct sli_mem_obj_s *)bpf_map_lookup_elem(&sli_mem_map, &ino);
}

static __always_inline struct sli_mem_obj_s* get_sli_mem(struct task_struct *task)
{
    cpu_cgrp_inode_t ino;
    if (get_current_cpuacct_ino(&ino, task)) {
        return NULL;
    }

    return lkup_sli_mem(ino);
}

static __always_inline void report_sli_mem(void *ctx, struct sli_mem_obj_s* sli_mem, u64 now)
{
    if (is_report_tmout(&(sli_mem->last_report))) {
        (void)bpfbuf_output(ctx,
                            &sli_mem_channel_map,
                            sli_mem,
                            sizeof(struct sli_mem_obj_s));
        sli_mem->last_report = now;
        __builtin_memset(&(sli_mem->sli), 0, sizeof(struct sli_mem_s));
    }
}

static __always_inline char is_filter_task(struct task_struct *task)
{
    unsigned int flags = BPF_CORE_READ(task, flags);
    return (char)((flags & PF_IDLE) || (flags & PF_KTHREAD));
}

static __always_inline int mem_sli_start(struct task_struct *task, void *ctx)
{
    if (is_filter_task(task)) {
        return 0;
    }

    struct task_mem_s mem = {0};
    mem.start_ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&task_mem_map, &task, &mem, BPF_ANY);
    return 0;
}

static __always_inline int mem_sli_end(struct task_struct *task, enum sli_mem_t type, void *ctx)
{
    struct task_mem_s* task_mem = bpf_map_lookup_elem(&task_mem_map, &task);
    if (task_mem) {
        u64 now = bpf_ktime_get_ns();
        if (now > task_mem->start_ts) {
            struct sli_mem_obj_s* sli_mem = get_sli_mem(task);
            if (sli_mem == NULL) {
                goto end;
            }

            u64 delay = now - task_mem->start_ts;
            enum sli_mem_lat_t idx = get_sli_mem_lat_type(delay);

            sli_mem->sli.mem_lats[type].cnt[idx]++;
            sli_mem->sli.lat_ns[type] += delay;

            report_sli_mem(ctx, sli_mem, now);
        }
    }
end:
    bpf_map_delete_elem(&task_mem_map, &task);
    return 0;
}

KPROBE(mem_cgroup_handle_over_high, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_start(task, ctx);
}

KRETPROBE(mem_cgroup_handle_over_high, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_end(task, SLI_MEM_RECLAIM, ctx);
}

KRAWTRACE(mm_vmscan_memcg_reclaim_begin, bpf_raw_tracepoint_args)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_start(task, ctx);
}

KRAWTRACE(mm_vmscan_memcg_reclaim_end, bpf_raw_tracepoint_args)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_end(task, SLI_MEM_RECLAIM, ctx);
}

KPROBE(do_swap_page, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_start(task, ctx);
}

KRETPROBE(do_swap_page, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_end(task, SLI_MEM_SWAPIN, ctx);
}

KPROBE(try_to_compact_pages, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_start(task, ctx);
}

KRETPROBE(try_to_compact_pages, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_end(task, SLI_MEM_COMPACT, ctx);
}

