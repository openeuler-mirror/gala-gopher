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
#include "task.h"
#include "proc_map.h"
#include "output_proc.h"

char g_linsence[] SEC("license") = "GPL";

static __always_inline void store_reclaim_start_ts(void)
{
    struct proc_data_s *proc;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return;
    }

    proc->page_op.reclaim_start_ts = bpf_ktime_get_ns();
}

static __always_inline void update_reclaim_ns(void *ctx)
{
    struct proc_data_s *proc;
    u64 ts = bpf_ktime_get_ns(), delta = 0;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return;
    }

    if (proc->page_op.reclaim_start_ts == 0) {
        return;
    }

    if (ts > proc->page_op.reclaim_start_ts) {
        delta = ts - proc->page_op.reclaim_start_ts;
    }

    proc->page_op.reclaim_start_ts = 0;
    if (delta > proc->page_op.reclaim_ns) {
        proc->page_op.reclaim_ns = delta;
        report_proc(ctx, proc, TASK_PROBE_PAGE_OP);
    }
}

KRAWTRACE(mm_vmscan_direct_reclaim_begin, bpf_raw_tracepoint_args)
{
    store_reclaim_start_ts();
    return 0;
}

KRAWTRACE(mm_vmscan_direct_reclaim_end, bpf_raw_tracepoint_args)
{
    update_reclaim_ns(ctx);
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int bpf_trace_mm_vmscan_direct_reclaim_begin_func(struct trace_event_raw_mm_vmscan_direct_reclaim_begin_template *ctx)
{
    store_reclaim_start_ts();
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int bpf_trace_mm_vmscan_direct_reclaim_end_func(struct trace_event_raw_mm_vmscan_direct_reclaim_end_template *ctx)
{
    update_reclaim_ns(ctx);
    return 0;
}

#define KPROBE_PAGE_CACHE(func, field) \
    KPROBE(func, pt_regs) \
    { \
        u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN; \
        \
        struct proc_data_s* proc = get_proc_entry(proc_id); \
        if (proc == NULL) { \
            return 0; \
        } \
        \
        __sync_fetch_and_add(&(proc->page_op.count_##field), 1); \
        \
        report_proc(ctx, proc, TASK_PROBE_PAGE_OP); \
        return 0; \
    }

KPROBE_PAGE_CACHE(mark_page_accessed, access_pagecache)
KPROBE_PAGE_CACHE(mark_buffer_dirty, mark_buffer_dirty)
KPROBE_PAGE_CACHE(add_to_page_cache_lru, load_page_cache)
KPROBE_PAGE_CACHE(account_page_dirtied, mark_page_dirty)
KPROBE_PAGE_CACHE(folio_account_dirtied, mark_page_dirty)

