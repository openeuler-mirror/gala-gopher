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

#ifndef __OUTPUT_PROC_H__
#define __OUTPUT_PROC_H__

#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "task.h"
#include "args_map.h"
#include "proc.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} g_proc_output SEC(".maps");

#define IS_PROC_TMOUT(stats_ts, ts, period, type, tmout) \
    do \
    { \
        if (((ts) > (stats_ts)->ts_##type) && (((ts) - (stats_ts)->ts_##type) >= period)) { \
            (stats_ts)->ts_##type = (ts); \
            tmout = 1; \
        } else { \
            tmout = 0; \
        } \
    } while (0)

static __always_inline __maybe_unused char is_proc_tmout(struct proc_data_s *proc, u32 flags)
{
    char tmout;
    u64 ts = bpf_ktime_get_ns();
    u64 period = get_period();

    struct proc_ts_s *stats_ts = &(proc->stats_ts);

    if (flags & TASK_PROBE_SYSCALL) {
        IS_PROC_TMOUT(stats_ts, ts, period, syscall, tmout);
    } else if (flags & TASK_PROBE_IO_SYSCALL) {
        IS_PROC_TMOUT(stats_ts, ts, period, syscall_io, tmout);
    } else if (flags & TASK_PROBE_NET_SYSCALL) {
        IS_PROC_TMOUT(stats_ts, ts, period, syscall_net, tmout);
    } else if (flags & TASK_PROBE_SCHED_SYSCALL) {
        IS_PROC_TMOUT(stats_ts, ts, period, syscall_sched, tmout);
    } else if (flags & TASK_PROBE_FORK_SYSCALL) {
        IS_PROC_TMOUT(stats_ts, ts, period, syscall_fork, tmout);
    } else if (flags & TASK_PROBE_EXT4_OP) {
        IS_PROC_TMOUT(stats_ts, ts, period, ext4_op, tmout);
    } else if (flags & TASK_PROBE_OVERLAY_OP) {
        IS_PROC_TMOUT(stats_ts, ts, period, overlay_op, tmout);
    } else if (flags & TASK_PROBE_TMPFS_OP) {
        IS_PROC_TMOUT(stats_ts, ts, period, tmpfs_op, tmout);
    } else if (flags & TASK_PROBE_PAGE_OP) {
        IS_PROC_TMOUT(stats_ts, ts, period, page, tmout);
    } else if (flags & TASK_PROBE_IO) {
        IS_PROC_TMOUT(stats_ts, ts, period, io, tmout);
    } else if (flags & TASK_PROBE_CPU) {
        IS_PROC_TMOUT(stats_ts, ts, period, cpu, tmout);
    } else if (flags & TASK_PROBE_IOCTL_SYSCALL) {
        IS_PROC_TMOUT(stats_ts, ts, period, syscall_ioctl, tmout);
    } else {
        tmout = 0;
    }

    return tmout;
}

static __always_inline __maybe_unused void reset_proc_stats(struct proc_data_s *proc, u32 flags)
{
    if (flags & TASK_PROBE_SYSCALL) {
        proc->syscall.failed = 0;
        proc->syscall.last_syscall_id = 0;
        proc->syscall.last_ret_code = 0;
    } else if (flags & TASK_PROBE_IO_SYSCALL) {
        proc->syscall.ns_mount = 0;
        proc->syscall.ns_umount = 0;
        proc->syscall.ns_read = 0;
        proc->syscall.ns_write = 0;
        proc->syscall.ns_fsync = 0;
    } else if (flags & TASK_PROBE_NET_SYSCALL) {
        proc->syscall.ns_sendmsg = 0;
        proc->syscall.ns_recvmsg = 0;
    } else if (flags & TASK_PROBE_SCHED_SYSCALL) {
        proc->syscall.ns_sched_yield = 0;
        proc->syscall.ns_futex = 0;
        proc->syscall.ns_epoll_wait = 0;
        proc->syscall.ns_epoll_pwait = 0;
   } else if (flags & TASK_PROBE_FORK_SYSCALL) {
        proc->syscall.ns_fork = 0;
        proc->syscall.ns_vfork = 0;
        proc->syscall.ns_clone = 0;
    } else if (flags & TASK_PROBE_EXT4_OP) {
        __builtin_memset(&(proc->op_ext4), 0x0, sizeof(proc->op_ext4));
    } else if (flags & TASK_PROBE_OVERLAY_OP) {
        __builtin_memset(&(proc->op_overlay), 0x0, sizeof(proc->op_overlay));
    } else if (flags & TASK_PROBE_TMPFS_OP) {
        __builtin_memset(&(proc->op_tmpfs), 0x0, sizeof(proc->op_tmpfs));
    } else if (flags & TASK_PROBE_PAGE_OP) {
        __builtin_memset(&(proc->page_op), 0x0, sizeof(proc->page_op));
    } else if (flags & TASK_PROBE_IO) {
        __builtin_memset(&(proc->proc_io), 0x0, sizeof(proc->proc_io));
    } else if (flags & TASK_PROBE_CPU) {
        __builtin_memset(&(proc->proc_cpu), 0x0, sizeof(proc->proc_cpu));
    } else if (flags & TASK_PROBE_IOCTL_SYSCALL) {
        proc->syscall.ns_ioctl = 0;
        proc->syscall.ioctl_fd = 0;
        proc->syscall.ioctl_cmd = 0;
    }
}

static __always_inline __maybe_unused void report_proc(void *ctx, struct proc_data_s *proc, u32 flags)
{
    if (!is_proc_tmout(proc, flags)) {
        return;
    }

    proc->flags = flags;
    (void)bpfbuf_output(ctx, &g_proc_output, proc, sizeof(struct proc_data_s));

    proc->flags = 0;
    reset_proc_stats(proc, flags);
}

#endif
