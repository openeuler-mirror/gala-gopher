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

#ifndef __SYSCALL_BPF_H__
#define __SYSCALL_BPF_H__
#include "bpf.h"
#include "stack.h"
#include "tprofiling.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(syscall_m_enter_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} syscall_enter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(syscall_m_stash_key_t));
    __uint(value_size, sizeof(trace_event_data_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);    // 每个线程最多缓存一个系统调用事件
} syscall_stash_map SEC(".maps");

static __always_inline int set_ino_of_fd(struct stats_fd_elem *elem)
{
    struct task_struct *task;
    struct file *f;
    struct file **ff;
    unsigned int max_fds;
    struct inode *fi;
    int fd = elem->fd;

    task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -1;
    }
    ff = BPF_CORE_READ(task, files, fdt, fd);
    max_fds = BPF_CORE_READ(task, files, fdt, max_fds);
    if (fd < 0 || fd >= max_fds) {
        return -1;
    }

    bpf_core_read(&f, sizeof(struct file *), (struct file *)(ff + fd));
    if (!f) {
        return -1;
    }

    fi = BPF_CORE_READ(f, f_inode);
    elem->ino = BPF_CORE_READ(fi, i_ino);
    elem->imode = BPF_CORE_READ(fi, i_mode);

    return 0;
}

#define STATS_APPEND_TO_SORTED(array, len, size, elem, idx) \
    for (int i = 0; i < size; i++) { \
        idx = size - 1 - i; \
        if (idx >= (len)) { \
            continue; \
        } \
        if ((elem).duration <= (array)[idx].duration) { \
            idx++; \
            break; \
        } \
        if (idx < size - 1) { \
            (array)[idx + 1] = (array)[idx]; \
        } \
    } \
    if (idx < size) { \
        (array)[idx] = (elem); \
        if (idx + 1 > (len)) { \
            (len) = idx + 1; \
        } \
    }

static __always_inline void stats_append_fd(syscall_data_t *scd, syscall_m_enter_t *sce)
{
    struct stats_fd_elem *elem = &scd->stats.stats_fd;

    elem->fd = sce->ext_info.fd_info.fd;
    elem->duration = sce->end_time - sce->start_time;
    if (set_ino_of_fd(elem)) {
        return;
    }
}

static __always_inline void stats_append_futex(syscall_data_t *scd, syscall_m_enter_t *sce)
{
    struct stats_futex_elem *elem = &scd->stats.stats_futex;

    elem->op = sce->ext_info.futex_info.op;
    elem->duration = sce->end_time - sce->start_time;
}

static __always_inline void stats_append_ioctl(syscall_data_t *scd, syscall_m_enter_t *sce)
{
    struct stats_ioctl_elem *elem = &scd->stats.stats_ioctl;

    elem->cmd = sce->ext_info.ioctl_info.cmd;
    elem->duration = sce->end_time - sce->start_time;
}

static __always_inline void append_stats_info(syscall_data_t *scd, syscall_m_enter_t *sce,
    syscall_m_meta_t *scm, void *ctx)
{
    if (scm->flag & SYSCALL_FLAG_FD) {
        stats_append_fd(scd, sce);
    }

    // stack trace
    if (scm->flag & SYSCALL_FLAG_STACK) {
        stats_append_stack(&scd->stats.stats_stack, (sce->end_time - sce->start_time), ctx);
    }

    if (scm->nr == SYSCALL_FUTEX_ID) {
        stats_append_futex(scd, sce);
    }

    if (scm->nr == SYSCALL_IOCTL_ID) {
        stats_append_ioctl(scd, sce);
    }
}

static __always_inline void init_syscall_data(syscall_data_t *scd, syscall_m_enter_t *sce,
    syscall_m_meta_t *scm, char is_stat, void *ctx)
{
    scd->nr = scm->nr;
    scd->start_time = sce->start_time;
    scd->end_time = sce->end_time;
    scd->duration = scd->end_time - scd->start_time;
    scd->count = 1;

    __builtin_memset(&scd->stats.stats_stack, 0, sizeof(struct stats_stack_elem));
    if (scm->nr == SYSCALL_FUTEX_ID) {
        scd->stats.stats_futex.op = -1;
    }
    if (scm->nr == SYSCALL_IOCTL_ID) {
        scd->stats.stats_ioctl.cmd = 0;
    }
    if (scm->flag & SYSCALL_FLAG_FD) {
        scd->stats.stats_fd.fd = 0;
    }
    if (is_stat) {
        append_stats_info(scd, sce, scm, ctx);
    }
}

static __always_inline trace_event_data_t *create_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm,
    char is_stat, void *ctx)
{
    trace_event_data_t *evt_data;

    evt_data = new_trace_event();
    if (!evt_data) {
        return NULL;
    }
    init_trace_event_common(evt_data, EVT_TYPE_SYSCALL);
    init_syscall_data(&evt_data->syscall_d, sce, scm, is_stat, ctx);

    return evt_data;
}

static __always_inline void emit_incomming_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm, void *ctx)
{
    trace_event_data_t *evt_data = create_syscall_event(sce, scm, 1, ctx);
    void *cur_event_map;

    if (!evt_data) {
        return;
    }
    cur_event_map = bpf_get_current_event_map();
    if (cur_event_map) {
        bpfbuf_output(ctx, cur_event_map, (void *)evt_data, sizeof(trace_event_data_t));
    }
}

static __always_inline void emit_syscall_event_stashed(trace_event_data_t *evt_data, void *ctx)
{
    void *cur_event_map;

    cur_event_map = bpf_get_current_event_map();
    if (cur_event_map) {
        bpfbuf_output(ctx, cur_event_map, (void *)evt_data, sizeof(trace_event_data_t));
    }
}

static __always_inline void stash_incomming_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm, void *ctx)
{
    syscall_m_stash_key_t sc_stash_key = {0};
    trace_event_data_t *evt_data = create_syscall_event(sce, scm, 0, ctx);

    if (!evt_data) {
        return;
    }
    sc_stash_key.pid = (u32)sce->ptid;
    sc_stash_key.nr = scm->nr;
    bpf_map_update_elem(&syscall_stash_map, &sc_stash_key, evt_data, BPF_ANY);
}

static __always_inline void merge_incomming_syscall_event(trace_event_data_t *evt_data, syscall_m_enter_t *sce,
    syscall_m_meta_t *scm, void *ctx)
{
    syscall_data_t *scd = &evt_data->syscall_d;

    scd->count++;
    scd->duration += sce->end_time - sce->start_time;
    scd->end_time = sce->end_time;
}

static __always_inline void process_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm, void *ctx)
{
    syscall_m_stash_key_t sc_stash_key = {0};
    trace_event_data_t *evt_data;

    sc_stash_key.pid = (u32)sce->ptid;
    sc_stash_key.nr = scm->nr;
    evt_data = (trace_event_data_t *)bpf_map_lookup_elem(&syscall_stash_map, &sc_stash_key);

    if (evt_data == (void *)0) {
        if (can_emit(sce->start_time, sce->end_time)) {
            emit_incomming_syscall_event(sce, scm, ctx);
        } else {
            stash_incomming_syscall_event(sce, scm, ctx);
        }
        return;
    }

    if (can_emit(evt_data->syscall_d.start_time, sce->end_time)) {
        emit_syscall_event_stashed(evt_data, ctx);
        (void)bpf_map_delete_elem(&syscall_stash_map, &sc_stash_key);

        if (can_emit(sce->start_time, sce->end_time)) {
            emit_incomming_syscall_event(sce, scm, ctx);
        } else {
            stash_incomming_syscall_event(sce, scm, ctx);
        }
    } else {
        merge_incomming_syscall_event(evt_data, sce, scm, ctx);
    }
}

#define __PROBE_SYSCALL_ENTER_BODY(name, probe_type) \
    do \
    { \
        syscall_m_enter_t sce; \
        \
        if (!is_proc_thrd_enabled()) { \
            return 0; \
        } \
        \
        __builtin_memset(&sce, 0, sizeof(sce)); \
        sce.ptid = bpf_get_current_pid_tgid(); \
        sce.start_time = bpf_ktime_get_ns(); \
        __SET_##probe_type##_SYSCALL_PARAMS(name, sce, ctx); \
        (void)bpf_map_update_elem(&syscall_enter_map, &sce.ptid, &sce, BPF_ANY); \
        return 0; \
    } while(0)

#define __PROBE_SYSCALL_EXIT_BODY(name) \
    do \
    { \
        u64 ptid = bpf_get_current_pid_tgid(); \
        syscall_m_enter_t *sce; \
        syscall_m_meta_t scm; \
        trace_setting_t *setting; \
        \
        sce = (syscall_m_enter_t *)bpf_map_lookup_elem(&syscall_enter_map, &ptid); \
        if (sce == (void *)0) { \
            return 0; \
        } \
        setting = get_trace_setting(); \
        if (setting == (void *)0) { \
            return 0; \
        } \
        \
        sce->end_time = bpf_ktime_get_ns(); \
        if (sce->end_time < sce->start_time + setting->min_exec_dur) { \
            (void)bpf_map_delete_elem(&syscall_enter_map, &ptid); \
            return 0; \
        } \
        \
        __builtin_memset(&scm, 0, sizeof(scm)); \
        scm.nr = sce->nr; \
        set_syscall_meta_##name(&scm); \
        process_syscall_event(sce, &scm, ctx); \
        (void)bpf_map_delete_elem(&syscall_enter_map, &ptid); \
        return 0; \
    } while(0)

#define SET_SYSCALL_PARAMS(name) static __always_inline void \
    set_syscall_params_##name(syscall_m_enter_t *sce, struct pt_regs *regs)

#define SET_SYSCALL_META(name) static __always_inline void set_syscall_meta_##name(syscall_m_meta_t *scm)

#define __SET_KP_SYSCALL_PARAMS(name, sce, ctx) \
    do \
    { \
        struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx); \
        set_syscall_params_##name(&sce, regs); \
    } while(0)

#define KPROBE_SYSCALL_ENTER(arch, name) \
    KPROBE(arch##name, pt_regs) \
    { \
        __PROBE_SYSCALL_ENTER_BODY(name, KP); \
    }

#define KPROBE_SYSCALL_EXIT(arch, name) \
    KRETPROBE(arch##name, pt_regs) \
    { \
        __PROBE_SYSCALL_EXIT_BODY(name); \
    }

#define KPROBE_SYSCALL(arch, name) \
    KPROBE_SYSCALL_ENTER(arch, name); \
    KPROBE_SYSCALL_EXIT(arch, name)

#define __SET_TP_SYSCALL_PARAMS(name, sce, ctx) set_tp_syscall_params_##name(&sce, ctx)

#define TP_SYSCALL_ENTER(name) \
    SEC("tracepoint/syscalls/sys_enter_" #name) \
    int bpf_tp_enter_##name(syscalls_enter_##name##_args_t *ctx) \
    { \
        __PROBE_SYSCALL_ENTER_BODY(name, TP); \
    }

#define TP_SYSCALL_EXIT(name) \
    SEC("tracepoint/syscalls/sys_exit_" #name) \
    int bpf_tp_exit_##name(syscalls_exit_##name##_args_t *ctx) \
    { \
        __PROBE_SYSCALL_EXIT_BODY(name); \
    }

#define SET_TP_SYSCALL_PARAMS(name) static __always_inline void \
    set_tp_syscall_params_##name(syscall_m_enter_t *sce, syscalls_enter_##name##_args_t *ctx)

#define TP_SYSCALL(name) \
    TP_SYSCALL_ENTER(name); \
    TP_SYSCALL_EXIT(name)

#endif
