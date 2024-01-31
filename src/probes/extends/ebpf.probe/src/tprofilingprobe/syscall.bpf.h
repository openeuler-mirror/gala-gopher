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
 * Author: algorithmofdish
 * Create: 2023-04-03
 * Description: the bpf-side prog of thread profiling probe
 ******************************************************************************/
#ifndef __SYSCALL_BPF_H__
#define __SYSCALL_BPF_H__
#include "bpf.h"
#include "py_stack_bpf.h"
#include "stack.h"
#include "tprofiling.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(syscall_m_enter_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} syscall_enter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(syscall_m_stash_key_t));
    __uint(value_size, sizeof(trace_event_data_t));
    __uint(max_entries, MAX_SIZE_OF_STASH_EVENT);
} syscall_stash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(trace_event_data_t));
    __uint(max_entries, 1);
} syscall_stash_heap SEC(".maps");

static __always_inline trace_event_data_t *new_syscall_trace_event()
{
    u32 zero = 0;
    trace_event_data_t *evt;

    evt = (trace_event_data_t *)bpf_map_lookup_elem(&syscall_stash_heap, &zero);
    return evt;
}

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
    struct stats_fd_elem elem = {0};
    struct stats_fd *stats_fd = &scd->stats.stats_fd;
    int idx;

    elem.fd = sce->ext_info.fd_info.fd;
    elem.duration = sce->end_time - sce->start_time;
    if (set_ino_of_fd(&elem)) {
        return;
    }
#pragma unroll
    STATS_APPEND_TO_SORTED(stats_fd->fds, stats_fd->num, STATS_TOP_FD_MAX_NUM, elem, idx)
    return;
}

static __always_inline void stats_append_futex(syscall_data_t *scd, syscall_m_enter_t *sce)
{
    struct stats_futex_elem elem = {0};
    struct stats_futex *stats_futex = &scd->stats.stats_futex;
    int idx;

    elem.op = sce->ext_info.futex_info.op;
    elem.duration = sce->end_time - sce->start_time;
#pragma unroll
    STATS_APPEND_TO_SORTED(stats_futex->ops, stats_futex->num, STATS_TOP_FUTEX_MAX_NUM, elem, idx)
    return;
}

static __always_inline int get_py_stack_id(int tgid)
{
    struct py_proc_data *py_proc_data;
    struct py_sample *py_sample;
    u64 py_stack_id = 0;

    py_proc_data = (struct py_proc_data *)bpf_map_lookup_elem(&py_proc_map, &tgid);

    if (!py_proc_data) {
        return 0;
    }
    py_sample = get_py_sample();
    if (!py_sample) {
        return 0;
    }

    py_sample->cpu_id = bpf_get_smp_processor_id();
    if (get_py_stack(py_sample, py_proc_data) != 0) {
        return 0;
    }

    py_stack_id = py_sample->py_stack_counter * py_sample->nr_cpus + py_sample->cpu_id + 1;
    //避免出现 py_stack_id为 0 的现象影响后续判断
    if (bpf_map_update_elem(&py_stack_cached, &py_stack_id, &py_sample->event.py_stack, BPF_ANY)) {
        return 0;
    }
    py_sample->py_stack_counter++;

    return py_stack_id;
}

static __always_inline void stats_append_stack(syscall_data_t *scd, syscall_m_enter_t *sce, void *ctx)
{
    struct stats_stack *stats_stack = &scd->stats.stats_stack;
    struct stats_stack_elem *stack_elem;
    int uid;
    int tgid;

    if (stats_stack->num >= STATS_STACK_MAX_NUM) {
        return;
    }
    uid = bpf_get_stackid(ctx, &stack_map, USER_STACKID_FLAGS);
    if (uid < 0) {
        return;
    }
    stack_elem = &stats_stack->stacks[stats_stack->num & (STATS_STACK_MAX_NUM_MASK - 1)];
    stack_elem->stack.uid = uid;
    tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);
    stack_elem->stack.pyid = get_py_stack_id(tgid);
    stack_elem->duration = sce->end_time - sce->start_time;
    stats_stack->num++;
    return;
}

static __always_inline void append_stats_info(syscall_data_t *scd, syscall_m_enter_t *sce,
    syscall_m_meta_t *scm, void *ctx)
{
    if (scm->flag & SYSCALL_FLAG_FD) {
        stats_append_fd(scd, sce);
    }

    // stack trace
    if (scm->flag & SYSCALL_FLAG_STACK) {
        stats_append_stack(scd, sce, ctx);
    }

    if (scm->nr == SYSCALL_FUTEX_ID) {
        stats_append_futex(scd, sce);
    }
}

static __always_inline void init_syscall_data(syscall_data_t *scd, syscall_m_enter_t *sce,
    syscall_m_meta_t *scm, void *ctx)
{
    scd->nr = scm->nr;
    scd->start_time = sce->start_time;
    scd->end_time = sce->end_time;
    scd->duration = scd->end_time - scd->start_time;
    scd->count = 1;
    scd->stats.stats_stack.num = 0;
    if (scm->nr == SYSCALL_FUTEX_ID) {
        scd->stats.stats_futex.num = 0;
    }
    if (scm->flag & SYSCALL_FLAG_FD) {
        scd->stats.stats_fd.num = 0;
    }
    append_stats_info(scd, sce, scm, ctx);
    scd->last_stat_time = sce->end_time;
}

static __always_inline void init_syscall_event_common(trace_event_data_t *evt_data)
{
    u64 ptid = bpf_get_current_pid_tgid();

    evt_data->type = EVT_TYPE_SYSCALL;
    evt_data->pid = (u32)ptid;
    evt_data->tgid = (u32)(ptid >> INT_LEN);
    (void)bpf_get_current_comm(evt_data->comm, sizeof(evt_data->comm));
}

static __always_inline trace_event_data_t *create_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm,
    void *ctx)
{
    trace_event_data_t *evt_data;

    evt_data = new_syscall_trace_event();
    if (!evt_data) {
        return NULL;
    }
    init_syscall_event_common(evt_data);
    init_syscall_data(&evt_data->syscall_d, sce, scm, ctx);

    return evt_data;
}

static __always_inline void emit_incomming_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm, void *ctx)
{
    trace_event_data_t *evt_data = create_syscall_event(sce, scm, ctx);

    if (!evt_data) {
        return;
    }
    bpfbuf_output(ctx, &event_map, (void *)evt_data, sizeof(trace_event_data_t));
}

static __always_inline void emit_syscall_event_stashed(trace_event_data_t *evt_data, void *ctx)
{
    bpfbuf_output(ctx, &event_map, (void *)evt_data, sizeof(trace_event_data_t));
}

static __always_inline void stash_incomming_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm, void *ctx)
{
    syscall_m_stash_key_t sc_stash_key = {0};
    trace_event_data_t *evt_data = create_syscall_event(sce, scm, ctx);

    if (!evt_data) {
        return;
    }
    sc_stash_key.pid = sce->pid;
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

    if (is_stats_triggered(scd->last_stat_time, sce->end_time)) {
        append_stats_info(scd, sce, scm, ctx);
        scd->last_stat_time = sce->end_time;
    }
}

static __always_inline void process_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm, void *ctx)
{
    syscall_m_stash_key_t sc_stash_key = {0};
    trace_event_data_t *evt_data;

    sc_stash_key.pid = sce->pid;
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
        sce.pid = (u32)bpf_get_current_pid_tgid(); \
        sce.start_time = bpf_ktime_get_ns(); \
        __SET_##probe_type##_SYSCALL_PARAMS(name, sce, ctx); \
        (void)bpf_map_update_elem(&syscall_enter_map, &sce.pid, &sce, BPF_ANY); \
        return 0; \
    } while(0)

#define __PROBE_SYSCALL_EXIT_BODY(name) \
    do \
    { \
        u32 pid = (u32)bpf_get_current_pid_tgid(); \
        syscall_m_enter_t *sce; \
        syscall_m_meta_t scm; \
        \
        sce = (syscall_m_enter_t *)bpf_map_lookup_elem(&syscall_enter_map, &pid); \
        if (sce == (void *)0) { \
            return 0; \
        } \
        \
        sce->end_time = bpf_ktime_get_ns(); \
        if (sce->end_time < sce->start_time + MIN_EXEC_DURATION) { \
            (void)bpf_map_delete_elem(&syscall_enter_map, &pid); \
            return 0; \
        } \
        \
        __builtin_memset(&scm, 0, sizeof(scm)); \
        set_syscall_meta_##name(&scm); \
        process_syscall_event(sce, &scm, ctx); \
        (void)bpf_map_delete_elem(&syscall_enter_map, &pid); \
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
