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
    __uint(value_size, sizeof(syscall_m_stash_val_t));
    __uint(max_entries, MAX_SIZE_OF_STASH_EVENT);
} syscall_stash_map SEC(".maps");

static __always_inline void init_syscall_data(syscall_data_t *scd, syscall_m_enter_t *sce,
                                              syscall_m_meta_t *scm, void *ctx)
{
    scd->nr = scm->nr;
    scd->start_time = sce->start_time;
    scd->end_time = sce->end_time;
    scd->duration = scd->end_time - scd->start_time;
    scd->count = 1;

    if (scm->flag & SYSCALL_FLAG_FD) {
        scd->ext_info.fd_info.fd = sce->ext_info.fd_info.fd;
    }

    // stack trace
    if (scm->flag & SYSCALL_FLAG_STACK) {
        scd->stack_info.uid = bpf_get_stackid(ctx, &stack_map, USER_STACKID_FLAGS);
    }

    if (scm->nr == SYSCALL_FUTEX_ID) {
        scd->ext_info.futex_info.op = sce->ext_info.futex_info.op;
    }
}

static __always_inline void init_syscall_event_common(trace_event_data_t *evt_data, u64 timestamp)
{
    u64 ptid = bpf_get_current_pid_tgid();

    evt_data->type = EVT_TYPE_SYSCALL;
    evt_data->timestamp = timestamp;
    evt_data->pid = (u32)ptid;
    evt_data->tgid = (u32)(ptid >> INT_LEN);
    (void)bpf_get_current_comm(evt_data->comm, sizeof(evt_data->comm));
}

static __always_inline void emit_incomming_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm, void *ctx)
{
    trace_event_data_t evt_data = {0};

    init_syscall_event_common(&evt_data, sce->start_time);
    init_syscall_data(&evt_data.syscall_d, sce, scm, ctx);

    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &evt_data, sizeof(evt_data));
}

static __always_inline void emit_syscall_event_stashed(syscall_m_stash_val_t *sc_stash, void *ctx)
{
    trace_event_data_t evt_data = {0};

    init_syscall_event_common(&evt_data, sc_stash->start_time);
    evt_data.syscall_d = (syscall_data_t)(*sc_stash);

    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &evt_data, sizeof(evt_data));
}

static __always_inline void stash_incomming_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm, void *ctx)
{
    syscall_m_stash_key_t sc_stash_key = {0};
    syscall_m_stash_val_t sc_stash = {0};

    sc_stash_key.pid = sce->pid;
    sc_stash_key.nr = scm->nr;
    init_syscall_data((syscall_data_t *)&sc_stash, sce, scm, ctx);
    bpf_map_update_elem(&syscall_stash_map, &sc_stash_key, &sc_stash, BPF_ANY);
}

static __always_inline void process_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm, void *ctx)
{
    syscall_m_stash_key_t sc_stash_key = {0};
    syscall_m_stash_val_t *sc_stash;

    sc_stash_key.pid = sce->pid;
    sc_stash_key.nr = scm->nr;
    sc_stash = (syscall_m_stash_val_t *)bpf_map_lookup_elem(&syscall_stash_map, &sc_stash_key);

    if (sc_stash == (void *)0) {
        if (can_emit(sce->start_time, sce->end_time)) {
            emit_incomming_syscall_event(sce, scm, ctx);
        } else {
            stash_incomming_syscall_event(sce, scm, ctx);
        }
        return;
    }

    if (can_emit(sc_stash->start_time, sce->end_time)) {
        emit_syscall_event_stashed(sc_stash, ctx);
        (void)bpf_map_delete_elem(&syscall_stash_map, &sc_stash_key);

        if (can_emit(sce->start_time, sce->end_time)) {
            emit_incomming_syscall_event(sce, scm, ctx);
        } else {
            stash_incomming_syscall_event(sce, scm, ctx);
        }
    } else {
        // merge event
        sc_stash->end_time = sce->end_time;
        sc_stash->count++;
        sc_stash->duration += sce->end_time - sce->start_time;
    }
}

#define KPROBE_SYSCALL_ENTER(arch, name) \
    KPROBE(arch##name, pt_regs) \
    { \
        syscall_m_enter_t sce; \
        profiling_setting_t *setting; \
        struct pt_regs *regs; \
        \
        setting = get_tp_setting(); \
        if (setting == (void *)0) { \
            return 0; \
        } \
        if (!is_proc_thrd_enabled(setting)) { \
            return 0; \
        } \
        \
        __builtin_memset(&sce, 0, sizeof(sce)); \
        sce.pid = (u32)bpf_get_current_pid_tgid(); \
        sce.start_time = bpf_ktime_get_ns(); \
        regs = (struct pt_regs *)PT_REGS_PARM1(ctx); \
        set_syscall_params_##name(&sce, regs); \
        (void)bpf_map_update_elem(&syscall_enter_map, &sce.pid, &sce, BPF_ANY); \
        return 0; \
    }

#define KPROBE_SYSCALL_EXIT(arch, name) \
    KRETPROBE(arch##name, pt_regs) \
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
        if (sce->end_time < sce->start_time + NSEC_PER_MSEC) { \
            (void)bpf_map_delete_elem(&syscall_enter_map, &pid); \
            return 0; \
        } \
        \
        __builtin_memset(&scm, 0, sizeof(scm)); \
        set_syscall_meta_##name(&scm); \
        process_syscall_event(sce, &scm, ctx); \
        (void)bpf_map_delete_elem(&syscall_enter_map, &pid); \
        return 0; \
    }

#define KPROBE_SYSCALL(arch, name) \
    KPROBE_SYSCALL_ENTER(arch, name); \
    KPROBE_SYSCALL_EXIT(arch, name)

#define SET_SYSCALL_PARAMS(name) static __always_inline void \
    set_syscall_params_##name(syscall_m_enter_t *sce, struct pt_regs *regs)

#define SET_SYSCALL_META(name) static __always_inline void set_syscall_meta_##name(syscall_m_meta_t *scm)

#endif