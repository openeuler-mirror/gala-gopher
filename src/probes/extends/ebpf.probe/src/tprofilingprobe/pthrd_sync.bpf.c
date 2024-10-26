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

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif
#define BPF_PROG_USER
#include "bpf.h"
#include "tprofiling.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(pthrd_m_key_t));
    __uint(value_size, sizeof(pthrd_m_enter_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} pthrd_enter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(pthrd_m_key_t));
    __uint(value_size, sizeof(trace_event_data_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} pthrd_stash_map SEC(".maps");

static __always_inline void init_pthrd_data(pthrd_data_t *pthrd_d, pthrd_m_enter_t *pthrd_enter, char is_stat, void *ctx)
{
    pthrd_d->start_time = pthrd_enter->start_time;
    pthrd_d->end_time = pthrd_enter->end_time;
    pthrd_d->duration = pthrd_enter->end_time - pthrd_enter->start_time;
    pthrd_d->count = 1;
    pthrd_d->id = pthrd_enter->key.id;
    __builtin_memset(&pthrd_d->stats_stack, 0, sizeof(struct stats_stack_elem));
    if (is_stat) {
        stats_append_stack(&pthrd_d->stats_stack, pthrd_d->duration, ctx);
    }
}

static __always_inline trace_event_data_t *create_pthrd_event(pthrd_m_enter_t *pthrd_enter, char is_stat, void *ctx)
{
    trace_event_data_t *evt_data;

    evt_data = new_trace_event();
    if (!evt_data) {
        return NULL;
    }
    init_trace_event_common(evt_data, EVT_TYPE_PTHREAD);
    init_pthrd_data(&evt_data->pthrd_d, pthrd_enter, is_stat, ctx);

    return evt_data;
}

static __always_inline void emit_incomming_pthrd_event(pthrd_m_enter_t *pthrd_enter, void *ctx)
{
    trace_event_data_t *evt_data = create_pthrd_event(pthrd_enter, 1, ctx);
    void *cur_event_map;

    if (!evt_data) {
        return;
    }
    cur_event_map = bpf_get_current_event_map();
    if (cur_event_map) {
        bpfbuf_output(ctx, cur_event_map, evt_data, sizeof(trace_event_data_t));
    }
}

static __always_inline void emit_pthrd_event_stashed(trace_event_data_t *evt_data, void *ctx)
{
    void *cur_event_map;

    cur_event_map = bpf_get_current_event_map();
    if (cur_event_map) {
        bpfbuf_output(ctx, cur_event_map, evt_data, sizeof(trace_event_data_t));
    }
}

static __always_inline void stash_incomming_pthrd_event(pthrd_m_enter_t *pthrd_enter, void *ctx)
{
    trace_event_data_t *evt_data = create_pthrd_event(pthrd_enter, 0, ctx);

    if (!evt_data) {
        return;
    }
    bpf_map_update_elem(&pthrd_stash_map, &pthrd_enter->key, evt_data, BPF_ANY);
}

static __always_inline void merge_incomming_pthrd_event(trace_event_data_t *evt_data, pthrd_m_enter_t *pthrd_enter)
{
    evt_data->pthrd_d.end_time = pthrd_enter->end_time;
    evt_data->pthrd_d.duration += pthrd_enter->end_time - pthrd_enter->start_time;
    evt_data->pthrd_d.count++;
}

static __always_inline void process_pthrd_event(pthrd_m_enter_t *pthrd_enter, void *ctx)
{
    trace_event_data_t *evt_data;

    evt_data = (trace_event_data_t *)bpf_map_lookup_elem(&pthrd_stash_map, &pthrd_enter->key);

    if (evt_data == (void *)0) {
        if (can_emit(pthrd_enter->start_time, pthrd_enter->end_time)) {
            emit_incomming_pthrd_event(pthrd_enter, ctx);
        } else {
            stash_incomming_pthrd_event(pthrd_enter, ctx);
        }
        return;
    }

    if (can_emit(evt_data->pthrd_d.start_time, pthrd_enter->end_time)) {
        emit_pthrd_event_stashed(evt_data, ctx);
        bpf_map_delete_elem(&pthrd_stash_map, &pthrd_enter->key);

        if (can_emit(pthrd_enter->start_time, pthrd_enter->end_time)) {
            emit_incomming_pthrd_event(pthrd_enter, ctx);
        } else {
            stash_incomming_pthrd_event(pthrd_enter, ctx);
        }
    } else {
        merge_incomming_pthrd_event(evt_data, pthrd_enter);
    }
}

static __always_inline void enter_pthrd_event(int id)
{
    pthrd_m_enter_t enter;
    u64 ptid = bpf_get_current_pid_tgid();

    // maybe delete?
    if (!is_proc_thrd_enabled()) {
        return;
    }

    __builtin_memset(&enter, 0, sizeof(enter));
    enter.key.pid = (int)ptid;
    enter.key.id = id;
    enter.start_time = bpf_ktime_get_ns();
    (void)bpf_map_update_elem(&pthrd_enter_map, &enter.key, &enter, BPF_ANY);
    return;
}

static __always_inline void exit_pthrd_event(int id, void *ctx)
{
    pthrd_m_enter_t *enter;
    pthrd_m_key_t key = {0};
    u32 pid = bpf_get_current_pid_tgid();
    trace_setting_t *setting;

    key.pid = pid;
    key.id = id;
    enter = (pthrd_m_enter_t *)bpf_map_lookup_elem(&pthrd_enter_map, &key);
    if (!enter) {
        return;
    }
    setting = get_trace_setting();
    if (!setting) {
        goto out;
    }
    enter->end_time = bpf_ktime_get_ns();
    if (enter->end_time < enter->start_time + setting->min_exec_dur) {
        goto out;
    }
    process_pthrd_event(enter, ctx);
out:
    (void)bpf_map_delete_elem(&pthrd_enter_map, &key);
    return;
}

#define UP_PTHREAD_ENTER(name, id) \
    UPROBE(name, pt_regs) \
    { \
        enter_pthrd_event(id); \
        return 0; \
    } \

#define UP_PTHREAD_EXIT(name, id) \
    URETPROBE(name, pt_regs) \
    { \
        exit_pthrd_event(id, ctx); \
        return 0; \
    } \

#define UP_PTHREAD(name, id) \
    UP_PTHREAD_ENTER(name, id); \
    UP_PTHREAD_EXIT(name, id)

/* start bpf prog definition */

UP_PTHREAD(pthread_mutex_lock, PTHREAD_MUTEX_LOCK_ID);
UP_PTHREAD(pthread_mutex_timedlock, PTHREAD_MUTEX_TIMEDLOCK_ID);
UP_PTHREAD(pthread_mutex_trylock, PTHREAD_MUTEX_TRYLOCK_ID);
UP_PTHREAD(pthread_rwlock_rdlock, PTHREAD_RWLOCK_RDLOCK_ID);
UP_PTHREAD(pthread_rwlock_wrlock, PTHREAD_RWLOCK_WRLOCK_ID);
UP_PTHREAD(pthread_rwlock_timedrdlock, PTHREAD_RWLOCK_TIMEDRDLOCK_ID);
UP_PTHREAD(pthread_rwlock_timedwrlock, PTHREAD_RWLOCK_TIMEDWRLOCK_ID);
UP_PTHREAD(pthread_rwlock_tryrdlock, PTHREAD_RWLOCK_TRYRDLOCK_ID);
UP_PTHREAD(pthread_rwlock_trywrlock, PTHREAD_RWLOCK_TRYWRLOCK_ID);
UP_PTHREAD(pthread_spin_lock, PTHREAD_SPIN_LOCK_ID);
UP_PTHREAD(pthread_spin_trylock, PTHREAD_SPIN_TRYLOCK_ID);
UP_PTHREAD(pthread_timedjoin_np, PTHREAD_TIMEDJOIN_NP_ID);
UP_PTHREAD(pthread_tryjoin_np, PTHREAD_TRYJOIN_NP_ID);
UP_PTHREAD(pthread_yield, PTHREAD_YIELD_ID);
UP_PTHREAD(sem_timedwait, SEM_TIMEDWAIT_ID);
UP_PTHREAD(sem_trywait, SEM_TRYWAIT_ID);
UP_PTHREAD(sem_wait, SEM_WAIT_ID);

/* end bpf prog definition */

char g_license[] SEC("license") = "Dual BSD/GPL";