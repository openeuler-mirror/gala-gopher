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
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "tprofiling.h"

#define BPF_F_INDEX_MASK  0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK

#ifndef BPF_F_FAST_STACK_CMP
#define BPF_F_FAST_STACK_CMP    (1ULL << 9)
#endif

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK    (1ULL << 8)
#endif

#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, MAX_CPU);
} event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(profiling_setting_t));
    __uint(max_entries, 1);
} setting_map SEC(".maps");

// filter process locally if enabled
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct proc_s));
    __uint(value_size, sizeof(struct obj_ref_s));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} proc_filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} thrd_bl_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(syscall_m_enter_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} syscall_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(syscall_m_stash_key_t));
    __uint(value_size, sizeof(syscall_m_stash_val_t));
    __uint(max_entries, MAX_SIZE_OF_STASH_EVENT);
} syscall_stash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(unsigned long));
    __uint(value_size, sizeof(syscall_m_meta_t));
    __uint(max_entries, MAX_SIZE_OF_SYSCALL_TABLE);
} syscall_table_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(oncpu_m_enter_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} oncpu_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(oncpu_data_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} oncpu_stash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64) * PERF_MAX_STACK_DEPTH);
    __uint(max_entries, 1024);
} stack_map SEC(".maps");

static __always_inline syscall_m_meta_t *get_syscall_meta(unsigned long nr)
{
    syscall_m_meta_t *scm = (syscall_m_meta_t *)bpf_map_lookup_elem(&syscall_table_map, &nr);
    return scm;
}

static __always_inline long bpf_syscall_get_nr(struct pt_regs *regs)
{
#if defined(__TARGET_ARCH_x86)
    return _(regs->orig_ax);
#elif defined(__TARGET_ARCH_arm64)
    return _(regs->syscallno);
#else
    return 0;
#endif
}

static __always_inline profiling_setting_t *get_tp_setting()
{
    u32 setting_k = 0;
    return (profiling_setting_t *)bpf_map_lookup_elem(&setting_map, &setting_k);
}

static __always_inline bool enable_proc(u32 tgid, profiling_setting_t *setting)
{
    struct proc_s proc_k = {.proc_id = tgid};
    void *proc_v;
    int filter_local = 0;

    if (setting->filter_local) {
        proc_v = bpf_map_lookup_elem(&proc_filter_map, &proc_k);
    } else {
        proc_v = bpf_map_lookup_elem(&proc_obj_map, &proc_k);
    }
    if (proc_v != (void *)0) {
        return true;
    }

    return false;
}

static __always_inline bool enable_thrd(u32 pid, u32 tgid)
{
    u32 *val;
    val = (u32 *)bpf_map_lookup_elem(&thrd_bl_map, &pid);
    if (val == (void *)0) {
        return true;
    }

    if (*val == tgid) {
        return false;
    } else {
        // invalid thread item in blacklist map
        bpf_map_delete_elem(&thrd_bl_map, &pid);
        return true;
    }
}

static __always_inline bool enable_proc_thrd(profiling_setting_t *setting)
{
    u64 pid_tgid;
    u32 tgid, pid;

    if (!setting->filter_enabled) {
        return true;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> INT_LEN;
    pid = (u32)pid_tgid;

    return enable_proc(tgid, setting) && enable_thrd(pid, tgid);
}

static __always_inline void init_syscall_data(syscall_data_t *scd, syscall_m_enter_t *sce,
                                              syscall_m_meta_t *scm, struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    scd->nr = sce->nr;
    scd->start_time = sce->start_time;
    scd->end_time = bpf_ktime_get_ns();
    scd->duration = scd->end_time - scd->start_time;
    scd->count = 1;

    if (scm->flag & SYSCALL_FLAG_FD) {
        int fd = _(PT_REGS_PARM1(regs));
        scd->ext_info.fd_info.fd = fd;
    }

    // stack trace
    if (scm->flag & SYSCALL_FLAG_STACK) {
        scd->stack_info.uid = bpf_get_stackid(ctx, &stack_map, USER_STACKID_FLAGS);
    }

    if (sce->nr == SYSCALL_FUTEX_ID) {
        scd->ext_info.futex_info.addr = (void *)_(PT_REGS_PARM1(regs));
        scd->ext_info.futex_info.op = _(PT_REGS_PARM2(regs));
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

static __always_inline void emit_incomming_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm,
                                                         struct bpf_raw_tracepoint_args *ctx)
{
    trace_event_data_t evt_data = {0};

    init_syscall_event_common(&evt_data, sce->start_time);
    init_syscall_data(&evt_data.syscall_d, sce, scm, ctx);

    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &evt_data, sizeof(evt_data));
}

static __always_inline void emit_syscall_event_stashed(syscall_m_stash_val_t *sc_stash, struct bpf_raw_tracepoint_args *ctx)
{
    trace_event_data_t evt_data = {0};

    init_syscall_event_common(&evt_data, sc_stash->start_time);
    evt_data.syscall_d = (syscall_data_t)(*sc_stash);

    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &evt_data, sizeof(evt_data));
}

static __always_inline void stash_incomming_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm,
                                                          struct bpf_raw_tracepoint_args *ctx)
{
    syscall_m_stash_key_t sc_stash_key = {0};
    syscall_m_stash_val_t sc_stash = {0};

    sc_stash_key.pid = sce->pid;
    sc_stash_key.nr = sce->nr;
    init_syscall_data((syscall_data_t *)&sc_stash, sce, scm, ctx);
    bpf_map_update_elem(&syscall_stash_map, &sc_stash_key, &sc_stash, BPF_ANY);
}

static __always_inline u64 get_aggr_duration()
{
    u32 setting_k = 0;
    profiling_setting_t *setting_v;
    u64 aggr_duration = 0;

    setting_v = (profiling_setting_t *)bpf_map_lookup_elem(&setting_map, &setting_k);
    if (setting_v != (void *)0) {
        aggr_duration = setting_v->aggr_duration;
    }
    if (aggr_duration == 0) {
        aggr_duration = DFT_AGGR_DURATION;
    }

    return aggr_duration;
}

static __always_inline bool can_emit(u64 stime, u64 etime)
{
    if (etime >= stime + get_aggr_duration()) {
        return true;
    }
    return false;
}

static __always_inline void process_syscall_event(syscall_m_enter_t *sce, syscall_m_meta_t *scm,
                                                  struct bpf_raw_tracepoint_args *ctx)
{
    u64 cur_time = bpf_ktime_get_ns();
    syscall_m_stash_key_t sc_stash_key = {0};
    syscall_m_stash_val_t *sc_stash;

    if (cur_time < sce->start_time) {
        return;
    }

    sc_stash_key.pid = sce->pid;
    sc_stash_key.nr = sce->nr;
    sc_stash = (syscall_m_stash_val_t *)bpf_map_lookup_elem(&syscall_stash_map, &sc_stash_key);

    if (sc_stash == (void *)0) {
        if (can_emit(sce->start_time, cur_time)) {
            emit_incomming_syscall_event(sce, scm, ctx);
        } else {
            stash_incomming_syscall_event(sce, scm, ctx);
        }
        return;
    }

    if (can_emit(sc_stash->start_time, cur_time)) {
        emit_syscall_event_stashed(sc_stash, ctx);
        (void)bpf_map_delete_elem(&syscall_stash_map, &sc_stash_key);

        if (can_emit(sce->start_time, cur_time)) {
            emit_incomming_syscall_event(sce, scm, ctx);
        } else {
            stash_incomming_syscall_event(sce, scm, ctx);
        }
    } else {
        // merge event
        // TODO: 考虑一下加锁？
        sc_stash->end_time = cur_time;
        sc_stash->count++;
        sc_stash->duration += cur_time - sce->start_time;
    }
}

static __always_inline void process_sys_enter(syscall_m_meta_t *scm)
{
    syscall_m_enter_t sce = {0};

    sce.pid = (u32)bpf_get_current_pid_tgid();
    sce.nr = scm->nr;
    sce.start_time = bpf_ktime_get_ns();
    (void)bpf_map_update_elem(&syscall_map, &sce.pid, &sce, BPF_ANY);
}

static __always_inline void process_sys_exit(syscall_m_enter_t *sce, struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long nr;
    syscall_m_meta_t *scm;
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    nr = bpf_syscall_get_nr(regs);
    if (__builtin_expect((nr != sce->nr), 0)) { // not likely happened
        return;
    }

    scm = get_syscall_meta(nr);
    if (__builtin_expect((scm == (void *)0), 0)) {  // not likely happened
        return;
    }

    process_syscall_event(sce, scm, ctx);
}

SEC("raw_tracepoint/sys_enter")
int bpf_raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long nr;
    syscall_m_meta_t *scm;
    profiling_setting_t *setting;

    nr = ctx->args[1];
    scm = get_syscall_meta(nr);
    if (scm == (void *)0) {
        return 0;
    }

    setting = get_tp_setting();
    if (setting == (void *)0) {
        return 0;
    }

    if (!enable_proc_thrd(setting)) {
        return 0;
    }

    process_sys_enter(scm);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int bpf_raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    u32 pid;
    syscall_m_enter_t *sce;

    pid = (u32)bpf_get_current_pid_tgid();
    // 如果查询到 sce ，则说明当前进程和系统调用满足过滤条件，无需再额外添加相应的过滤判断逻辑
    sce = (syscall_m_enter_t *)bpf_map_lookup_elem(&syscall_map, &pid);
    if (sce == (void *)0) {
        return 0;
    }

    process_sys_exit(sce, ctx);

    (void)bpf_map_delete_elem(&syscall_map, &pid);

    return 0;
}

static __always_inline void init_oncpu_event_common(trace_event_data_t *evt_data, u64 timestamp,
                                                    struct task_struct *task)
{
    evt_data->type = EVT_TYPE_ONCPU;
    evt_data->timestamp = timestamp;
    evt_data->pid = _(task->pid);
    evt_data->tgid = _(task->tgid);
    bpf_probe_read_str(evt_data->comm, sizeof(evt_data->comm), task->comm);
}

static __always_inline void emit_incomming_oncpu_event(oncpu_m_enter_t *oncpu_enter, struct task_struct *task,
                                                       struct pt_regs *ctx)
{
    trace_event_data_t evt_data = {0};
    u64 end_time = bpf_ktime_get_ns();

    init_oncpu_event_common(&evt_data, oncpu_enter->start_time, task);

    evt_data.oncpu_d.start_time = oncpu_enter->start_time;
    evt_data.oncpu_d.end_time = end_time;
    evt_data.oncpu_d.duration = end_time - oncpu_enter->start_time;
    evt_data.oncpu_d.count = 1;

    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &evt_data, sizeof(evt_data));
}

static __always_inline void emit_oncpu_event_stashed(oncpu_data_t *oncpu_stash, struct task_struct *task,
                                                     struct pt_regs *ctx)
{
    trace_event_data_t evt_data = {0};

    init_oncpu_event_common(&evt_data, oncpu_stash->start_time, task);
    evt_data.oncpu_d = *oncpu_stash;

    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &evt_data, sizeof(evt_data));
}

static __always_inline void stash_incomming_oncpu_event(oncpu_m_enter_t *oncpu_enter, struct task_struct *task,
                                                        struct pt_regs *ctx)
{
    oncpu_data_t oncpu_d = {0};
    
    oncpu_d.start_time = oncpu_enter->start_time;
    oncpu_d.end_time = bpf_ktime_get_ns();
    oncpu_d.duration = oncpu_d.end_time - oncpu_d.start_time;
    oncpu_d.count = 1;

    bpf_map_update_elem(&oncpu_stash_map, &oncpu_enter->pid, &oncpu_d, BPF_ANY);
}

static __always_inline void process_oncpu_event(oncpu_m_enter_t *oncpu_enter, struct task_struct *task,
                                                struct pt_regs *ctx)
{
    u64 cur_time = bpf_ktime_get_ns();
    oncpu_data_t *oncpu_stash;
    u32 pid;

    if (cur_time < oncpu_enter->start_time) {
        return;
    }

    pid = _(task->pid);
    oncpu_stash = (oncpu_data_t *)bpf_map_lookup_elem(&oncpu_stash_map, &pid);

    if (oncpu_stash == (void *)0) {
        if (can_emit(oncpu_enter->start_time, cur_time)) {
            emit_incomming_oncpu_event(oncpu_enter, task, ctx);
        } else {
            stash_incomming_oncpu_event(oncpu_enter, task, ctx);
        }
        return;
    }

    if (can_emit(oncpu_stash->start_time, cur_time)) {
        emit_oncpu_event_stashed(oncpu_stash, task, ctx);
        bpf_map_delete_elem(&oncpu_stash_map, &pid);

        if (can_emit(oncpu_enter->start_time, cur_time)) {
            emit_incomming_oncpu_event(oncpu_enter, task, ctx);
        } else {
            stash_incomming_oncpu_event(oncpu_enter, task, ctx);
        }
    } else {
        // merge event
        oncpu_stash->end_time = cur_time;
        oncpu_stash->count++;
        oncpu_stash->duration += cur_time - oncpu_enter->start_time;
    }
}

static __always_inline void process_oncpu(struct task_struct *task, profiling_setting_t *setting)
{
    u32 pid, tgid;
    oncpu_m_enter_t oncpu_enter = {0};

    pid = _(task->pid);
    tgid = _(task->tgid);
    if (setting->filter_enabled) {
        if (!enable_proc(tgid, setting) || !enable_thrd(pid, tgid)) {
            return;
        }
    }

    oncpu_enter.pid = pid;
    oncpu_enter.start_time = bpf_ktime_get_ns();
    (void)bpf_map_update_elem(&oncpu_map, &oncpu_enter.pid, &oncpu_enter, BPF_ANY);
}

static __always_inline void process_offcpu(struct task_struct *task, struct pt_regs *ctx)
{
    u32 pid = _(task->pid);
    oncpu_m_enter_t *oncpu_enter;

    oncpu_enter = (oncpu_m_enter_t *)bpf_map_lookup_elem(&oncpu_map, &pid);
    if (oncpu_enter == (void *)0) {
        return;
    }

    process_oncpu_event(oncpu_enter, task, ctx);

    (void)bpf_map_delete_elem(&oncpu_map, &pid);
}

KPROBE(finish_task_switch, pt_regs)
{
    struct task_struct *prev = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    profiling_setting_t *setting;

    setting = get_tp_setting();
    if (setting == (void *)0) {
        return 0;
    }

    process_offcpu(prev, ctx);
    process_oncpu(current, setting);

    return 0;
}

char g_license[] SEC("license") = "Dual BSD/GPL";
