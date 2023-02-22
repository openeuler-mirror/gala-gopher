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
 * Author: luzhihao
 * Create: 2022-11-07
 * Description: sched latency probe
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "sched_report_channel.h"

char g_linsence[] SEC("license") = "GPL";

#define DELAY_MAX  (u64)((u64)10 * 1000 * 1000 * 1000)  // 10S

#ifndef BPF_F_FAST_STACK_CMP
#define BPF_F_FAST_STACK_CMP    (1ULL << 9)
#endif
#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)

struct sched_switch_args {
    struct trace_entry ent;
    char prev_comm[TASK_COMM_LEN];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[TASK_COMM_LEN];
    pid_t next_pid;
    int next_prio;
};

struct sched_latency_s {
    u32 cpu;
    pid_t proc_id;
    u64 last_resched_ts;    // Started scheduling delay statistics(non-zero), unit: nanosecond
    u64 last_report_ts;     // Last report time, unit: nanosecond
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(pid_t));
    __uint(value_size, sizeof(struct sched_latency_s));
    __uint(max_entries, 1000);
} resched_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 1000);
} systime_latency_stackmap SEC(".maps");


#if defined(__TARGET_ARCH_x86)
#define TIF_NEED_RESCHED    3
#elif defined(__TARGET_ARCH_arm64)
#define TIF_NEED_RESCHED    1
#endif

/* Refer to the Linux(v4.18) code. */

#if (CURRENT_KERNEL_VERSION >= KERNEL_VERSION(4, 18, 0))
static inline struct thread_info *task_thread_info(struct task_struct *task, struct thread_info *tfp)
{
    bpf_probe_read(tfp, sizeof(*tfp), (char *)&(task->thread_info));
    return tfp;
}
#else
static inline struct thread_info *task_thread_info(struct task_struct *task, struct thread_info *tfp)
{
    return NULL;
}
#endif

/* Refer to the Linux(v4.18) code. */
#define BITS_PER_LONG   64
#define BIT_WORD(nr)    ((nr) / BITS_PER_LONG)

static __always_inline int test_bit(int nr, const volatile unsigned long *addr)
{
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

static __always_inline int test_ti_thread_flag(struct thread_info *ti, int flag)
{
    if (ti == NULL) {
        return 0;
    }
    return test_bit(flag, (unsigned long *)&ti->flags);
}

static __always_inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
    struct thread_info tf;
    return test_ti_thread_flag(task_thread_info(tsk, &tf), flag);
}

static __always_inline int test_tsk_need_resched(struct task_struct *tsk)
{
    return test_tsk_thread_flag(tsk, TIF_NEED_RESCHED);
}

static __always_inline u64 get_sched_delay(u64 now, u64 last)
{
    u64 delay;
    if (now <= last) {
        return 0;
    }

    delay = now - last;
    if (delay >= DELAY_MAX) {
        return 0;
    }
    if (delay >= get_lat_thr()) {
        return delay;
    }

    return 0;
}

static __always_inline struct sched_latency_s* get_resched_pid(pid_t pid)
{
    return (struct sched_latency_s*)bpf_map_lookup_elem(&resched_pid_map, &pid);
}

static __always_inline void try_del_resched_pid(pid_t pid)
{
    bpf_map_delete_elem(&resched_pid_map, &pid);
}

static __always_inline struct sched_latency_s* add_resched_pid(pid_t pid, pid_t tgid, char *crt)
{
    struct sched_latency_s *sched_latp = NULL;
    struct sched_latency_s sched_lati = {0};

    sched_latp = get_resched_pid(pid);
    if (sched_latp) {
        return sched_latp;
    }

    sched_lati.last_resched_ts = bpf_ktime_get_ns();
    sched_lati.last_report_ts = 0;
    sched_lati.cpu = bpf_get_smp_processor_id();
    sched_lati.proc_id = tgid;
    bpf_map_update_elem(&resched_pid_map, &pid, &sched_lati, BPF_ANY);
    *crt = 1;
    return get_resched_pid(pid);
}

static __always_inline void __build_evt(struct sched_latency_s *sched_latp,
                                                    struct event *evt,
                                                    enum sched_evt_t type,
                                                    u64 now, u64 delay, void *ctx)
{
    evt->e = EVT_SYSTIME;
    evt->cpu = sched_latp->cpu;
    evt->proc_id = sched_latp->proc_id;
    __builtin_memcpy(evt->comm, sched_latp->comm, sizeof(evt->comm));
    evt->stack_id = bpf_get_stackid(ctx, &systime_latency_stackmap, KERN_STACKID_FLAGS);

    if (type == SCHED_LAT_START) {
        evt->body.systime.start = sched_latp->last_resched_ts;
    }
    else if (type == SCHED_LAT_END) {
        evt->body.systime.end = now;
    }
    evt->body.systime.delay = delay;
    evt->body.systime.issue = now;
    return;
}

KRETPROBE(account_process_tick, pt_regs)
{
    pid_t pid, tgid;
    char create = 0;
    u64 now, delay;
    struct sched_latency_s *sched_latp = NULL;
    struct task_struct* tsk = (struct task_struct *)bpf_get_current_task();

    pid = _(tsk->pid);
    if (pid == 0) {
        return 0;
    }

    if(!test_tsk_need_resched(tsk)) {
        return 0;
    }

    char comm[TASK_COMM_LEN] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));

    tgid = _(tsk->tgid);
    if (!is_targe_comm(comm, tgid)) {
        return 0;
    }

    sched_latp = add_resched_pid(pid, tgid, &create);
    if (sched_latp == NULL) {
        return 0;
    }

    if (create) {
        // First-triggered re-schedule.
        bpf_probe_read_str(&(sched_latp->comm), TASK_COMM_LEN * sizeof(char), (char *)tsk->comm);
        return 0;
    }

    // Next-triggered re-schedule.
    u64 last_ts = (sched_latp->last_report_ts != 0) ?: sched_latp->last_resched_ts;
    now = bpf_ktime_get_ns();
    delay = get_sched_delay(now, last_ts);
    if (delay == 0) {
        // The scheduling delay does not exceed the threshold.
        // Nothing to do.
        return 0;
    }

    delay = now - sched_latp->last_resched_ts;  // report overall delay
    struct event evt = {0};
    if (sched_latp->last_report_ts == 0) {
        __build_evt(sched_latp, &evt, SCHED_LAT_START, now, delay, ctx);
    } else {
        __build_evt(sched_latp, &evt, SCHED_LAT_CONT, now, delay, ctx);
    }

    bpf_perf_event_output(ctx, &sched_report_channel_map, BPF_F_ALL_CPU,
                          &evt, sizeof(evt));
    sched_latp->last_report_ts = now;
    return 0;
}

bpf_section("tp/sched/sched_switch")
void tracepoint_sched_switch(struct sched_switch_args *ctx)
{
    u64 now, delay;
    struct sched_latency_s *sched_latp = NULL;

    sched_latp = get_resched_pid(ctx->prev_pid);
    if (sched_latp == NULL) {
        // Not in the re-schedule state.
        return;
    }

    now = bpf_ktime_get_ns();

    u64 last_ts = (sched_latp->last_report_ts != 0) ?: sched_latp->last_resched_ts;
    delay = get_sched_delay(now, last_ts);
    if (delay > 0) {
        // Reporting an abnormal scheduling delay event through perf (end) 
        struct event evt = {0};
        delay = now - sched_latp->last_resched_ts;  // report overall delay
        __build_evt(sched_latp, &evt, SCHED_LAT_END, now, delay, ctx);

        bpf_perf_event_output(ctx, &sched_report_channel_map, BPF_F_ALL_CPU,
                              &evt, sizeof(evt));
    }

    // Exit re-schedule state
    try_del_resched_pid(ctx->prev_pid);

    return;
}

