/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2022-07-13
 * Description: Collecting Task sched Data
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "task.h"
#include "proc_map.h"
#include "output_proc.h"

char g_linsence[] SEC("license") = "GPL";

typedef u64 conn_ctx_t;         // pid & tgid

struct cpu_timestamp_s {
    u32 is_iowait;
    u64 offcpu_start_ts;
};

#define __PROC_MAX      1000
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct cpu_timestamp_s));
    __uint(max_entries, __PROC_MAX);
} cpu_map SEC(".maps");

static __always_inline struct cpu_timestamp_s* get_cpu_timestamp(conn_ctx_t id)
{
    struct cpu_timestamp_s new_proc_cpu = {0};
    struct cpu_timestamp_s *proc_cpu = NULL;

    proc_cpu = (struct cpu_timestamp_s *)bpf_map_lookup_elem(&cpu_map, &id);
    if (proc_cpu) {
        return proc_cpu;
    }

    (void)bpf_map_update_elem(&cpu_map, &id, &new_proc_cpu, BPF_ANY);

    return  (struct cpu_timestamp_s *)bpf_map_lookup_elem(&cpu_map, &id);
}

static __always_inline struct cpu_timestamp_s* lkup_cpu_timestamp(conn_ctx_t id)
{
    return (struct cpu_timestamp_s *)bpf_map_lookup_elem(&cpu_map, &id);
}

static __always_inline void offcpu_start(struct task_struct* prev)
{
    if (prev == NULL) {
        return;
    }

    int tgid = _(prev->tgid);
    int pid = _(prev->pid);

    struct proc_data_s* proc = get_proc_entry(tgid);
    if (proc == NULL) {
        return;
    }

    conn_ctx_t id = (conn_ctx_t)(((u64)tgid << INT_LEN) & (u64)pid);
    struct cpu_timestamp_s *cpu_ts = get_cpu_timestamp(id);
    if (cpu_ts == NULL) {
        return;
    }

    u64 is_iowait = BPF_CORE_READ_BITFIELD_PROBED(prev, in_iowait);

    u64 ts = bpf_ktime_get_ns();

    cpu_ts->is_iowait = (u32)is_iowait;
    cpu_ts->offcpu_start_ts = ts;
    return;
}

static __always_inline void offcpu_end(void *ctx, conn_ctx_t id)
{
    u64 delta;

    struct cpu_timestamp_s *cpu_ts = lkup_cpu_timestamp(id);
    if (cpu_ts == NULL) {
        return;
    }

    struct proc_data_s* proc = get_proc_entry(id >> INT_LEN);
    if (proc == NULL) {
        goto end;
    }

    u64 ts = bpf_ktime_get_ns();

    if (cpu_ts->offcpu_start_ts < ts) {
        delta = ts - cpu_ts->offcpu_start_ts;
        if (cpu_ts->is_iowait) {
            __sync_fetch_and_add(&(proc->proc_cpu.iowait_ns), delta);
            __sync_fetch_and_add(&(proc->proc_cpu.offcpu_ns), delta);
        } else {
            __sync_fetch_and_add(&(proc->proc_cpu.offcpu_ns), delta);
        }

        report_proc(ctx, proc, TASK_PROBE_CPU);
    }

end:
    (void)bpf_map_delete_elem(&cpu_map, &id);
    return;
}

KPROBE(finish_task_switch, pt_regs)
{
    struct task_struct* prev = (struct task_struct *)PT_REGS_PARM1(ctx);
    conn_ctx_t id = (conn_ctx_t)bpf_get_current_pid_tgid();

    offcpu_start(prev);
    offcpu_end(ctx, id);

    return 0;
}

