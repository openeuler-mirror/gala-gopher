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
 * Description: syscall latency probe
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "sched_report_channel.h"

char g_linsence[] SEC("license") = "GPL";

#define TASK_RUNNING			0x0000

#ifndef BPF_F_FAST_STACK_CMP
#define BPF_F_FAST_STACK_CMP    (1ULL << 9)
#endif
#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)

struct sys_enter_s {
    char comm[TASK_COMM_LEN];
    pid_t proc_id;
    int cpu;

    pid_t pid;
    long int sysid;
    long int prev_state;

    u32 stack_id;
    u64 csw, enter, exit;   // unit: nanosecond
    u64 wait, sleep;        // unit: nanosecond
};

struct bpf_map_def SEC("maps") syscall_enter_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(pid_t),
    .value_size = sizeof(struct sys_enter_s),
    .max_entries = 10 * 1024,
};

struct bpf_map_def SEC("maps") syscall_latency_stackmap = {
    .type = BPF_MAP_TYPE_STACK_TRACE,
    .key_size = sizeof(u32),
    .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
    .max_entries = 1000,
};

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

struct sys_enter_arg {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
};

struct sys_exit_arg {
    struct trace_entry ent;
    long id;
    long ret;
};

static __always_inline void __build_evt(struct sys_enter_s *sys_enter, struct event *evt)
{
    evt->e = EVT_SYSCALL;
    evt->proc_id = sys_enter->proc_id;
    __builtin_memcpy(evt->comm, sys_enter->comm, sizeof(evt->comm));
    evt->cpu = sys_enter->cpu;
    evt->stack_id = sys_enter->stack_id;

    evt->body.syscall.sysid = sys_enter->sysid;
    evt->body.syscall.csw = sys_enter->csw;
    evt->body.syscall.enter = sys_enter->enter;
    evt->body.syscall.exit = sys_enter->exit;
    evt->body.syscall.wait = sys_enter->wait;
    evt->body.syscall.sleep = sys_enter->sleep;
    return;
}

bpf_section("tp/raw_syscalls/sys_enter")
void tracepoint_sys_enter(struct sys_enter_arg *ctx)
{
    char comm[TASK_COMM_LEN] = {0};
    pid_t pid = bpf_get_current_pid_tgid();
    pid_t proc_id = bpf_get_current_pid_tgid() >> INT_LEN;
    u64 now;
    struct sys_enter_s *sys_enter = NULL;

    bpf_get_current_comm(&comm, sizeof(comm));

    if (!is_targe_comm(comm, proc_id)) {
        return;
    }

    sys_enter = bpf_map_lookup_elem(&syscall_enter_map, &pid);
    if (!sys_enter) {
        now = bpf_ktime_get_ns();
        struct sys_enter_s sys_enteri = {0};
        __builtin_memcpy(sys_enteri.comm, comm, sizeof(sys_enteri.comm));
        sys_enteri.proc_id = proc_id;
        sys_enteri.pid = pid;
        sys_enteri.cpu = bpf_get_smp_processor_id();

        sys_enteri.enter = now;
        bpf_map_update_elem(&syscall_enter_map, &pid, &sys_enteri, 0);
    }
    return;
}

bpf_section("tp/sched/sched_switch")
void tracepoint_sched_switch(struct sched_switch_args *ctx)
{
    pid_t next_pid, prev_pid;
    u64 now;
    struct sys_enter_s *sys_enter = NULL;

    next_pid = ctx->next_pid;
    prev_pid = ctx->prev_pid;
    now = bpf_ktime_get_ns();

    sys_enter = bpf_map_lookup_elem(&syscall_enter_map, &prev_pid);
    if (sys_enter) {
        sys_enter->csw = now;
        sys_enter->prev_state = ctx->prev_state;
        sys_enter->stack_id = bpf_get_stackid(ctx, &syscall_latency_stackmap, KERN_STACKID_FLAGS);
    }

    sys_enter = bpf_map_lookup_elem(&syscall_enter_map, &next_pid);
    if (sys_enter) {
        sys_enter->csw = now;
        sys_enter->prev_state = ctx->prev_state;
        if (sys_enter->prev_state == TASK_RUNNING) {
            sys_enter->wait += (now - sys_enter->csw);
        } else {
            sys_enter->sleep += (now - sys_enter->csw);
        }
    }

    return;
}

bpf_section("tp/raw_syscalls/sys_exit")
void tracepoint_raw_sys_exit(struct sys_exit_arg *ctx)
{
    u64 delay, lat_thr;
    pid_t pid = bpf_get_current_pid_tgid();
    struct sys_enter_s *sys_enter = NULL;

    sys_enter = bpf_map_lookup_elem(&syscall_enter_map, &pid);
    if (!sys_enter) {
        return;
    }

    sys_enter->exit = bpf_ktime_get_ns();

    delay = sys_enter->exit - sys_enter->enter;
    lat_thr = get_lat_thr();
    if (delay >= lat_thr) {
        struct event evt = {0};
        __build_evt(sys_enter, &evt);

        bpf_perf_event_output(ctx, &sched_report_channel_map, BPF_F_ALL_CPU,
                              &evt, sizeof(evt));
    }

    bpf_map_delete_elem(&syscall_enter_map, &pid);
}

