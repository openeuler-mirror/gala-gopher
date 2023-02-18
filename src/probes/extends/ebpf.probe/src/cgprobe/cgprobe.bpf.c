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
 * Author: wo_cow
 * Create: 2022-06-10
 * Description: cgprobe kernel prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include <bpf/bpf_endian.h>
#include "bpf.h"
#include "cgprobe.h"

char g_linsence[] SEC("license") = "GPL";

#define BPF_F_INDEX_MASK        0xffffffffULL
#define BPF_F_CURRENT_CPU       BPF_F_INDEX_MASK

#ifndef __CGROUP_MAX
#define __CGROUP_MAX (1024)
#endif
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64)); // cgroup_id
    __uint(value_size, sizeof(struct mem_cgroup_gauge));
    __uint(max_entries, __CGROUP_MAX);
} cg_map SEC(".maps");

#ifndef __PERF_OUT_MAX
#define __PERF_OUT_MAX (64)
#endif
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, __PERF_OUT_MAX);
} output SEC(".maps");

// Data collection args
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));  // const value 0
    __uint(value_size, sizeof(struct ns_args_s)); // nsprobe args
    __uint(max_entries, 1);
} args_map SEC(".maps");

#ifndef __PERIOD
#define __PERIOD NS(30)
#endif
static __always_inline u64 get_period()
{
    u32 key = 0;
    u64 period = __PERIOD;

    struct ns_args_s *args;
    args = (struct ns_args_s *)bpf_map_lookup_elem(&args_map, &key);
    if (args) {
        period = args->period;
    }

    return period; // units from second to nanosecond
}

static __always_inline int create_cgroup_gauge(__u64 cgroup_id)
{
    struct mem_cgroup_gauge cg = {0};
    cg.cgroup_id = cgroup_id;
    return bpf_map_update_elem(&cg_map, &cgroup_id, &cg, BPF_ANY);
}

static __always_inline struct mem_cgroup_gauge* get_cgroup_gauge(__u64 cgroup_id)
{
    return (struct mem_cgroup_gauge *)bpf_map_lookup_elem(&cg_map, &cgroup_id);
}

static __always_inline void del_cgroup_gauge(struct mem_cgroup* memcg)
{
    (void)bpf_map_delete_elem(&cg_map, &memcg);
    return;
}

static __always_inline __u64 get_cgroup_gauge_id(struct mem_cgroup* memcg)
{
    __u64 cgroup_id;
   struct cgroup *cgroup = _(memcg->css.cgroup);
    if (cgroup == NULL)
        return 0;

    struct kernfs_node *kn = _(cgroup->kn);
    if (kn == NULL) {
        return 0;
    }

#if (CURRENT_KERNEL_VERSION < KERNEL_VERSION(5, 5, 0))
    cgroup_id = _(kn->id.ino);
#else
    cgroup_id = _(kn->id);
#endif
    return cgroup_id;
}

static __always_inline void periodic_report(struct pt_regs *ctx, struct mem_cgroup_gauge* cg)
{
    u64 ts_nsec = bpf_ktime_get_ns();
    u64 period = get_period();

    if (cg->last_report_ts_nsec == 0 ||
        (ts_nsec > cg->last_report_ts_nsec && ts_nsec - cg->last_report_ts_nsec >= period)) {
        (void)bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, cg, sizeof(struct mem_cgroup_gauge));
        cg->nr_pages = 0;
        cg->oom_order = 0;
        cg->last_report_ts_nsec = ts_nsec;
    }

    return;
}


static __always_inline struct mem_cgroup_gauge* lkup_memcg(struct mem_cgroup *memcg)
{
    __u64 cgroup_id;
    struct mem_cgroup_gauge* cg;

    if (memcg == NULL) {
        return NULL;
    }

    cgroup_id = get_cgroup_gauge_id(memcg);
    if (cgroup_id == 0) {
        return NULL;
    }

    cg = get_cgroup_gauge(cgroup_id);
    if (cg == NULL) {
        (void)create_cgroup_gauge(cgroup_id);
        cg = get_cgroup_gauge(cgroup_id);
        if (cg == NULL) {
            return NULL;
        }
    }
    return cg;
}

KPROBE(try_charge, pt_regs)
{
    struct mem_cgroup *memcg = (struct mem_cgroup *)PT_REGS_PARM1(ctx);
    unsigned int nr_pages = (unsigned int)PT_REGS_PARM3(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();
    struct mem_cgroup_gauge* cg = lkup_memcg(memcg);
    if (cg == NULL) {
        return;
    }
    cg->nr_pages = max(nr_pages, cg->nr_pages);
    periodic_report(ctx, cg);
}

KPROBE(mem_cgroup_out_of_memory, pt_regs)
{
    struct mem_cgroup *memcg = (struct mem_cgroup *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();
    struct mem_cgroup_gauge* cg = lkup_memcg(memcg);
    if (cg == NULL) {
        return;
    }
    cg->oom_order++;
    periodic_report(ctx, cg);
}

KPROBE(__mem_cgroup_free, pt_regs)
{
    struct mem_cgroup *memcg = (struct mem_cgroup *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    del_cgroup_gauge(memcg);
}