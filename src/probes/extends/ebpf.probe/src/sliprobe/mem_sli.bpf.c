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
 * Create: 2024-04-17
 * Description: mem sli
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"

#include "sli.h"

char g_linsence[] SEC("license") = "GPL";

#define PF_IDLE			0x00000002	/* I am an IDLE thread */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */

struct task_mem_s {
	u64 start_ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct task_struct *));
    __uint(value_size, sizeof(struct task_mem_s));
    __uint(max_entries, 1000);
} task_mem_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} sli_mem_channel_map SEC(".maps");

static __always_inline void report_sli_mem(void *ctx, struct sli_mem_obj_s* sli_mem)
{
    if (is_report_tmout(&(sli_mem->last_report))) {
        (void)bpfbuf_output(ctx,
                            &sli_mem_channel_map,
                            sli_mem,
                            sizeof(struct sli_mem_obj_s));
        sli_mem->last_report = 0;
        __builtin_memset(&(sli_mem->sli), 0, sizeof(struct sli_mem_s));
    }
}

static __always_inline char is_filter_task(struct task_struct *task)
{
    unsigned int flags = BPF_CORE_READ(task, flags);
    return (char)((flags & PF_IDLE) || (flags & PF_KTHREAD));
}

static __always_inline int mem_sli_start(struct task_struct *task, void *ctx)
{
    if (is_filter_task(task)) {
        return 0;
    }

    struct task_mem_s mem = {0};
    mem.start_ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&task_mem_map, &task, &mem, BPF_ANY);
    return 0;
}

static __always_inline int mem_sli_end(struct task_struct *task, enum sli_mem_t type, void *ctx)
{
    struct task_mem_s* task_mem = bpf_map_lookup_elem(&task_mem_map, &task);
    if (task_mem) {
        u64 now = bpf_ktime_get_ns();
        if (now > task_mem->start_ts) {
            u64 delay = now - task_mem->start_ts;

            struct sli_mem_obj_s* sli_mem = get_sli_mem(task);
            if (sli_mem == NULL) {
                goto end;
            }

            enum sli_mem_lat_t idx = get_sli_mem_lat_type(delay);
            
            sli_mem->sli.mem_lats[type].cnt[idx]++;
            sli_mem->sli.lat_ns[type] += delay;

            report_sli_mem(ctx, sli_mem);
        }
    }
end:
    bpf_map_delete_elem(&task_mem_map, &task);
    return 0;
}

KPROBE(mem_cgroup_handle_over_high, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_start(task, ctx);
}

KRETPROBE(mem_cgroup_handle_over_high, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_end(task, SLI_MEM_RECLAIM, ctx);
}

KRAWTRACE(mm_vmscan_memcg_reclaim_begin, bpf_raw_tracepoint_args)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_start(task, ctx);
}

KRAWTRACE(mm_vmscan_memcg_reclaim_end, bpf_raw_tracepoint_args)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_end(task, SLI_MEM_RECLAIM, ctx);
}

KPROBE(do_swap_page, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_start(task, ctx);
}

KRETPROBE(do_swap_page, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_end(task, SLI_MEM_SWAPIN, ctx);
}

KPROBE(try_to_compact_pages, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_start(task, ctx);
}

KRETPROBE(try_to_compact_pages, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    return mem_sli_end(task, SLI_MEM_COMPACT, ctx);
}

