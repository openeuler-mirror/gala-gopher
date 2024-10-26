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
 * Create: 2024-10-09
 * Description: Python GC eBPF prog
 ******************************************************************************/
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif
#define BPF_PROG_USER
#include "bpf.h"
#include "pygc_bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} gc_output SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(context_id));
    __uint(value_size, sizeof(struct pygc_evt_s));
    __uint(max_entries, 1000);
} pygc_evt_map SEC(".maps");

static __always_inline __maybe_unused void report_gc_evt(void *ctx, struct pygc_evt_s *gc_evt)
{
    (void)bpfbuf_output(ctx, &gc_output, gc_evt, sizeof(struct pygc_evt_s));
}

UPROBE(collect_with_callback, pt_regs)
{
    struct pygc_evt_s evt = {0};
    context_id id = bpf_get_current_pid_tgid();

    evt.id = id;
    evt.start_time = bpf_ktime_get_ns();
    (void)bpf_map_update_elem(&pygc_evt_map, &id, &evt, BPF_ANY);
    return 0;
}

URETPROBE(collect_with_callback, pt_regs)
{
    struct pygc_evt_s *gc_evt;
    context_id id = bpf_get_current_pid_tgid();

    gc_evt = (struct pygc_evt_s *)bpf_map_lookup_elem(&pygc_evt_map, &id);
    if (!gc_evt) {
        return 0;
    }

    gc_evt->end_time = bpf_ktime_get_ns();
    if (gc_evt->end_time < gc_evt->start_time + GC_1MS) {
        goto out;
    }

    report_gc_evt(ctx, gc_evt);
out:
    (void)bpf_map_delete_elem(&pygc_evt_map, &id);
    return 0;
}

char g_license[] SEC("license") = "Dual BSD/GPL";
