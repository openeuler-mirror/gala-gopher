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

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "tprofiling.h"

static __always_inline int init_oncpu_sample_data(oncpu_sample_data_t *sample_d, void *ctx)
{
    sample_d->time = bpf_ktime_get_ns();
    sample_d->cpu = bpf_get_smp_processor_id();

    __builtin_memset(&sample_d->stats_stack, 0, sizeof(struct stats_stack_elem));
    // TODO: add kid if need
    if (stats_append_stack(&sample_d->stats_stack, 0, ctx)) {   // 堆栈获取失败，没必要上报
        return -1;
    }
    return 0;
}

static __always_inline trace_event_data_t *create_perf_event(void *ctx)
{
    trace_event_data_t *evt_data;
    int ret;

    evt_data = new_trace_event();
    if (!evt_data) {
        return NULL;
    }
    init_trace_event_common(evt_data, EVT_TYPE_ONCPU_PERF);
    ret = init_oncpu_sample_data(&evt_data->sample_d, ctx);
    if (ret) {
        return NULL;
    }

    return evt_data;
}

bpf_section("perf_event")
int bpf_perf_event_func(struct bpf_perf_event_data *ctx)
{
    trace_event_data_t *evt_data;
    void *cur_event_map;

    if (!is_proc_thrd_enabled()) {
        return 0;
    }

    evt_data = create_perf_event(ctx);
    if (!evt_data) {
        return 0;
    }
    cur_event_map = bpf_get_current_event_map();
    if (cur_event_map) {
        bpfbuf_output(ctx, cur_event_map, evt_data, sizeof(trace_event_data_t));
    }

    return 0;
}


char g_license[] SEC("license") = "Dual BSD/GPL";