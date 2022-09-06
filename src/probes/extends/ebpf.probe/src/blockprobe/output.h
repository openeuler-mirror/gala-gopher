/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 */
#ifndef __OUTPUT_H__
#define __OUTPUT_H__

#pragma once

#ifdef BPF_PROG_KERN

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "blockprobe.h"

#define BPF_F_INDEX_MASK    0xffffffffULL
#define BPF_F_ALL_CPU   BPF_F_INDEX_MASK

#ifndef __PERF_OUT_MAX
#define __PERF_OUT_MAX (64)
#endif
struct bpf_map_def SEC("maps") output = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = __PERF_OUT_MAX,
};

// Data collection args
struct bpf_map_def SEC("maps") args_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),    // const value 0
    .value_size = sizeof(struct block_args_s),  // block args
    .max_entries = 1,
};

#ifndef __PERIOD
#define __PERIOD NS(30)
#endif
static __always_inline u64 get_period()
{
    u32 key = 0;
    u64 period = __PERIOD;

    struct block_args_s *args;
    args = (struct block_args_s *)bpf_map_lookup_elem(&args_map, &key);
    if (args) {
        period = args->period;
    }

    return period; // units from second to nanosecond
}

static __always_inline __maybe_unused void report(void *ctx, struct block_data *bdata)
{
    bdata->ts = 0;  // Start a new statistical period
    (void)bpf_perf_event_output(ctx, &output, BPF_F_ALL_CPU, bdata, sizeof(struct block_data));

    __builtin_memset(&(bdata->blk_stats), 0x0, sizeof(bdata->blk_stats));
    __builtin_memset(&(bdata->blk_drv_stats), 0x0, sizeof(bdata->blk_drv_stats));
    __builtin_memset(&(bdata->blk_dev_stats), 0x0, sizeof(bdata->blk_dev_stats));
    __builtin_memset(&(bdata->iscsi_err_stats), 0x0, sizeof(bdata->iscsi_err_stats));
    __builtin_memset(&(bdata->conn_stats), 0x0, sizeof(bdata->conn_stats));
    __builtin_memset(&(bdata->sas_stats), 0x0, sizeof(bdata->sas_stats));
    __builtin_memset(&(bdata->pc_stats), 0x0, sizeof(bdata->pc_stats));
}

static __always_inline __maybe_unused void report_blk(void *ctx, struct block_data *bdata)
{
    __u64 ts = bpf_ktime_get_ns();
    __u64 period = get_period();

    // first calc
    if (bdata->ts == 0) {
        bdata->ts = ts;
        return;
    }

    // calculation of intra-period
    if ((ts > bdata->ts) && ((ts - bdata->ts) >= period)) {
        report(ctx, bdata);
    }
}


#endif
#endif
