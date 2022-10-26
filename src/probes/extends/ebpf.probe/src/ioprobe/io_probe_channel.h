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
#include "io_trace.h"

#define BPF_F_INDEX_MASK    0xffffffffULL
#define BPF_F_ALL_CPU   BPF_F_INDEX_MASK

#ifndef __PERF_OUT_MAX
#define __PERF_OUT_MAX (64)
#endif
struct bpf_map_def SEC("maps") io_latency_channel_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = __PERF_OUT_MAX,
};

struct bpf_map_def SEC("maps") io_err_channel_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = __PERF_OUT_MAX,
};

// Data collection args
struct bpf_map_def SEC("maps") io_args_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),    // const value 0
    .value_size = sizeof(struct io_trace_args_s),  // args
    .max_entries = 1,
};

#define __DEFAULT_REPORT_PERIOD (__u64)((__u64)30 * 1000000000)
static __always_inline u64 get_report_period()
{
    u32 key = 0;
    u64 period = __DEFAULT_REPORT_PERIOD;

    struct io_trace_args_s *args;
    args = (struct io_trace_args_s *)bpf_map_lookup_elem(&io_args_map, &key);
    if (args != NULL && args->report_period != 0) {
        period = args->report_period;
    }

    return period;
}

static __always_inline u64 get_sample_interval()
{
    u32 key = 0;
    u64 interval = 0;   // default

    struct io_trace_args_s *args;
    args = (struct io_trace_args_s *)bpf_map_lookup_elem(&io_args_map, &key);
    if (args) {
        interval = args->sample_interval;
    }

    return interval;
}

static __always_inline char is_target_dev(int major, int first_minor)
{
    u32 key = 0;

    struct io_trace_args_s *args;
    args = (struct io_trace_args_s *)bpf_map_lookup_elem(&io_args_map, &key);
    if (args && args->target_major != 0) {
        return (args->target_major == major && args->target_first_minor == first_minor) ? 1 : 0;
    }

    return 1;
}

static __always_inline __maybe_unused char is_report_tmout(struct io_latency_s* io_latency)
{
    if (io_latency->ts == 0) {
        io_latency->ts = bpf_ktime_get_ns();
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 report_period = get_report_period();
    if ((ts > io_latency->ts) && ((ts - io_latency->ts) >= report_period)) {
        return 1;
    }
    return 0;
}

static __always_inline __maybe_unused void report_io_latency(void *ctx, struct io_latency_s* io_latency)
{
    if (is_report_tmout(io_latency)) {
        (void)bpf_perf_event_output(ctx,
                                    &io_latency_channel_map,
                                    BPF_F_ALL_CPU,
                                    io_latency,
                                    sizeof(struct io_latency_s));
        io_latency->proc_id = 0;
        io_latency->data_len = 0;
        io_latency->err_count = 0;
        io_latency->ts = 0;
        __builtin_memset(io_latency->comm, 0, sizeof(io_latency->comm));
        __builtin_memset(io_latency->rwbs, 0, sizeof(io_latency->rwbs));
        __builtin_memset(io_latency->latency, 0, sizeof(io_latency->latency));
    }
}

static __always_inline __maybe_unused void report_io_err(void *ctx, struct io_err_s* io_err)
{
    (void)bpf_perf_event_output(ctx, &io_err_channel_map, BPF_F_ALL_CPU, io_err, sizeof(struct io_err_s));
}

#endif
#endif
