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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} io_latency_channel_map SEC(".maps");

// Data collection args
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32)); // const value 0
    __uint(value_size, sizeof(struct io_trace_args_s));
    __uint(max_entries, 1);
} io_args_map SEC(".maps");


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

static __always_inline __maybe_unused u64 get_sample_interval()
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

static __always_inline __maybe_unused char is_report_tmout(struct io_report_s* io_report)
{
    if (io_report->ts == 0) {
        io_report->ts = bpf_ktime_get_ns();
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 report_period = get_report_period();
    if ((ts > io_report->ts) && ((ts - io_report->ts) >= report_period)) {
        return 1;
    }
    return 0;
}

static __always_inline __maybe_unused void report_io_latency(void *ctx, struct io_latency_s* io_latency)
{
    if (is_report_tmout(&(io_latency->io_latency_ts))) {
        (void)bpfbuf_output(ctx,
                            &io_latency_channel_map,
                            io_latency,
                            sizeof(struct io_latency_s));
        io_latency->proc_id = 0;
        io_latency->data_len = 0;
        io_latency->io_latency_ts.ts = 0;
        __builtin_memset(io_latency->comm, 0, sizeof(io_latency->comm));
        __builtin_memset(io_latency->rwbs, 0, sizeof(io_latency->rwbs));
        __builtin_memset(io_latency->latency, 0, sizeof(io_latency->latency));
    }
}

#endif
#endif
