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

#include "bpf.h"
#include "sched.h"

#define BPF_F_INDEX_MASK    0xffffffffULL
#define BPF_F_ALL_CPU   BPF_F_INDEX_MASK

#ifndef __PERF_OUT_MAX
#define __PERF_OUT_MAX (64)
#endif
struct bpf_map_def SEC("maps") sched_report_channel_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = __PERF_OUT_MAX,
};

// Data collection args
struct bpf_map_def SEC("maps") sched_args_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),    // const value 0
    .value_size = sizeof(struct sched_args_s),  // args
    .max_entries = 1,
};

#define __DEFAULT_LAT_THR (__u64)((__u64)5 * 1000000000)  // 5 s
static __always_inline __maybe_unused u64 get_lat_thr(void)
{
    u32 key = 0;
    u64 thr = __DEFAULT_LAT_THR;

    struct sched_args_s *args;
    args = (struct sched_args_s *)bpf_map_lookup_elem(&sched_args_map, &key);
    if (args != NULL && args->latency_thr != 0) {
        thr = args->latency_thr;
    }

    return thr;
}

#define __COMP_ARRAY(src, dst, size, ret) \
    do {\
        ret = 0; \
        int __index; \
        for (__index = 0; __index < size; __index++) \
        { \
            if (src[__index] != dst[__index]) { \
                ret = 1; \
                break; \
            } \
        } \
    } while (0)

static __always_inline __maybe_unused char is_targe_comm(char *comm, u32 proc_id)
{
    u32 key = 0;

    struct sched_args_s *args;
    args = (struct sched_args_s *)bpf_map_lookup_elem(&sched_args_map, &key);
    if (args == NULL) {
        return 1;
    }

    if (args->is_target_wl) {
        struct proc_s obj = {.proc_id = proc_id};
        return is_proc_exist(&obj);
    }

    if (args->target_comm[0] == 0) {
        return 1;
    }

    int ret;
    __COMP_ARRAY(args->target_comm, comm, TASK_COMM_LEN, ret);
    if (ret == 0) {
        return 1;
    }
    return 0;
}


#endif
#endif
