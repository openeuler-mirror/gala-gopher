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
 * Create: 2022-02-22
 * Description: block probe bpf prog
 ******************************************************************************/
#ifndef __BLOCK__H
#define __BLOCK__H

#pragma once

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "blockprobe.h"

struct bpf_map_def SEC("maps") scsi_block_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct block_key),
    .max_entries = 1,
};

static __always_inline __maybe_unused struct block_key* get_scsi_block()
{
    u32 flag = 0;
    return (struct block_key *)bpf_map_lookup_elem(&scsi_block_map, &flag);
}

#define __BLOCK_NUM     128
struct bpf_map_def SEC("maps") block_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct block_key),
    .value_size = sizeof(struct block_data),
    .max_entries = __BLOCK_NUM,
};

#define CALC_LATENCY_STATS(stats, type, delta) \
    do \
    {\
        __u64 __jitter; \
        stats->type##_max = \
            stats->type##_max > delta ? stats->type##_max : delta; \
        stats->type##_sum += delta; \
        if (stats->type##_last > delta) {\
            __jitter = stats->type##_last - delta; \
        } else { \
            __jitter = delta - stats->type##_last; \
        } \
        stats->type##_jitter = (__jitter > stats->type##_jitter ? __jitter : stats->type##_jitter); \
        stats->count_##type++; \
        stats->type##_last = delta; \
    } while (0)


#define INIT_LATENCY_STATS(stats, type, delta) \
    do \
    {\
        stats->type##_max = delta; \
        stats->type##_last = delta; \
        stats->type##_sum = delta; \
        stats->type##_jitter = 0; \
        stats->count_##type = 1; \
    } while (0)

static __always_inline __maybe_unused __u64 get_delta_time_ns(struct request *req, __u64 ts)
{
    __u64 start_time_ns = _(req->start_time_ns);
    
    if ((start_time_ns != 0) && (ts > start_time_ns)) {
        return (__u64)(ts - start_time_ns);
    }

    return 0;
}

static __always_inline __maybe_unused struct block_data *get_block_entry(struct block_key *key)
{
    return (struct block_data *)bpf_map_lookup_elem(&block_map, key);
}

static __always_inline __maybe_unused void get_block_key_by_req(struct request *req, struct block_key *key)
{
    struct gendisk *disk = _(req->rq_disk);

    key->major = _(disk->major);
    key->first_minor = _(disk->first_minor);
}

static __always_inline __maybe_unused void report_latency(void *ctx, struct block_data *bdata,
        struct latency_stats *latency_stats, __u64 delta, __u64 ts)
{
    if (delta == 0) {
        return;
    }
    __u64 us = delta >> 3;
    __u64 period = get_period();

    // first calc
    if (bdata->ts == 0) {
        INIT_LATENCY_STATS(latency_stats, latency, us);
        bdata->ts = ts;
        return;
    }

    // calculation of intra-period
    if (ts > bdata->ts) {
        if ((ts - bdata->ts) < period) {
            CALC_LATENCY_STATS(latency_stats, latency, us);
        } else {
            report(ctx, bdata);
        }
    } else {
        bdata->ts = 0; // error
    }
}

#endif
