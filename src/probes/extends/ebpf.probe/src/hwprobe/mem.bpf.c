/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lizhenxing
 * Create: 2023-05-18
 * Description: nic bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hw_args.h"

char g_linsence[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct mem_entity_s));
    __uint(value_size, sizeof(struct mc_event_s));
    __uint(max_entries, __HW_COUNT_MAX);
} mc_event_count_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} mc_event_channel_map SEC(".maps");

static __always_inline struct mc_event_s *get_mc_event(struct mem_entity_s *mem_entity)
{
    struct mc_event_s *mc_event = (struct mc_event_s *)bpf_map_lookup_elem(&mc_event_count_map, mem_entity);
    if (mc_event) {
        return mc_event;
    }

    struct mc_event_s new_mc_event = {0};
    new_mc_event.entity.err_type = mem_entity->err_type;
    __builtin_memcpy(&new_mc_event.entity.label, &mem_entity->label, LABEL_LEN);
    new_mc_event.entity.mc_index = mem_entity->mc_index;
    new_mc_event.entity.top_layer = mem_entity->top_layer;

    bpf_map_update_elem(&mc_event_count_map, mem_entity, &new_mc_event, BPF_ANY);
    return (struct mc_event_s *)bpf_map_lookup_elem(&mc_event_count_map, mem_entity);
}

static __always_inline void report_mc_event(void *ctx, struct mc_event_s* mc_event)
{
    if (is_report_tmout(&(mc_event->report_ts))) {

        (void)bpfbuf_output(ctx, &mc_event_channel_map, mc_event, sizeof(struct mc_event_s));
        mc_event->error_count = 0;
    }
}

KRAWTRACE(mc_event, bpf_raw_tracepoint_args)
{
    struct mem_entity_s mem_entity = {0};

    unsigned int   err_type      = (unsigned int)ctx->args[0];
    char *         label         = (char *)ctx->args[2];
    int            error_count   = (int)ctx->args[3];
    char           mc_index      = (char)ctx->args[4];
    char           top_layer     = (char)ctx->args[5];

    mem_entity.err_type = err_type;
    (void)bpf_core_read_str(&mem_entity.label, LABEL_LEN,  label);
    mem_entity.mc_index = mc_index;
    mem_entity.top_layer = top_layer;

    struct mc_event_s *mc_event = get_mc_event(&mem_entity);
    if (mc_event == NULL) {
        return 0;
    }

    __sync_fetch_and_add(&(mc_event->error_count), error_count);
    report_mc_event(ctx, mc_event);

    return 0;
}

SEC("tracepoint/ras/mc_event")
int bpf_trace_mc_event_func(struct trace_event_raw_mc_event *ctx)
{
    struct mem_entity_s mem_entity = {0};

    unsigned int   err_type      = (unsigned int)ctx->error_type;
    char *         label         = (char *)(u64)(ctx->__data_loc_label);
    int            error_count   = (int)ctx->error_count;
    char           mc_index      = (char)ctx->mc_index;
    char           top_layer     = (char)ctx->top_layer;

    mem_entity.err_type = err_type;
    (void)bpf_core_read_str(&mem_entity.label, LABEL_LEN,  label);
    mem_entity.mc_index = mc_index;
    mem_entity.top_layer = top_layer;

    struct mc_event_s *mc_event = get_mc_event(&mem_entity);
    if (mc_event == NULL) {
        return 0;
    }

    __sync_fetch_and_add(&(mc_event->error_count), error_count);
    report_mc_event(ctx, mc_event);

    return 0;
}
