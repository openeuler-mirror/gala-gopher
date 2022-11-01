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
 * Author: luzhihao
 * Create: 2022-10-8
 * Description: page cache bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "io_probe_channel.h"

char g_linsence[] SEC("license") = "GPL";

#ifndef __PERF_OUT_MAX
#define __PERF_OUT_MAX (64)
#endif
struct bpf_map_def SEC("maps") page_cache_channel_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = __PERF_OUT_MAX,
};

#define __PAGECACHE_ENTRIES_MAX (100)
struct bpf_map_def SEC("maps") page_cache_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct pagecache_entity_s),
    .value_size = sizeof(struct pagecache_stats_s),
    .max_entries = __PAGECACHE_ENTRIES_MAX,
};

static __always_inline int buffer_head_to_blk(struct buffer_head *bh, int *major, int *minor)
{
    if (bh == NULL) {
        return -1;
    }

    struct block_device *bd = _(bh->b_bdev);
    if (bd == NULL) {
        return -1;
    }

    dev_t devt = _(bd->bd_dev);
    *major = MAJOR(devt);
    *minor = MINOR(devt);
    return 0;
}

static __always_inline struct buffer_head * page_to_buffer_head(struct page *page)
{
    unsigned long flags = _(page->flags);

    if (!(flags & (1UL << PG_mappedtodisk))) {
        return NULL;
    }

    long unsigned int private = _(page->private);
    return (struct buffer_head *)private;
}

static __always_inline void create_page_cache(int major, int minor)
{
    struct pagecache_entity_s pagecache_entity = {.major = major, .first_minor = minor};
    struct pagecache_stats_s pagecache_stats = {0};

    pagecache_stats.major = major;
    pagecache_stats.first_minor = minor;
    bpf_map_update_elem(&page_cache_map, &pagecache_entity, &pagecache_stats, BPF_ANY);
}

static __always_inline struct pagecache_stats_s *lkup_page_cache(struct pagecache_entity_s *pagecache_entity)
{
    return (struct pagecache_stats_s *)bpf_map_lookup_elem(&page_cache_map, pagecache_entity);
}

static __always_inline struct pagecache_stats_s *get_page_cache(struct pagecache_entity_s *pagecache_entity)
{
    struct pagecache_stats_s *pagecache_stats = NULL;

    pagecache_stats = lkup_page_cache(pagecache_entity);
    if (!is_target_dev(pagecache_entity->major, pagecache_entity->first_minor)) {
        return NULL;
    }
    if (pagecache_stats != NULL) {
        return pagecache_stats;
    }
    create_page_cache(pagecache_entity->major, pagecache_entity->first_minor);
    return lkup_page_cache(pagecache_entity);
}

static __always_inline void report_page_cache(void *ctx, struct pagecache_stats_s* page_cache)
{
    if (is_report_tmout(&(page_cache->page_cache_ts))) {
        (void)bpf_perf_event_output(ctx,
                                    &page_cache_channel_map,
                                    BPF_F_ALL_CPU,
                                    page_cache,
                                    sizeof(struct pagecache_stats_s));
        page_cache->access_pagecache = 0;
        page_cache->mark_buffer_dirty = 0;
        page_cache->load_page_cache = 0;
        page_cache->mark_page_dirty = 0;
        page_cache->page_cache_ts.ts = 0;
    }
}

KPROBE(mark_page_accessed, pt_regs)
{
    struct pagecache_entity_s pagecache_entity;
    struct pagecache_stats_s *page_cache_stats;
    struct page *page = (struct page *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    if (buffer_head_to_blk(page_to_buffer_head(page), &pagecache_entity.major, &pagecache_entity.first_minor)) {
        return;
    }

    page_cache_stats = get_page_cache(&pagecache_entity);
    if (!page_cache_stats) {
        return;
    }

    __sync_fetch_and_add(&(page_cache_stats->access_pagecache), 1);

    report_page_cache(ctx, page_cache_stats);
}


KPROBE(mark_buffer_dirty, pt_regs)
{
    struct pagecache_entity_s pagecache_entity;
    struct pagecache_stats_s *page_cache_stats;
    struct buffer_head *bh = (struct buffer_head *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    if (buffer_head_to_blk(bh, &pagecache_entity.major, &pagecache_entity.first_minor)) {
        return;
    }

    page_cache_stats = get_page_cache(&pagecache_entity);
    if (!page_cache_stats) {
        return;
    }

    __sync_fetch_and_add(&(page_cache_stats->mark_buffer_dirty), 1);
    report_page_cache(ctx, page_cache_stats);
}


KPROBE(add_to_page_cache_lru, pt_regs)
{
    struct pagecache_entity_s pagecache_entity;
    struct pagecache_stats_s *page_cache_stats;
    struct page *page = (struct page *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    if (buffer_head_to_blk(page_to_buffer_head(page), &pagecache_entity.major, &pagecache_entity.first_minor)) {
        return;
    }

    page_cache_stats = get_page_cache(&pagecache_entity);
    if (!page_cache_stats) {
        return;
    }

    __sync_fetch_and_add(&(page_cache_stats->load_page_cache), 1);
    report_page_cache(ctx, page_cache_stats);
}

KPROBE(account_page_dirtied, pt_regs)
{
    struct pagecache_entity_s pagecache_entity;
    struct pagecache_stats_s *page_cache_stats;
    struct page *page = (struct page *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    if (buffer_head_to_blk(page_to_buffer_head(page), &pagecache_entity.major, &pagecache_entity.first_minor)) {
        return;
    }

    page_cache_stats = get_page_cache(&pagecache_entity);
    if (!page_cache_stats) {
        return;
    }

    __sync_fetch_and_add(&(page_cache_stats->mark_page_dirty), 1);
    report_page_cache(ctx, page_cache_stats);
}
