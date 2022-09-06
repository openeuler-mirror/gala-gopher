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
 * Create: 2022-07-8
 * Description: page cache bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "output.h"
#include "block.h"

char g_linsence[] SEC("license") = "GPL";

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))

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

KPROBE(mark_page_accessed, pt_regs)
{
    struct block_key key;
    struct block_data *bdata;
    struct page *page = (struct page *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    if (buffer_head_to_blk(page_to_buffer_head(page), &key.major, &key.first_minor)) {
        return;
    }

    bdata = get_block_entry(&key);
    if (!bdata) {
        return;
    }

    __sync_fetch_and_add(&(bdata->pc_stats.access_pagecache), 1);

    report_blk(ctx, bdata);
}


KPROBE(mark_buffer_dirty, pt_regs)
{
    struct block_key key;
    struct block_data *bdata;
    struct buffer_head *bh = (struct buffer_head *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    if (buffer_head_to_blk(bh, &key.major, &key.first_minor)) {
        return;
    }

    bdata = get_block_entry(&key);
    if (!bdata) {
        return;
    }

    __sync_fetch_and_add(&(bdata->pc_stats.mark_buffer_dirty), 1);
    report_blk(ctx, bdata);
}


KPROBE(add_to_page_cache_lru, pt_regs)
{
    struct block_key key;
    struct block_data *bdata;
    struct page *page = (struct page *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    if (buffer_head_to_blk(page_to_buffer_head(page), &key.major, &key.first_minor)) {
        return;
    }

    bdata = get_block_entry(&key);
    if (!bdata) {
        return;
    }

    __sync_fetch_and_add(&(bdata->pc_stats.load_page_cache), 1);
    report_blk(ctx, bdata);
}

KPROBE(account_page_dirtied, pt_regs)
{
    struct block_key key;
    struct block_data *bdata;
    struct page *page = (struct page *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    if (buffer_head_to_blk(page_to_buffer_head(page), &key.major, &key.first_minor)) {
        return;
    }

    bdata = get_block_entry(&key);
    if (!bdata) {
        return;
    }

    __sync_fetch_and_add(&(bdata->pc_stats.mark_page_dirty), 1);
    report_blk(ctx, bdata);
}
