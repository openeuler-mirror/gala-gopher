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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "io_probe_channel.h"

char g_linsence[] SEC("license") = "GPL";

#define __IO_COUNT_MAX      100
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct io_entity_s));
    __uint(value_size, sizeof(struct io_count_s));
    __uint(max_entries, __IO_COUNT_MAX);
} io_count_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} io_count_channel_map SEC(".maps");


struct block_bio_queue_args {
    struct trace_entry ent;
    dev_t dev;
    sector_t sector;
    unsigned int nr_sector;
    char rwbs[RWBS_LEN];
    char comm[TASK_COMM_LEN];
};

static __always_inline void report_io_count(void *ctx, struct io_count_s* io_count)
{
    if (is_report_tmout(&(io_count->io_count_ts))) {
        (void)bpfbuf_output(ctx,
                            &io_count_channel_map,
                            io_count,
                            sizeof(struct io_count_s));
        io_count->read_bytes = 0;
        io_count->write_bytes = 0;
        io_count->io_count_ts.ts = 0;
    }
}

static __always_inline struct io_count_s* get_io_count(int major, int minor)
{
    struct io_entity_s io_entity = {.major = major, .first_minor = minor};

    struct io_count_s* io_count = (struct io_count_s *)bpf_map_lookup_elem(&io_count_map, &io_entity);
    if (io_count) {
        return io_count;
    }

    if (!is_target_dev(major, minor)) {
        return NULL;
    }

    struct io_count_s new_io_count = {0};
    new_io_count.major = major;
    new_io_count.first_minor = minor;
    bpf_map_update_elem(&io_count_map, &io_entity, &new_io_count, BPF_ANY);
    return (struct io_count_s *)bpf_map_lookup_elem(&io_count_map, &io_entity);
}

static __always_inline char is_read_bio(struct block_bio_queue_args *bio)
{
    if ((bio->rwbs[0] == 'R' || bio->rwbs[1] == 'R')) {
        return 1;
    }
    return 0;
}

static __always_inline char is_write_bio(struct block_bio_queue_args *bio)
{
    if ((bio->rwbs[0] == 'W' || bio->rwbs[1] == 'W')) {
        return 1;
    }

    if ((bio->rwbs[0] == 'F' || bio->rwbs[1] == 'F')) {
        return 1;
    }

    return 0;
}

bpf_section("tracepoint/block/block_bio_queue")
void tracepoint_block_bio_queue(struct block_bio_queue_args *ctx)
{
    u32 bio_size;
    int major, minor;
    struct io_count_s* io_count;
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    major = MAJOR(ctx->dev);
    minor = MINOR(ctx->dev);

    io_count = get_io_count(major, minor);
    if (!io_count) {
        return;
    }

    bio_size = ctx->nr_sector * 512;

    if (is_read_bio(ctx)) {
        __sync_fetch_and_add(&(io_count->read_bytes), bio_size);
        report_io_count(ctx, io_count);
        return;
    }

    if (is_write_bio(ctx)) {
        __sync_fetch_and_add(&(io_count->write_bytes), bio_size);
        report_io_count(ctx, io_count);
        return;
    }
}


