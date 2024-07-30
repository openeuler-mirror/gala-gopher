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

#include "sli.h"

char g_linsence[] SEC("license") = "GPL";

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)
#define PF_IDLE			0x00000002	/* I am an IDLE thread */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */

struct bio_stats_s {
    u64 start_ts;
    struct task_struct *task;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(cpu_cgrp_inode_t));
    __uint(value_size, sizeof(struct sli_io_obj_s));
    __uint(max_entries, 1000);
} sli_io_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 1000);
} bio_args_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} sli_io_channel_map SEC(".maps");

#define __BIO_MAX      1000
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct bio*));
    __uint(value_size, sizeof(struct bio_stats_s));
    __uint(max_entries, __BIO_MAX);
} bio_map SEC(".maps");

static __always_inline struct sli_io_obj_s* lkup_sli_io(cpu_cgrp_inode_t ino)
{
    return (struct sli_io_obj_s *)bpf_map_lookup_elem(&sli_io_map, &ino);
}

static __always_inline struct sli_io_obj_s* get_sli_io(struct task_struct *task)
{
    cpu_cgrp_inode_t ino;
    if (get_current_cpuacct_ino(&ino, task)) {
        return NULL;
    }

    return lkup_sli_io(ino);
}

static __always_inline char is_filter_task(struct task_struct *task)
{
    unsigned int flags = BPF_CORE_READ(task, flags);
    return (char)((flags & PF_IDLE) || (flags & PF_KTHREAD));
}

static __always_inline void report_sli_io(void *ctx, struct sli_io_obj_s *sli_io, u64 now)
{
    if (is_report_tmout(&(sli_io->last_report))) {
        (void)bpfbuf_output(ctx,
                            &sli_io_channel_map,
                            sli_io,
                            sizeof(struct sli_io_obj_s));
        sli_io->last_report = now;
        __builtin_memset(&(sli_io->sli), 0, sizeof(struct sli_io_s));
    }
}

static __always_inline char is_rw_bio(struct bio *bio)
{
    u32 op = _(bio->bi_opf);

    return ((op & REQ_OP_MASK) == REQ_OP_READ) ||
        ((op & REQ_OP_MASK) == REQ_OP_WRITE) ||
        ((op & REQ_OP_MASK) == REQ_OP_FLUSH);
}

static __always_inline int is_err_bio(struct bio *bio)
{
    return (_(bio->bi_status) != 0);
}

static __always_inline void end_bio(void *ctx, struct bio *bio)
{
    struct bio_stats_s *bio_stats = bpf_map_lookup_elem(&bio_map, &bio);
    if (bio_stats == NULL) {
        return;
    }

    if (!is_err_bio(bio)) {
        u64 end_ts = bpf_ktime_get_ns();
        if (end_ts > bio_stats->start_ts) {
            struct sli_io_obj_s* sli_io = get_sli_io(bio_stats->task);
            if (sli_io == NULL) {
                goto end;
            }

            u64 delay = end_ts - bio_stats->start_ts;
            enum sli_io_lat_t idx = get_sli_io_lat_type(delay);

            sli_io->sli.io_lats.cnt[idx]++;
            sli_io->sli.lat_ns += delay;

            report_sli_io(ctx, sli_io, end_ts);
        }
    }

end:
    (void)bpf_map_delete_elem(&bio_map, &bio);
    return;
}

static __always_inline void start_bio(void *ctx, struct task_struct *task, struct bio *bio)
{
    if (is_filter_task(task)) {
        return;
    }

    struct sli_io_obj_s* sli_io = get_sli_io(task);
    if (sli_io == NULL) {
        return;
    }

    if (is_rw_bio(bio)) {
        struct bio_stats_s bio_stats = {0};
        bio_stats.task = task;
        bio_stats.start_ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&bio_map, &bio, &bio_stats, BPF_ANY);
    }

    return;
}

bpf_section("raw_tracepoint/block_bio_queue") \
int bpf_raw_trace_block_bio_queue_single_arg(struct bpf_raw_tracepoint_args* ctx)
{
    struct bio *bio = (struct bio*)ctx->args[0];

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    start_bio(ctx, task, bio);
    return 0;
}

bpf_section("raw_tracepoint/block_bio_queue") \
int bpf_raw_trace_block_bio_queue_double_arg(struct bpf_raw_tracepoint_args* ctx)
{
    struct bio *bio = (struct bio*)ctx->args[1];

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    start_bio(ctx, task, bio);
    return 0;
}

KPROBE(generic_make_request_checks, pt_regs)
{
    u64 key = bpf_get_current_pid_tgid();
    u64 value = (u64)PT_REGS_PARM1(ctx);
    (void)bpf_map_update_elem(&bio_args_buffer, &key, &value, BPF_ANY);
    return 0;
}

KRETPROBE(generic_make_request_checks, pt_regs)
{
    struct bio *bio = NULL;
    u64 *bio_args = NULL;
    u64 key = bpf_get_current_pid_tgid();
    bool ret = (bool)PT_REGS_RC(ctx);
    if (ret == false) {
        goto end;
    }

    bio_args = (u64 *)bpf_map_lookup_elem(&bio_args_buffer, &key);
    if (bio_args == NULL) {
        goto end;
    }
    bio = (struct bio *)(*bio_args);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    start_bio(ctx, task, bio);

end:
    (void)bpf_map_delete_elem(&bio_args_buffer, &key);
    return 0;
}

// block_bio_complete, block_rq_complete exclusion, so use kprobe
KPROBE(bio_endio, pt_regs)
{
    struct bio *bio = (struct bio*)PT_REGS_PARM1(ctx);

    end_bio(ctx, bio);
    return 0;
}
