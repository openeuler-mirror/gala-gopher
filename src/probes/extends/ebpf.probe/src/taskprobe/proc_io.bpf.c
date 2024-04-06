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
 * Create: 2022-07-13
 * Description: Collecting Task I/O Data
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "task.h"
#include "proc.h"
#include "proc_map.h"
#include "output_proc.h"

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)
#define BIG_BIO_SIZE (4 * 1024)

char g_linsence[] SEC("license") = "GPL";

struct proc_bio_stats_s {
    u64 proc_id;
    u64 start_ts;
};

#define __BIO_MAX      1000
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct bio*));
    __uint(value_size, sizeof(struct proc_bio_stats_s));
    __uint(max_entries, __BIO_MAX);
} bio_map SEC(".maps");

static __always_inline char is_read_bio(struct bio *bio)
{
    u32 op = _(bio->bi_opf);
    return ((op & REQ_OP_MASK) == REQ_OP_READ);
}

static __always_inline char is_write_bio(struct bio *bio)
{
    u32 op = _(bio->bi_opf);
    return ((op & REQ_OP_MASK) == REQ_OP_WRITE) ||
        ((op & REQ_OP_MASK) == REQ_OP_FLUSH);
}

static __always_inline int store_bio(struct bio *bio, int proc_id)
{
    struct proc_bio_stats_s bio_stats = {0};
    bio_stats.proc_id = (u64)proc_id;
    bio_stats.start_ts = bpf_ktime_get_ns();
    return bpf_map_update_elem(&bio_map, &bio, &bio_stats, BPF_ANY);
}

static __always_inline int is_err_bio(struct bio *bio)
{
    return (_(bio->bi_status) != 0);
}

static __always_inline void end_bio(void *ctx, struct bio *bio)
{
    struct proc_bio_stats_s *bio_stats = bpf_map_lookup_elem(&bio_map, &bio);
    if (bio_stats == NULL) {
        return;
    }
    struct proc_data_s *proc;

    proc = get_proc_entry((u32)bio_stats->proc_id);
    if (proc == NULL) {
        (void)bpf_map_delete_elem(&bio_map, &bio);
        return;
    }

    if (is_err_bio(bio)) {
        __sync_fetch_and_add(&(proc->proc_io.bio_err_count), 1);
        report_proc(ctx, proc, TASK_PROBE_IO);
    } else {
        u64 end_ts = bpf_ktime_get_ns();
        if (end_ts > bio_stats->start_ts) {
            u64 delta = end_ts - bio_stats->start_ts;
            proc->proc_io.bio_latency = max(proc->proc_io.bio_latency, delta);
            report_proc(ctx, proc, TASK_PROBE_IO);
        }
    }

    (void)bpf_map_delete_elem(&bio_map, &bio);
    return;
}

static __always_inline void start_bio(void *ctx, u32 proc_id, struct bio *bio)
{
    u32 bio_size;
    struct proc_data_s *proc;

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return;
    }

    if (is_read_bio(bio)) {
        bio_size = _(bio->bi_iter.bi_size);
        if (bio_size > BIG_BIO_SIZE) {
            __sync_fetch_and_add(&(proc->proc_io.greater_4k_io_read), 1);
        } else {
            __sync_fetch_and_add(&(proc->proc_io.less_4k_io_read), 1);
        }
        report_proc(ctx, proc, TASK_PROBE_IO);

        store_bio(bio, proc_id);
        return;
    }

    if (is_write_bio(bio)) {
        bio_size = _(bio->bi_iter.bi_size);
        if (bio_size > BIG_BIO_SIZE) {
            __sync_fetch_and_add(&(proc->proc_io.greater_4k_io_write), 1);
        } else {
            __sync_fetch_and_add(&(proc->proc_io.less_4k_io_write), 1);
        }
        report_proc(ctx, proc, TASK_PROBE_IO);

        store_bio(bio, proc_id);
        return;
    }
    return;
}

bpf_section("raw_tracepoint/block_bio_queue") \
int bpf_raw_trace_block_bio_queue_single_arg(struct bpf_raw_tracepoint_args* ctx)
{
    struct bio *bio = (struct bio*)ctx->args[0];
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    start_bio(ctx, proc_id, bio);

    return 0;
}

bpf_section("raw_tracepoint/block_bio_queue") \
int bpf_raw_trace_block_bio_queue_double_arg(struct bpf_raw_tracepoint_args* ctx)
{
    struct bio *bio = (struct bio*)ctx->args[1];
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    start_bio(ctx, proc_id, bio);

    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 1000);
} bio_args_buffer SEC(".maps");

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
    start_bio(ctx, (u32)(key >> INT_LEN), bio);

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

KRAWTRACE(sched_process_hang, bpf_raw_tracepoint_args)
{
    struct proc_data_s *proc;
    struct task_struct* task = (struct task_struct*)ctx->args[0];
    u32 proc_id = (u32)_(task->tgid);
    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return 0;
    }
    __sync_fetch_and_add(&(proc->proc_io.hang_count), 1);
    report_proc(ctx, proc, TASK_PROBE_IO);
    return 0;
}

SEC("tracepoint/sched/sched_process_hang")
int bpf_trace_sched_process_hang_func(struct trace_event_raw_sched_process_hang *ctx)
{
    struct proc_data_s *proc;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;
    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return 0;
    }
    __sync_fetch_and_add(&(proc->proc_io.hang_count), 1);
    report_proc(ctx, proc, TASK_PROBE_IO);
    return 0;
}
