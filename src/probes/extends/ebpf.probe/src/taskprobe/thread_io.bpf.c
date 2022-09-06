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
#include "task_map.h"
#include "output_task.h"

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

char g_linsence[] SEC("license") = "GPL";

#define __BIO_MAX      1000
struct bpf_map_def SEC("maps") bio_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct bio*),
    .value_size = sizeof(int),  // pid
    .max_entries = __BIO_MAX,
};

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

static __always_inline int store_bio(struct bio *bio, int pid)
{
    return bpf_map_update_elem(&bio_map, &bio, &pid, BPF_ANY);
}

static __always_inline int is_err_bio(struct bio *bio)
{
    return (_(bio->bi_status) != 0);
}

static __always_inline void end_bio(void *ctx, struct bio *bio)
{
    int *pid = bpf_map_lookup_elem(&bio_map, &bio);
    if (pid == NULL) {
        return;
    }

    if (is_err_bio(bio)) {
        struct task_data* data = get_task(*pid);
        if (data) {
            __sync_fetch_and_add(&(data->io.bio_err_count), 1);
            report_task(ctx, data, TASK_PROBE_THREAD_IO);
        }
        return;
    }

    (void)bpf_map_delete_elem(&bio_map, &bio);
    return;
}


KPROBE(submit_bio, pt_regs)
{
    struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);

    int pid = (int)bpf_get_current_pid_tgid();

    if (!user_mode(ctx)) {
        return;
    }

    struct task_data *data = get_task(pid);
    if (data == NULL) {
        return;
    }

    if (is_read_bio(bio)) {
        data->io.bio_bytes_read += _(bio->bi_iter.bi_size);
        report_task(ctx, data, TASK_PROBE_THREAD_IO);

        store_bio(bio, pid);
        return;
    }

    if (is_write_bio(bio)) {
        data->io.bio_bytes_write += _(bio->bi_iter.bi_size);
        report_task(ctx, data, TASK_PROBE_THREAD_IO);

        store_bio(bio, pid);
        return;
    }
}

KPROBE(bio_endio, pt_regs)
{
    struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);
    end_bio(ctx, bio);
}

KRAWTRACE(sched_stat_iowait, bpf_raw_tracepoint_args)
{
    struct task_struct* task = (struct task_struct*)ctx->args[0];
    u64 delta = (u64)ctx->args[1];

    struct task_data *data = get_task((int)_(task->pid));
    if (data) {
        __sync_fetch_and_add(&(data->io.iowait_us), delta);
        report_task(ctx, data, TASK_PROBE_THREAD_IO);
    }
}

KRAWTRACE(sched_process_hang, bpf_raw_tracepoint_args)
{
    struct task_struct* task = (struct task_struct*)ctx->args[0];
    struct task_data *data = get_task((int)_(task->pid));
    if (data) {
        __sync_fetch_and_add(&(data->io.hang_count), 1);
        report_task(ctx, data, TASK_PROBE_THREAD_IO);
    }
}
