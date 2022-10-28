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
 * Create: 2022-10-22
 * Description: IO common trace bpf prog
 ******************************************************************************/
#ifndef __IO_TRACE_BPF_H__
#define __IO_TRACE_BPF_H__

#pragma once

#ifdef BPF_PROG_KERN

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "io_trace.h"
#include "io_probe_channel.h"

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)
#define REQ_FUA         (1ULL << __REQ_FUA)
#define REQ_RAHEAD      (1ULL << __REQ_RAHEAD)
#define REQ_SYNC        (1ULL << __REQ_SYNC)
#define REQ_META        (1ULL << __REQ_META)
#define REQ_PREFLUSH    (1ULL << __REQ_PREFLUSH)

struct bpf_map_def SEC("maps") io_sample_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u64),  // sample ts, unit: ns
    .max_entries = 1,
};

#define __IO_ENTRIES_MAX (5 * 1024)
struct bpf_map_def SEC("maps") io_trace_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct io_entity_s),
    .value_size = sizeof(struct io_trace_s),
    .max_entries = __IO_ENTRIES_MAX,
};

#define __IO_ERR_MAX (100)
struct bpf_map_def SEC("maps") io_err_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct io_entity_s),
    .value_size = sizeof(struct io_err_s),
    .max_entries = __IO_ERR_MAX,
};

#define __IO_LATENCY_ENTRIES_MAX (100)
struct bpf_map_def SEC("maps") io_latency_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct io_latency_entity_s),
    .value_size = sizeof(struct io_latency_s),
    .max_entries = __IO_LATENCY_ENTRIES_MAX,
};

static __always_inline __maybe_unused char is_sample_tmout(u64 current_ts)
{
    u64 sample_interval = get_sample_interval();
    if (sample_interval == 0) {
        return 1;
    }

    int key = 0;    // const
    u64 *sample_ts = (u64 *)bpf_map_lookup_elem(&io_sample_map, &key);
    if (sample_ts == NULL) {
        return 1;
    }
    if (*sample_ts == 0) {
        bpf_map_update_elem(&io_sample_map, &key, &current_ts, BPF_ANY);
        return 1;
    }

    if (*sample_ts < current_ts) {
        u64 delta = current_ts - *sample_ts;
        if (delta >= sample_interval) {
            bpf_map_update_elem(&io_sample_map, &key, &current_ts, BPF_ANY);
            return 1;
        }
    }
    return 0;
}

static __always_inline __maybe_unused void get_io_entity(struct io_entity_s *io_entity, struct request *req)
{
    io_entity->request = req;
}

#define INIT_LATENCY_STATS(stats, delta) \
    do \
    {\
        (stats).max = delta; \
        (stats).last = delta; \
        (stats).sum = delta; \
        (stats).jitter = 0; \
        (stats).count = 1; \
    } while (0)

#define CALC_LATENCY_STATS(stats, delta) \
    do \
    {\
        __u64 __jitter; \
        (stats).max = \
            (stats).max > delta ? (stats).max : delta; \
        (stats).sum += delta; \
        if ((stats).last > delta) {\
            __jitter = (stats).last - delta; \
        } else { \
            __jitter = delta - (stats).last; \
        } \
        (stats).jitter = (__jitter > (stats).jitter ? __jitter : (stats).jitter); \
        (stats).count++; \
        (stats).last = delta; \
    } while (0)

#define CALC_LATENCY(io_latency, io_trace) \
    do \
    { \
        u64 __io_delta, io_drv_delta, io_dev_delta; \
        u64 __last_io_latency; \
        int __init = 0; \
        \
        __last_io_latency = io_latency->latency[IO_STAGE_BLOCK].max; \
        __io_delta = io_trace->ts[IO_ISSUE_END] - io_trace->ts[IO_ISSUE_START]; \
        io_drv_delta = io_trace->ts[IO_ISSUE_DEVICE] - io_trace->ts[IO_ISSUE_START]; \
        io_dev_delta = io_trace->ts[IO_ISSUE_DEVICE_END] - io_trace->ts[IO_ISSUE_DEVICE]; \
        if (io_latency->latency[IO_STAGE_BLOCK].max == 0) { \
            __init = 1; \
        }\
        if (__init == 1) { \
            INIT_LATENCY_STATS(io_latency->latency[IO_STAGE_BLOCK], __io_delta); \
            INIT_LATENCY_STATS(io_latency->latency[IO_STAGE_DRIVER], io_drv_delta); \
            INIT_LATENCY_STATS(io_latency->latency[IO_STAGE_DEVICE], io_dev_delta); \
        } else { \
            CALC_LATENCY_STATS(io_latency->latency[IO_STAGE_BLOCK], __io_delta); \
            CALC_LATENCY_STATS(io_latency->latency[IO_STAGE_DRIVER], io_drv_delta); \
            CALC_LATENCY_STATS(io_latency->latency[IO_STAGE_DEVICE], io_dev_delta); \
        } \
        if (__io_delta > __last_io_latency) { \
            io_latency->proc_id = io_trace->proc_id; \
            io_latency->data_len = io_trace->data_len; \
            __builtin_memcpy(io_latency->comm, io_trace->comm, TASK_COMM_LEN); \
            __builtin_memcpy(io_latency->rwbs, io_trace->rwbs, RWBS_LEN); \
        } \
    } while (0)

static __always_inline void blk_fill_rwbs(char *rwbs, unsigned int op)
{
    switch (op & REQ_OP_MASK) {
    case REQ_OP_WRITE:
    case REQ_OP_WRITE_SAME:
        rwbs[0] = 'W';
        break;
    case REQ_OP_DISCARD:
        rwbs[0] = 'D';
        break;
    case REQ_OP_SECURE_ERASE:
        rwbs[0] = 'E';
        break;
    case REQ_OP_FLUSH:
        rwbs[0] = 'F';
        break;
    case REQ_OP_READ:
        rwbs[0] = 'R';
        break;
    default:
        rwbs[0] = 'N';
    }

    if (op & REQ_FUA) {
        rwbs[1] = 'F';
    } else {
        rwbs[1] = '#';
    }
    if (op & REQ_RAHEAD) {
        rwbs[2] = 'A';
    } else {
        rwbs[2] = '#';
    }
    if (op & REQ_SYNC) {
        rwbs[3] = 'S';
    } else {
        rwbs[3] = '#';
    }
    if (op & REQ_META) {
        rwbs[4] = 'M';
    } else {
        rwbs[4] = '#';
    }
}

static __always_inline __maybe_unused char is_normal_io_trace(struct io_trace_s *io_trace)
{
    if (io_trace->ts[IO_ISSUE_START] == 0) {
        return 0;
    }

    if (io_trace->ts[IO_ISSUE_DRIVER] == 0) {
        return 0;
    }

    if (io_trace->ts[IO_ISSUE_DEVICE] == 0) {
        return 0;
    }

    if (io_trace->ts[IO_ISSUE_DEVICE_END] == 0) {
        return 0;
    }

    if (io_trace->ts[IO_ISSUE_END] == 0) {
        return 0;
    }

    if (io_trace->ts[IO_ISSUE_END] <= io_trace->ts[IO_ISSUE_START]) {
        return 0;
    }

    if (io_trace->ts[IO_ISSUE_DEVICE] <= io_trace->ts[IO_ISSUE_START]) {
        return 0;
    }

    if (io_trace->ts[IO_ISSUE_DEVICE_END] <= io_trace->ts[IO_ISSUE_DEVICE]) {
        return 0;
    }
    return 1;
}

static __always_inline struct io_trace_s* lkup_io_trace(struct request* req)
{
    struct io_entity_s io_entity = {0};

    if (req == NULL) {
        return NULL;
    }

    get_io_entity(&io_entity, req);
    return (struct io_trace_s *)bpf_map_lookup_elem(&io_trace_map, &io_entity);
}

static __always_inline struct io_trace_s* get_io_trace(struct request* req)
{
    struct io_entity_s io_entity = {0};
    struct io_trace_s new_io_trace = {0};
    struct io_trace_s *io_trace;
    struct gendisk *disk;

    if (req == NULL) {
        return NULL;
    }

    get_io_entity(&io_entity, req);
    io_trace = (struct io_trace_s *)bpf_map_lookup_elem(&io_trace_map, &io_entity);
    if (io_trace != NULL) {
        return io_trace;
    }

    if (!is_sample_tmout(bpf_ktime_get_ns())) {
        return NULL;
    }

    disk = _(req->rq_disk);
    if (disk == NULL) {
        return NULL;
    }

    int major = _(disk->major);
    int first_minor = _(disk->first_minor);
    if (!is_target_dev(major, first_minor)) {
        return NULL;
    }

    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;
    if (proc_id) {
        new_io_trace.proc_id = proc_id;
        (void)bpf_get_current_comm(&new_io_trace.comm, sizeof(new_io_trace.comm));
    }

    unsigned int cmd_flags = _(req->cmd_flags);
    blk_fill_rwbs(new_io_trace.rwbs, cmd_flags);
    new_io_trace.data_len = _(req->__data_len);
    new_io_trace.major = major;
    new_io_trace.first_minor = first_minor;

    bpf_map_update_elem(&io_trace_map, &io_entity, &new_io_trace, BPF_ANY);

    return (struct io_trace_s *)bpf_map_lookup_elem(&io_trace_map, &io_entity);
}

static __always_inline struct io_err_s* get_io_err(struct request* req)
{
    struct io_entity_s io_entity = {0};
    struct io_err_s new_io_err = {0};
    struct io_err_s *io_err;
    struct gendisk *disk;

    if (req == NULL) {
        return NULL;
    }

    get_io_entity(&io_entity, req);
    io_err = (struct io_err_s *)bpf_map_lookup_elem(&io_err_map, &io_entity);
    if (io_err != NULL) {
        return io_err;
    }

    disk = _(req->rq_disk);
    if (disk == NULL) {
        return NULL;
    }

    int major = _(disk->major);
    int first_minor = _(disk->first_minor);
    if (!is_target_dev(major, first_minor)) {
        return NULL;
    }

    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;
    if (proc_id) {
        new_io_err.proc_id = proc_id;
        (void)bpf_get_current_comm(&new_io_err.comm, sizeof(new_io_err.comm));
    }

    unsigned int cmd_flags = _(req->cmd_flags);
    blk_fill_rwbs(new_io_err.rwbs, cmd_flags);
    new_io_err.data_len = _(req->__data_len);
    new_io_err.major = major;
    new_io_err.first_minor = first_minor;

    bpf_map_update_elem(&io_err_map, &io_entity, &new_io_err, BPF_ANY);

    return (struct io_err_s *)bpf_map_lookup_elem(&io_err_map, &io_entity);
}

static __always_inline struct io_latency_s* get_io_latency(struct io_trace_s* io_trace)
{
    struct io_latency_entity_s io_latency_entity = {0};
    struct io_latency_s new_io_latency = {0};
    struct io_latency_s *io_latency;

    io_latency_entity.major = io_trace->major;
    io_latency_entity.first_minor = io_trace->first_minor;

    io_latency = (struct io_latency_s *)bpf_map_lookup_elem(&io_latency_map, &io_latency_entity);
    if (io_latency != NULL) {
        return io_latency;
    }

    new_io_latency.major = io_latency_entity.major;
    new_io_latency.first_minor = io_latency_entity.first_minor;
    bpf_map_update_elem(&io_latency_map, &io_latency_entity, &new_io_latency, BPF_ANY);

    return (struct io_latency_s *)bpf_map_lookup_elem(&io_latency_map, &io_latency_entity);
}

KRAWTRACE(block_rq_issue, bpf_raw_tracepoint_args)
{
    struct io_trace_s *io_trace = NULL;
    struct request* req = (struct request *)ctx->args[1];
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    io_trace = get_io_trace(req);
    if (io_trace == NULL) {
        return;
    }
    // Use 'request->start_time_ns' to replace the 'block_getrq' tracepoint.
    io_trace->ts[IO_ISSUE_START] = _(req->start_time_ns);

    u64 ts = bpf_ktime_get_ns();
    if (io_trace->ts[IO_ISSUE_DRIVER] == 0) {
        io_trace->ts[IO_ISSUE_DRIVER] = ts; // virtblk/SCSI
    }
    io_trace->ts[IO_ISSUE_DEVICE] = ts; // virtblk/NVME
}

KPROBE(blk_mq_complete_request, pt_regs)
{
    struct io_trace_s *io_trace = NULL;
    struct request *req = (struct request *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    io_trace = lkup_io_trace(req);
    if (io_trace == NULL) {
        return;
    }

    // virtblk/NVME
    if (io_trace->ts[IO_ISSUE_DEVICE_END] == 0) {
        io_trace->ts[IO_ISSUE_DEVICE_END] = bpf_ktime_get_ns();
    }
}

KRAWTRACE(block_rq_complete, bpf_raw_tracepoint_args)
{
    struct io_trace_s *io_trace = NULL;
    struct io_err_s *io_err = NULL;
    struct io_entity_s io_entity = {0};
    struct request* req = (struct request *)ctx->args[0];
    int error = (int)ctx->args[1];
    struct io_latency_s* io_latency;
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();

    io_trace = lkup_io_trace(req);
    if (io_trace == NULL) {
        return;
    }
    io_latency = get_io_latency(io_trace);
    if (io_latency == NULL) {
        return;
    }

    if (!error) {
        io_trace->ts[IO_ISSUE_END] = bpf_ktime_get_ns();
        if (is_normal_io_trace(io_trace)) {
            CALC_LATENCY(io_latency, io_trace);
            report_io_latency(ctx, io_latency);
        }
    } else {
        io_latency->err_count++;
        io_err = get_io_err(req);
        if (io_err) {
            io_err->err_code = error;
            report_io_err(ctx, io_err);
        }
    }
    get_io_entity(&io_entity, req);
    bpf_map_delete_elem(&io_trace_map, &io_entity);
    if (io_err) {
        bpf_map_delete_elem(&io_err_map, &io_entity);
    }
}


#endif

#endif
