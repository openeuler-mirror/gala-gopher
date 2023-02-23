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
 * Create: 2022-11-03
 * Description: Collecting I/O Data
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

#define __IO_ERR_MAX (100)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct io_entity_s));
    __uint(value_size, sizeof(struct io_err_s));
    __uint(max_entries, __IO_ERR_MAX);
} io_err_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, __PERF_OUT_MAX);
} io_err_channel_map SEC(".maps");

struct block_rq_complete_args {
    struct trace_entry ent;
    dev_t dev;
    sector_t sector;
    unsigned int nr_sector;
    int error;
    char rwbs[RWBS_LEN];
    char cmd[0];
};

static __always_inline void report_io_err(void *ctx, struct io_err_s* io_err)
{
    (void)bpf_perf_event_output(ctx, &io_err_channel_map, BPF_F_ALL_CPU, io_err, sizeof(struct io_err_s));
}

static __always_inline int get_io_devt(struct request* req, int *major, int *minor)
{
    struct gendisk *disk;

    if (req == NULL) {
        return -1;
    }

    disk = _(req->rq_disk);
    if (disk == NULL) {
        return -1;
    }

    *major = _(disk->major);
    *minor = _(disk->first_minor);
    return 0;
}

static __always_inline struct io_err_s* get_io_err(int major, int minor)
{
    struct io_entity_s io_entity = {.major = major, .first_minor = minor};
    struct io_err_s new_io_err = {0};
    struct io_err_s *io_err;

    io_err = (struct io_err_s *)bpf_map_lookup_elem(&io_err_map, &io_entity);
    if (io_err != NULL) {
        return io_err;
    }

    if (!is_target_dev(major, minor)) {
        return NULL;
    }

    new_io_err.major = major;
    new_io_err.first_minor = minor;

    bpf_map_update_elem(&io_err_map, &io_entity, &new_io_err, BPF_ANY);

    return (struct io_err_s *)bpf_map_lookup_elem(&io_err_map, &io_entity);
}

static __always_inline void update_io_err(struct block_rq_complete_args* ctx, struct io_err_s* io_err)
{

    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;
    if (proc_id) {
        io_err->proc_id = proc_id;
        (void)bpf_get_current_comm(&io_err->comm, sizeof(io_err->comm));
    }

    __builtin_memcpy(io_err->rwbs, ctx->rwbs, RWBS_LEN);
    io_err->data_len = ctx->nr_sector * 512;
    io_err->err_code = ctx->error;
    return;
}

bpf_section("tracepoint/block/block_rq_complete")
int tracepoint_block_rq_complete(struct block_rq_complete_args *ctx)
{
    int major, minor;
    struct io_err_s *io_err = NULL;
    struct io_entity_s io_entity = {0};

    major = MAJOR(ctx->dev);
    minor = MINOR(ctx->dev);

    io_entity.major = major;
    io_entity.first_minor = minor;

    if (ctx->error) {
        io_err = get_io_err(major, minor);
        if (io_err) {
            update_io_err(ctx, io_err);
            report_io_err(ctx, io_err);
            bpf_map_delete_elem(&io_err_map, &io_entity);
        }
    }
    return 0;
}

KRAWTRACE(scsi_dispatch_cmd_timeout, bpf_raw_tracepoint_args)
{
    int major, minor;
    struct io_err_s *io_err = NULL;
    struct scsi_cmnd *sc = (struct scsi_cmnd *)ctx->args[0];
    if (sc == NULL) {
        return 0;
    }

    struct request* req = _(sc->request);

    if (get_io_devt(req, &major, &minor)) {
        return 0;
    }

    io_err = get_io_err(major, minor);
    if (io_err == NULL) {
        return 0;
    }

    io_err->scsi_tmout = 1;
    return 0;
}

KRAWTRACE(scsi_dispatch_cmd_error, bpf_raw_tracepoint_args)
{
    int major, minor;
    struct io_err_s *io_err = NULL;
    struct scsi_cmnd *sc = (struct scsi_cmnd *)ctx->args[0];
    int scsi_err = (int)ctx->args[1];
    if (sc == NULL) {
        return 0;
    }

    struct request* req = _(sc->request);

    if (get_io_devt(req, &major, &minor)) {
        return 0;
    }

    io_err = get_io_err(major, minor);
    if (io_err == NULL) {
        return 0;
    }

    io_err->scsi_err = scsi_err;
    return 0;
}

