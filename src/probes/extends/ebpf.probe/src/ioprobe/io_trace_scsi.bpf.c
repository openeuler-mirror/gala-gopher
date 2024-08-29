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
#include "io_trace_bpf.h"

char g_linsence[] SEC("license") = "GPL";

static __always_inline struct request *scsi_cmd_to_request(struct scsi_cmnd *sc)
{
    struct request *req;

    if (bpf_core_field_exists(((struct scsi_cmnd *)0)->request)) {
        req = _(sc->request);
    } else {
#if CLANG_VER_MAJOR >= 12
        // same with scsi_cmd_to_rq() in kernel
        req = (struct request *)(sc - bpf_core_type_size(struct request));
#else
        req = NULL;
#endif
    }

    return req;
}

/*
 * Raw tracepoint defined in modules is not supported in this version, so use kprobe as hook instead.
 *    scsi_dispatch_cmd_start --> scsi_dispatch_cmd()
 *    scsi_dispatch_cmd_done --> scsi_done()/scsi_mq_done()
 */
KPROBE(scsi_dispatch_cmd, pt_regs)
{
    struct io_trace_s *io_trace = NULL;
    struct scsi_cmnd *sc = (struct scsi_cmnd *)PT_REGS_PARM1(ctx);
    struct scsi_device *sd;
    struct Scsi_Host *host;
    enum scsi_device_state sd_state;
    if (sc == NULL) {
        return 0 ;
    }

    sd = _(sc->device);
    if (sd == NULL) {
        return 0;
    }

    host = _(sd->host);
    if (host == NULL) {
        return 0;
    }

    sd_state = _(sd->sdev_state);
    if (sd_state == SDEV_DEL || sd_state == SDEV_BLOCK || sd_state == SDEV_CREATED_BLOCK ||
        _(sc->cmd_len) > _(host->max_cmd_len) || _(host->shost_state) == SHOST_DEL) {
        return 0;
    }

    struct request* req = _(sc->request);
    io_trace = lkup_io_trace(req);
    if (io_trace == NULL) {
        return 0;
    }

    // Refreshes the time when the SCSI device issue an I/O operation.
    io_trace->ts[IO_ISSUE_DEVICE] = bpf_ktime_get_ns();
    return 0;
}

KPROBE(scsi_done, pt_regs)
{
    struct io_trace_s *io_trace = NULL;
    struct scsi_cmnd *sc = (struct scsi_cmnd *)PT_REGS_PARM1(ctx);
    if (sc == NULL) {
        return 0;
    }

    struct request* req = _(sc->request);

    io_trace = lkup_io_trace(req);
    if (io_trace == NULL) {
        return 0;
    }

    io_trace->ts[IO_ISSUE_DEVICE_END] = bpf_ktime_get_ns();
    return 0;
}

KPROBE(scsi_mq_done, pt_regs)
{
    struct io_trace_s *io_trace = NULL;
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();
    struct scsi_cmnd *sc = (struct scsi_cmnd *)PT_REGS_PARM1(ctx);
    if (sc == NULL) {
        return 0;
    }

    struct request* req = _(sc->request);

    io_trace = lkup_io_trace(req);
    if (io_trace == NULL) {
        return 0;
    }

    io_trace->ts[IO_ISSUE_DEVICE_END] = bpf_ktime_get_ns();
    return 0;
}

KRAWTRACE(scsi_dispatch_cmd_start, bpf_raw_tracepoint_args)
{
    struct io_trace_s *io_trace = NULL;
    struct scsi_cmnd *sc = (struct scsi_cmnd *)ctx->args[0];
    if (sc == NULL) {
        return 0;
    }

    struct request* req = scsi_cmd_to_request(sc);

    io_trace = lkup_io_trace(req);
    if (io_trace == NULL) {
        return 0;
    }

    // Refreshes the time when the SCSI device issue an I/O operation.
    io_trace->ts[IO_ISSUE_DEVICE] = bpf_ktime_get_ns();
    return 0;
}

KRAWTRACE(scsi_dispatch_cmd_done, bpf_raw_tracepoint_args)
{
    struct io_trace_s *io_trace = NULL;
    struct scsi_cmnd *sc = (struct scsi_cmnd *)ctx->args[0];
    if (sc == NULL) {
        return 0;
    }

    struct request* req = scsi_cmd_to_request(sc);

    io_trace = lkup_io_trace(req);
    if (io_trace == NULL) {
        return 0;
    }

    io_trace->ts[IO_ISSUE_DEVICE_END] = bpf_ktime_get_ns();
    return 0;
}
