/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
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
 * Description: io trace(SCSI)
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "io_trace_bpf.h"

char g_linsence[] SEC("license") = "GPL";

#if (CURRENT_KERNEL_VERSION < KERNEL_VERSION(4, 13, 0))
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
#else
KRAWTRACE(scsi_dispatch_cmd_start, bpf_raw_tracepoint_args)
{
    struct io_trace_s *io_trace = NULL;
    struct scsi_cmnd *sc = (struct scsi_cmnd *)ctx->args[0];
    if (sc == NULL) {
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

KRAWTRACE(scsi_dispatch_cmd_done, bpf_raw_tracepoint_args)
{
    struct io_trace_s *io_trace = NULL;
    struct scsi_cmnd *sc = (struct scsi_cmnd *)ctx->args[0];
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
#endif
