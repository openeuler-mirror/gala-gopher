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

KRAWTRACE(scsi_dispatch_cmd_start, bpf_raw_tracepoint_args)
{
    struct io_trace_s *io_trace = NULL;
    struct scsi_cmnd *sc = (struct scsi_cmnd *)ctx->args[0];
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();
    if (sc == NULL) {
        return;
    }

    struct request* req = _(sc->request);

    io_trace = lkup_io_trace(req);
    if (io_trace == NULL) {
        return;
    }

    // Refreshes the time when the SCSI device issue an I/O operation.
    io_trace->ts[IO_ISSUE_DEVICE] = bpf_ktime_get_ns();
}

KRAWTRACE(scsi_dispatch_cmd_done, bpf_raw_tracepoint_args)
{
    struct io_trace_s *io_trace = NULL;
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();
    struct scsi_cmnd *sc = (struct scsi_cmnd *)ctx->args[0];
    if (sc == NULL) {
        return;
    }

    struct request* req = _(sc->request);

    io_trace = lkup_io_trace(req);
    if (io_trace == NULL) {
        return;
    }

    io_trace->ts[IO_ISSUE_DEVICE_END] = bpf_ktime_get_ns();
}

