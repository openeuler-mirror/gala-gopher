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
 * Description: io trace(nvme)
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "io_trace_bpf.h"

char g_linsence[] SEC("license") = "GPL";

#if (CURRENT_KERNEL_VERSION > KERNEL_VERSION(4, 18, 0))
KRAWTRACE(nvme_setup_cmd, bpf_raw_tracepoint_args)
{
    struct io_trace_s *io_trace = NULL;
    struct scsi_cmnd *sc = (struct scsi_cmnd *)ctx->args[0];
    if (sc == NULL) {
        return 0;
    }

    struct request* req = _(sc->request);

    io_trace = get_io_trace(req);
    if (io_trace == NULL) {
        return 0;
    }

    io_trace->ts[IO_ISSUE_DRIVER] = bpf_ktime_get_ns();
    return 0;
}
#else
KPROBE(nvme_setup_cmd, pt_regs)
{
    struct io_trace_s *io_trace = NULL;
    struct request *req = (struct request *)PT_REGS_PARM2(ctx);

    io_trace = get_io_trace(req);
    if (io_trace == NULL) {
        return 0;
    }

    io_trace->ts[IO_ISSUE_DRIVER] = bpf_ktime_get_ns();
    return 0;
}
#endif

