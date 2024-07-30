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

KRAWTRACE(nvme_setup_cmd, bpf_raw_tracepoint_args)
{
    struct io_trace_s *io_trace = NULL;
    struct request *req = (struct request *)ctx->args[0];
    if (req == NULL) {
        return 0;
    }

    io_trace = get_io_trace(req);
    if (io_trace == NULL) {
        return 0;
    }

    io_trace->ts[IO_ISSUE_DRIVER] = bpf_ktime_get_ns();
    return 0;
}

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

