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
 * Create: 2022-02-22
 * Description: block probe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "output.h"
#include "block.h"

char g_linsence[] SEC("license") = "GPL";

KPROBE(mq_flush_data_end_io, pt_regs)
{
    struct block_key key;
    struct block_data *bdata;
    struct request *req = (struct request *)PT_REGS_PARM1(ctx);

    get_block_key_by_req(req, &key);
    bdata = get_block_entry(&key);
    if (!bdata) {
        return;
    }
    __u64 ts = bpf_ktime_get_ns();
    report_latency(ctx, bdata, &(bdata->blk_stats.flush), get_delta_time_ns(req, ts), ts);
}

KPROBE(blk_account_io_done, pt_regs)
{
    struct block_key key;
    struct block_data *bdata;
    struct request *req = (struct request *)PT_REGS_PARM1(ctx);

    get_block_key_by_req(req, &key);
    bdata = get_block_entry(&key);
    if (!bdata) {
        return;
    }

    __u64 ts = bpf_ktime_get_ns();
    report_latency(ctx, bdata, &(bdata->blk_stats.req), get_delta_time_ns(req, ts), ts);
}

KRAWTRACE(block_rq_issue, bpf_raw_tracepoint_args)
{
    struct block_key key;
    struct block_data *bdata;
    struct request *req = (struct request *)ctx->args[1];

    get_block_key_by_req(req, &key);
    bdata = get_block_entry(&key);
    if (!bdata) {
        return;
    }

    __u64 ts = bpf_ktime_get_ns();
    report_latency(ctx, bdata, &(bdata->blk_drv_stats), get_delta_time_ns(req, ts), ts);
}

KPROBE(blk_mq_complete_request, pt_regs)
{
    struct block_key key;
    struct block_data *bdata;
    struct request *req = (struct request *)PT_REGS_PARM1(ctx);

    get_block_key_by_req(req, &key);
    bdata = get_block_entry(&key);
    if (!bdata) {
        return;
    }

    __u64 ts = bpf_ktime_get_ns();
    report_latency(ctx, bdata, &(bdata->blk_dev_stats), get_delta_time_ns(req, ts), ts);
}

