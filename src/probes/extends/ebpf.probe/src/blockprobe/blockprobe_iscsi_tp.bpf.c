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

KPROBE(iscsi_conn_error_event, pt_regs)
{
    unsigned int err = (unsigned int)PT_REGS_PARM2(ctx);
    struct block_key* bkey = get_scsi_block();
    if(!bkey) {
        return;
    }
    struct block_data *bdata = get_block_entry(bkey);
    if(!bdata) {
        return;
    }

    if ((err > ISCSI_ERR_BASE) && ((err - ISCSI_ERR_BASE) < ISCSI_ERR_MAX)) {
        bdata->conn_stats.conn_err[err - ISCSI_ERR_BASE]++;
        report_blk(ctx, bdata);
    }
}

