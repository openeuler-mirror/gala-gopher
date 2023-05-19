
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
 * Author: algorithmofdish
 * Create: 2023-04-03
 * Description: the bpf-side prog of thread profiling probe
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "syscall.bpf.h"
#include "syscall_tp_args.h"

char g_license[] SEC("license") = "GPL";

SET_TP_SYSCALL_PARAMS(futex)
{
    sce->ext_info.futex_info.op = ctx->op;
}

SET_SYSCALL_META(futex)
{
    scm->nr = SYSCALL_FUTEX_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

TP_SYSCALL(futex)