
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

SET_TP_SYSCALL_PARAMS(sendto)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(sendto)
{
    scm->nr = SYSCALL_SENDTO_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(recvfrom)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(recvfrom)
{
    scm->nr = SYSCALL_RECVFROM_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(sendmsg)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(sendmsg)
{
    scm->nr = SYSCALL_SENDMSG_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(recvmsg)
{
    sce->ext_info.fd_info.fd = ctx->fd;

}

SET_SYSCALL_META(recvmsg)
{
    scm->nr = SYSCALL_RECVMSG_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(sendmmsg)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(sendmmsg)
{
    scm->nr = SYSCALL_SENDMMSG_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(recvmmsg)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(recvmmsg)
{
    scm->nr = SYSCALL_RECVMMSG_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

TP_SYSCALL(sendto)
TP_SYSCALL(recvfrom)
TP_SYSCALL(sendmsg)
TP_SYSCALL(recvmsg)
TP_SYSCALL(sendmmsg)
TP_SYSCALL(recvmmsg)
