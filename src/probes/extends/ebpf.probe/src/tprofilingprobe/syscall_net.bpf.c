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
#include "syscall.bpf.h"
#include "syscall_tp_args.h"

char g_license[] SEC("license") = "GPL";

SET_TP_SYSCALL_PARAMS(sendto)
{
    sce->nr = SYSCALL_SENDTO_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(sendto)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(recvfrom)
{
    sce->nr = SYSCALL_RECVFROM_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(recvfrom)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(sendmsg)
{
    sce->nr = SYSCALL_SENDMSG_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(sendmsg)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(recvmsg)
{
    sce->nr = SYSCALL_RECVMSG_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(recvmsg)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(sendmmsg)
{
    sce->nr = SYSCALL_SENDMMSG_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(sendmmsg)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(recvmmsg)
{
    sce->nr = SYSCALL_RECVMMSG_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(recvmmsg)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

TP_SYSCALL(sendto)
TP_SYSCALL(recvfrom)
TP_SYSCALL(sendmsg)
TP_SYSCALL(recvmsg)
TP_SYSCALL(sendmmsg)
TP_SYSCALL(recvmmsg)
