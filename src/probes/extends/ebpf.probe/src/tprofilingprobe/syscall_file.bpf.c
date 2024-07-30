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

SET_TP_SYSCALL_PARAMS(read)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(read)
{
    scm->nr = SYSCALL_READ_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(write)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(write)
{
    scm->nr = SYSCALL_WRITE_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(readv)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(readv)
{
    scm->nr = SYSCALL_READV_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(writev)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(writev)
{
    scm->nr = SYSCALL_WRITEV_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(preadv)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(preadv)
{
    scm->nr = SYSCALL_PREADV_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(pwritev)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(pwritev)
{
    scm->nr = SYSCALL_PWRITEV_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(sync) { return; }

SET_SYSCALL_META(sync)
{
    scm->nr = SYSCALL_SYNC_ID;
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(fsync)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(fsync)
{
    scm->nr = SYSCALL_FSYNC_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(fdatasync)
{
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(fdatasync)
{
    scm->nr = SYSCALL_FDATASYNC_ID;
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

TP_SYSCALL(read)
TP_SYSCALL(readv)
TP_SYSCALL(write)
TP_SYSCALL(writev)
TP_SYSCALL(preadv)
TP_SYSCALL(pwritev)
TP_SYSCALL(sync)
TP_SYSCALL(fsync)
TP_SYSCALL(fdatasync)
