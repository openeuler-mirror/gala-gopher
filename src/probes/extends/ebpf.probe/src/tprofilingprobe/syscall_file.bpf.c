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
    sce->nr = SYSCALL_READ_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(read)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(write)
{
    sce->nr = SYSCALL_WRITE_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(write)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(readv)
{
    sce->nr = SYSCALL_READV_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(readv)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(writev)
{
    sce->nr = SYSCALL_WRITEV_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(writev)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(preadv)
{
    sce->nr = SYSCALL_PREADV_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(preadv)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(pwritev)
{
    sce->nr = SYSCALL_PWRITEV_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(pwritev)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(sync) { sce->nr = SYSCALL_SYNC_ID; }

SET_SYSCALL_META(sync)
{
    scm->flag = SYSCALL_FLAG_STACK;
}

SET_TP_SYSCALL_PARAMS(fsync)
{
    sce->nr = SYSCALL_FSYNC_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(fsync)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(fdatasync)
{
    sce->nr = SYSCALL_FDATASYNC_ID;
    sce->ext_info.fd_info.fd = ctx->fd;
}

SET_SYSCALL_META(fdatasync)
{
    scm->flag = SYSCALL_FLAG_FD_STACK;
}

SET_TP_SYSCALL_PARAMS(ioctl)
{
    sce->nr = SYSCALL_IOCTL_ID;
    sce->ext_info.ioctl_info.cmd = ctx->cmd;
}

SET_SYSCALL_META(ioctl)
{
    scm->flag = SYSCALL_FLAG_STACK;
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
TP_SYSCALL(ioctl)
