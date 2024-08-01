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
#include "task.h"
#include "fs_op.h"
#include "output_proc.h"

char g_linsence[] SEC("license") = "GPL";

KPROBE_FS_OP(ext4_file_read_iter, ext4, read, TASK_PROBE_EXT4_OP)
KPROBE_FS_OP(ext4_file_write_iter, ext4, write, TASK_PROBE_EXT4_OP)
KPROBE_FS_OP(ext4_file_open, ext4, open, TASK_PROBE_EXT4_OP)
KPROBE_FS_OP(ext4_sync_file, ext4, flush, TASK_PROBE_EXT4_OP)
