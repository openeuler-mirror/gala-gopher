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
#define TCP_FD_BPF
#include <bpf/bpf_endian.h>
#include "bpf.h"
#include "tcp_link.h"

char g_linsence[] SEC("license") = "GPL";

static void do_load_tcp_fd(u32 tgid, int fd, struct sock_info_s *info)
{
    struct sock *sk;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (fd == 0) {
        return;
    }

    sk = sock_get_by_fd(fd, task);
    if (sk == (struct sock *)0) {
        return;
    }

    (void)create_sock_obj(tgid, sk, info);
}

static void load_tcp_fd(u32 tgid)
{
    struct tcp_fd_info *tcp_fd_s = bpf_map_lookup_elem(&tcp_fd_map, &tgid);
    struct sock_info_s tcp_sock_data = {0};
    if (!tcp_fd_s) {
        return;
    }
#pragma clang loop unroll(full)
    for (int i = 0; i < TCP_FD_PER_PROC_MAX; i++) {
        if (i == tcp_fd_s->cnt) {
            break;
        }
        tcp_sock_data.role = tcp_fd_s->fd_role[i];
        tcp_sock_data.syn_srtt = 0;
        tcp_sock_data.proc_id = tgid;
        do_load_tcp_fd(tgid, tcp_fd_s->fds[i], &tcp_sock_data);
    }

    (void)bpf_map_delete_elem(&tcp_fd_map, &tgid);
}

KPROBE(tcp_sendmsg, pt_regs)
{
    /* create tcp sock from tcp fd */
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    load_tcp_fd(tgid);
    return 0;
}

KPROBE(tcp_recvmsg, pt_regs)
{
    /* create tcp sock from tcp fd */
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    load_tcp_fd(tgid);
    return 0;
}

