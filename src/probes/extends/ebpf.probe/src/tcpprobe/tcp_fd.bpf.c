/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2022-07-28
 * Description: tcp fd probe
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include <bpf/bpf_endian.h>
#include "bpf.h"
#include "tcp_link.h"

char g_linsence[] SEC("license") = "GPL";

#define __TCP_FD_MAX (50)

// Used to identifies the TCP pid and fd.
// Temporary MAP. Data exists only in the startup phase.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32)); // tgid
    __uint(value_size, sizeof(struct tcp_fd_info));
    __uint(max_entries, __TCP_FD_MAX);
} tcp_fd_map SEC(".maps");

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
}

KPROBE(tcp_recvmsg, pt_regs)
{
    /* create tcp sock from tcp fd */
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    load_tcp_fd(tgid);
}

