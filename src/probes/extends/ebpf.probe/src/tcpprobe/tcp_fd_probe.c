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
 * Create: 2022-07-26
 * Description: tcp establish fd
 ******************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "tcp.h"
#include "ipc.h"
#include "tcpprobe.h"
#include "tcp_fd.skel.h"

static struct bpf_prog_s* fd_probe = NULL;

int tcp_load_fd_probe(void)
{
    struct bpf_prog_s *prog;

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return -1;
    }

    __LOAD_PROBE(tcp_fd, err, 1);
    prog->skels[prog->num].skel = tcp_fd_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)tcp_fd_bpf__destroy;
    prog->num++;

    fd_probe = prog;
    return 0;
err:
    UNLOAD(tcp_fd);
    return -1;
}

void tcp_unload_fd_probe(void)
{
    if (fd_probe) {
        INFO("[TCPPROBE] unload fd probe succeed.\n");
        unload_bpf_prog(&fd_probe);
        fd_probe = NULL;
    }
}

int is_tcp_fd_probe_loaded(void)
{
    if (fd_probe) {
        return 1;
    }
    return 0;
}