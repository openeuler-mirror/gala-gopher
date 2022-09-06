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
 * Author: sky
 * Create: 2021-05-22
 * Description: tcp_probe user prog
 ******************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sched.h>
#include <fcntl.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "object.h"
#include "tcpprobe.h"

#define UNLOAD_TCP_FD_PROBE (120)   // 2 min

static struct probe_params params = {.period = DEFAULT_PERIOD,
                                     .cport_flag = 0};
static volatile sig_atomic_t g_stop;

#define RM_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/probe/__tcplink_*"

static void sig_int(int signo)
{
    g_stop = 1;
}

int main(int argc, char **argv)
{
    int err = -1;
    int fd;
    int start_time_second;
    struct bpf_prog_s *tcp_progs = NULL;
    FILE *fp = NULL;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %d\n", errno);
        return errno;
    }

    err = args_parse(argc, argv, &params);
    if (err != 0) {
        return -1;
    }

    fp = popen(RM_MAP_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }

    obj_module_init();
    lkup_established_tcp();

    INIT_BPF_APP(tcpprobe, EBPF_RLIM_LIMITED);

    tcp_progs = tcp_load_probe(&params);
    if (!tcp_progs) {
        goto err;
    }

    fd = tcp_load_fd_probe();

    printf("Successfully started!\n");

    start_time_second = 0;
    while (!g_stop) {
        start_time_second++;
        if (start_time_second > UNLOAD_TCP_FD_PROBE) {
            tcp_unload_fd_probe();
        }

        load_established_tcps(&params, fd);

        //if (tcp_progs->pb && ((err = perf_buffer__poll(tcp_progs->pb, THOUSAND)) < 0)) {
        //    ERROR("[TCPPROBE]: perf poll failed.\n");
        //    break;
        //}
        for (int i = 0; i < tcp_progs->num; i++) {
            if (tcp_progs->pbs[i] && (err = perf_buffer__poll(tcp_progs->pbs[i], THOUSAND) < 0)) {
                ERROR("[TCPPROBE]: perf poll prog_%d failed.\n", i);
                break;
            }
        }
    }

err:
    unload_bpf_prog(&tcp_progs);

    tcp_unload_fd_probe();
    destroy_established_tcps();
    obj_module_exit();
    return -err;
}
