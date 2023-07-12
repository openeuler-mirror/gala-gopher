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
#include "ipc.h"
#include "tcpprobe.h"

#define UNLOAD_TCP_FD_PROBE (120)   // 2 min

static volatile sig_atomic_t g_stop;
static struct ipc_body_s g_ipc_body;

#define RM_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__tcplink_*"

void load_established_tcps(struct ipc_body_s *ipc_body, int map_fd);
int tcp_load_probe(struct ipc_body_s *ipc_body, struct bpf_prog_s **tcp_progs);

static void sig_int(int signo)
{
    g_stop = 1;
}

static void load_tcp_snoopers(int fd, struct ipc_body_s *ipc_body)
{
    struct proc_s proc = {0};
    struct obj_ref_s ref = {.count = 1};

    if (fd <= 0) {
        return;
    }

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type == SNOOPER_OBJ_PROC) {
            proc.proc_id = ipc_body->snooper_objs[i].obj.proc.proc_id;
            (void)bpf_map_update_elem(fd, &proc, &ref, BPF_ANY);
        }
    }
}

static void unload_tcp_snoopers(int fd, struct ipc_body_s *ipc_body)
{
    struct proc_s proc = {0};

    if (fd <= 0) {
        return;
    }

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type == SNOOPER_OBJ_PROC) {
            proc.proc_id = ipc_body->snooper_objs[i].obj.proc.proc_id;
            (void)bpf_map_delete_elem(fd, &proc);
        }
    }
}

int main(int argc, char **argv)
{
    int err = -1, ret;
    int tcp_fd_map_fd = -1, proc_obj_map_fd = -1;
    int start_time_second;
    struct bpf_prog_s *tcp_progs = NULL;
    FILE *fp = NULL;
    struct ipc_body_s ipc_body;

    fp = popen(RM_MAP_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }
    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %d\n", errno);
        return errno;
    }
    (void)memset(&g_ipc_body, 0, sizeof(g_ipc_body));

    int msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        fprintf(stderr, "Create ipc msg que failed.\n");
        goto err;
    }

    INIT_BPF_APP(tcpprobe, EBPF_RLIM_LIMITED);
    lkup_established_tcp();
    ret = tcp_load_fd_probe(&tcp_fd_map_fd, &proc_obj_map_fd);
    if (ret) {
        fprintf(stderr, "Load tcp fd ebpf prog failed.\n");
        goto err;
    }

    printf("Successfully started!\n");

    start_time_second = 0;
    while (!g_stop) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_TCP, &ipc_body);
        if (ret == 0) {
            /* zero probe_flag means probe is restarted, so reload bpf prog */
            if (ipc_body.probe_flags & IPC_FLAGS_PARAMS_CHG || ipc_body.probe_flags == 0) {
                unload_bpf_prog(&tcp_progs);
                if (tcp_load_probe(&ipc_body, &tcp_progs)) {
                    destroy_ipc_body(&ipc_body);
                    break;
                }
            }

            if (ipc_body.probe_flags & IPC_FLAGS_SNOOPER_CHG || ipc_body.probe_flags == 0) {
                unload_tcp_snoopers(proc_obj_map_fd, &g_ipc_body);
                load_tcp_snoopers(proc_obj_map_fd, &ipc_body);
            }
            destroy_ipc_body(&g_ipc_body);
            (void)memcpy(&g_ipc_body, &ipc_body, sizeof(g_ipc_body));
        }

        if (tcp_progs) {
            load_established_tcps(&g_ipc_body, tcp_fd_map_fd);

            start_time_second++;
            if (start_time_second > UNLOAD_TCP_FD_PROBE) {
                tcp_unload_fd_probe();
                start_time_second = 0;
            }
            for (int i = 0; i < tcp_progs->num && i < SKEL_MAX_NUM; i++) {
                if (tcp_progs->pbs[i] && ((err = perf_buffer__poll(tcp_progs->pbs[i], THOUSAND)) < 0)) {
                    if (err != -EINTR) {
                        ERROR("[TCPPROBE]: perf poll prog_%d failed.\n", i);
                    }
                    break;
                }
            }
        } else {
            sleep(1);
        }
    }

err:
    unload_bpf_prog(&tcp_progs);

    tcp_unload_fd_probe();
    destroy_established_tcps();
    return -err;
}
