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
#include <time.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "ipc.h"
#include "tc_loader.h"
#include "tcpprobe.h"
#include "tcp_tracker.h"

#define UNLOAD_TCP_FD_PROBE (120)   // 2 min

static volatile sig_atomic_t g_stop;
static struct tcp_mng_s g_tcp_mng;

#define RM_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__tcplink_*"

void load_established_tcps(struct ipc_body_s *ipc_body, int map_fd);
int tcp_load_probe(struct tcp_mng_s *tcp_mng, struct ipc_body_s *ipc_body, struct bpf_prog_s **new_prog);
void scan_tcp_trackers(struct tcp_mng_s *tcp_mng);
void scan_tcp_flow_trackers(struct tcp_mng_s *tcp_mng);

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

static void reload_tc_bpf(struct ipc_body_s* ipc_body)
{
#ifdef KERNEL_SUPPORT_TSTAMP
    char is_loaded = 0;
    char need_load = 0;
    char is_dev_changed = 0;

    if (g_tcp_mng.ipc_body.probe_flags & PROBE_RANGE_TCP_DELAY) {
        is_loaded = 1;
    }
    if (ipc_body->probe_flags & PROBE_RANGE_TCP_DELAY) {
        need_load = 1;
    }
    if (strcmp(g_tcp_mng.ipc_body.probe_param.target_dev, ipc_body->probe_param.target_dev) != 0) {
        is_dev_changed = 1;
    }

    if (is_loaded && is_dev_changed) {
        offload_tc_bpf(TC_TYPE_INGRESS);
    }
    if (need_load && (!is_loaded || is_dev_changed)) {
        load_tc_bpf(ipc_body->probe_param.target_dev, TC_PROG, TC_TYPE_INGRESS);
    }
#endif
    return;
}

static char is_need_scan(struct tcp_mng_s *tcp_mng)
{
#define __SCAN_TIME_SECS     (1 * 60)       // 1min
    time_t current = (time_t)time(NULL);
    time_t secs;

    if (current > tcp_mng->last_scan) {
        secs = current - tcp_mng->last_scan;
        if (secs >= __SCAN_TIME_SECS) {
            tcp_mng->last_scan = current;
            return 1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    int err = -1, ret;
    int tcp_fd_map_fd = -1, proc_obj_map_fd = -1;
    int start_time_second;
    struct tcp_mng_s *tcp_mng = &g_tcp_mng;
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
    (void)memset(tcp_mng, 0, sizeof(struct tcp_mng_s));

    int msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        fprintf(stderr, "Create ipc msg que failed.\n");
        goto err;
    }

    INIT_BPF_APP(tcpprobe, EBPF_RLIM_LIMITED);

#ifndef KERNEL_SUPPORT_TSTAMP
    INFO("[TCPPROBE]: The kernel version does not support loading the tc tstamp program\n");
#endif
    INFO("[TCPPROBE]: Starting to load established tcp...\n");

    lkup_established_tcp();
    ret = tcp_load_fd_probe(&tcp_fd_map_fd, &proc_obj_map_fd);
    if (ret) {
        fprintf(stderr, "Load tcp fd ebpf prog failed.\n");
        goto err;
    }

    INFO("[TCPPROBE]: Successfully started!\n");

    start_time_second = 0;
    tcp_mng->last_scan = (time_t)time(NULL);
    while (!g_stop) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_TCP, &ipc_body);
        if (ret == 0) {
            /* zero probe_flag means probe is restarted, so reload bpf prog */
            if (ipc_body.probe_flags & IPC_FLAGS_PARAMS_CHG || ipc_body.probe_flags == 0) {
                INFO("[TCPPROBE]: Starting to unload ebpf prog.\n");
                reload_tc_bpf(&ipc_body);
                unload_bpf_prog(&(tcp_mng->tcp_progs));
                if (tcp_load_probe(tcp_mng, &ipc_body, &(tcp_mng->tcp_progs))) {
                    destroy_ipc_body(&ipc_body);
                    break;
                }
            }

            if (ipc_body.probe_flags & IPC_FLAGS_SNOOPER_CHG || ipc_body.probe_flags == 0) {
                unload_tcp_snoopers(proc_obj_map_fd, &(tcp_mng->ipc_body));
                load_tcp_snoopers(proc_obj_map_fd, &ipc_body);
            }
            destroy_ipc_body(&(tcp_mng->ipc_body));
            (void)memcpy(&(tcp_mng->ipc_body), &ipc_body, sizeof(tcp_mng->ipc_body));
        }

        if (tcp_mng->tcp_progs) {
            load_established_tcps(&(tcp_mng->ipc_body), tcp_fd_map_fd);

            start_time_second++;
            if (start_time_second > UNLOAD_TCP_FD_PROBE) {
                tcp_unload_fd_probe();
                start_time_second = 0;
            }
            for (int i = 0; i < tcp_mng->tcp_progs->num && i < SKEL_MAX_NUM; i++) {
                if (tcp_mng->tcp_progs->pbs[i] && ((err = perf_buffer__poll(tcp_mng->tcp_progs->pbs[i], THOUSAND)) < 0)) {
                    if (err != -EINTR) {
                        ERROR("[TCPPROBE]: perf poll prog_%d failed.\n", i);
                    }
                    break;
                }
            }
        } else {
            sleep(1);
        }

        // Scans all TCP trackers every minute to delete invalid trackers and output data.
        if (is_need_scan(tcp_mng)) {
            scan_tcp_trackers(tcp_mng);
            scan_tcp_flow_trackers(tcp_mng);
        }
    }

err:
    unload_bpf_prog(&(tcp_mng->tcp_progs));
#ifdef KERNEL_SUPPORT_TSTAMP
    offload_tc_bpf(TC_TYPE_INGRESS);
#endif
    destroy_ipc_body(&(tcp_mng->ipc_body));
    destroy_tcp_trackers(tcp_mng);
    destroy_tcp_flow_trackers(tcp_mng);
    tcp_unload_fd_probe();
    destroy_established_tcps();
    return -err;
}
