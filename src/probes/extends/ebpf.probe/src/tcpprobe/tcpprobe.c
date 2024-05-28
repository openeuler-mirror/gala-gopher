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
#include "tcp_tracker.h"
#include "feat_probe.h"
#include "tcpprobe.h"

#define UNLOAD_TCP_FD_PROBE (120)   // 2 min

static volatile sig_atomic_t g_stop;
static struct tcp_mng_s g_tcp_mng;

#define RM_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__tcplink_*"
#define RM_COMMON_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__tcpprobe_*"

int load_established_tcps(int proc_obj_map_fd, int map_fd);
int tcp_load_probe(struct tcp_mng_s *tcp_mng, struct ipc_body_s *ipc_body, struct bpf_prog_s **new_prog);
void scan_tcp_trackers(struct tcp_mng_s *tcp_mng);
void scan_tcp_flow_trackers(struct tcp_mng_s *tcp_mng);
void aging_tcp_trackers(struct tcp_mng_s *tcp_mng);
void aging_tcp_flow_trackers(struct tcp_mng_s *tcp_mng);

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
    char is_loaded = 0;
    char need_load = 0;
    char is_dev_changed = 0;

    if (!probe_tstamp()) {
        return;
    }

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
}

static char is_need_aging(struct tcp_mng_s *tcp_mng)
{
#define __AGING_TIME_SECS     (5 * 60)       // 5min
    time_t current = (time_t)time(NULL);
    time_t secs;

    if (current > tcp_mng->last_aging) {
        secs = current - tcp_mng->last_aging;
        if (secs >= __AGING_TIME_SECS) {
            tcp_mng->last_aging = current;
            return 1;
        }
    }

    return 0;
}

static int init_tcp_historm(struct tcp_mng_s *tcp_mng)
{
    char *historm = NULL;

    for (int i = 0; i < TCP_HISTORM_MAX; i++) {
        historm = (char *)malloc(MAX_HISTO_SERIALIZE_SIZE);
        if (historm == NULL) {
            return -1;
        }
        historm[0] = 0;
        tcp_mng->historms[i] = historm;
    }
    return 0;
}

static void deinit_tcp_historm(struct tcp_mng_s *tcp_mng)
{
    for (int i = 0; i < TCP_HISTORM_MAX; i++) {
        if (tcp_mng->historms[i] != NULL) {
            free(tcp_mng->historms[i]);
            tcp_mng->historms[i] = NULL;
        }
    }
}

static void empty_tcp_fd_map(int map_fd)
{
    u32 key = 0, next_key = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        (void)bpf_map_delete_elem(map_fd, &next_key);
        key = next_key;
    }
}

static int load_established_tcps_mngt(int proc_obj_map_fd, int tcp_fd_map_fd)
{
    static time_t last_load_time;
    time_t now;
    int estab_loaded;

    time(&now);
    estab_loaded = load_established_tcps(proc_obj_map_fd, tcp_fd_map_fd);
    if (estab_loaded > 0) {
        if (!is_tcp_fd_probe_loaded()) {
            if (tcp_load_fd_probe()) {
                ERROR("[TCPPROBE] Load tcp fd ebpf prog failed.\n");
                return -1;
            }
        }
        last_load_time = now;
    } else {
        if (now > last_load_time + UNLOAD_TCP_FD_PROBE) {
            tcp_unload_fd_probe();
            empty_tcp_fd_map(tcp_fd_map_fd);
        }
    }

    return 0;
}

static void clean_tcp_pin_map()
{
    FILE *fp = NULL;
    fp = popen(RM_MAP_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }
    fp = popen(RM_COMMON_MAP_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }
}

int main(int argc, char **argv)
{
    int err = -1, ret;
    int tcp_fd_map_fd = -1, proc_obj_map_fd = -1;
    struct tcp_mng_s *tcp_mng = &g_tcp_mng;

    struct ipc_body_s ipc_body;
    bool supports_tstamp;

    supports_tstamp = probe_tstamp();

    clean_tcp_pin_map();

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        ERROR("[TCPPROBE] Can't set signal handler: %d\n", errno);
        return errno;
    }
    (void)memset(tcp_mng, 0, sizeof(struct tcp_mng_s));

    int msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        ERROR("[TCPPROBE] Get ipc msg queue failed.\n");
        goto err;
    }

    if (init_tcp_historm(tcp_mng)) {
        ERROR("[TCPPROBE] Init tcp historm failed.\n");
        goto err;
    }

    INIT_BPF_APP(tcpprobe, EBPF_RLIM_LIMITED);

    if (!supports_tstamp) {
        INFO("[TCPPROBE]: The kernel version does not support loading the tc tstamp program\n");
    }
    INFO("[TCPPROBE]: Starting to load established tcp...\n");

    ret = tcp_load_fd_probe();
    if (ret) {
        ERROR("[TCPPROBE] Load tcp fd ebpf prog failed.\n");
        goto err;
    }

    tcp_fd_map_fd = bpf_obj_get(TCP_LINK_FD_PATH);
    proc_obj_map_fd = bpf_obj_get(GET_PROC_MAP_PIN_PATH(tcpprobe));
    if (tcp_fd_map_fd <= 0 || proc_obj_map_fd <= 0) {
        ERROR("[TCPPROBE]: Failed to get bpf map fd\n");
        goto err;
    }

    INFO("[TCPPROBE]: Successfully started!\n");

    tcp_mng->last_aging = (time_t)time(NULL);
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
                lkup_established_tcp(proc_obj_map_fd, &ipc_body);
                unload_tcp_snoopers(proc_obj_map_fd, &(tcp_mng->ipc_body));
                load_tcp_snoopers(proc_obj_map_fd, &ipc_body);
            }
            destroy_ipc_body(&(tcp_mng->ipc_body));
            (void)memcpy(&(tcp_mng->ipc_body), &ipc_body, sizeof(tcp_mng->ipc_body));
        }

        if (tcp_mng->tcp_progs) {
            ret = load_established_tcps_mngt(proc_obj_map_fd, tcp_fd_map_fd);
            if (ret) {
                goto err;
            }

            for (int i = 0; i < tcp_mng->tcp_progs->num && i < SKEL_MAX_NUM; i++) {
                if (tcp_mng->tcp_progs->buffers[i] &&
                    ((err = bpf_buffer__poll(tcp_mng->tcp_progs->buffers[i], THOUSAND)) < 0) &&
                    err != -EINTR) {
                    ERROR("[TCPPROBE]: perf poll prog_%d failed.\n", i);
                    break;
                }
            }
        } else {
            sleep(1);
        }

        scan_tcp_trackers(tcp_mng);
        scan_tcp_flow_trackers(tcp_mng);

        // Aging all invalid TCP trackers trackers.
        if (is_need_aging(tcp_mng)) {
            aging_tcp_trackers(tcp_mng);
            aging_tcp_flow_trackers(tcp_mng);
        }
    }

err:
    unload_bpf_prog(&(tcp_mng->tcp_progs));
    if (supports_tstamp) {
        offload_tc_bpf(TC_TYPE_INGRESS);
    }
    destroy_ipc_body(&(tcp_mng->ipc_body));
    destroy_tcp_trackers(tcp_mng);
    destroy_tcp_flow_trackers(tcp_mng);
    deinit_tcp_historm(tcp_mng);
    tcp_unload_fd_probe();
    destroy_established_tcps();

    clean_tcp_pin_map();
    return -err;
}
