/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wo_cow
 * Create: 2022-02-20
 * Description: podprobe user prog
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "event.h"
#include "container.h"
#include "podprobe.skel.h"
#include "podprobe.h"

#define POD_TBL_NAME "pod_state"
#define KUBEPODS_PREFIX "/kubepods/"
#define PODID_PREFIX "/pod"
#define POD_ID_LEN 64
#define POD_NAME_LEN 64
#define POD_NAME_CMD "docker ps | grep %s | awk 'NR==1{print $1}' | xargs docker inspect "\
                     "--format '{{.Config.Hostname}}' 2>/dev/null"

static volatile sig_atomic_t stop;
static struct probe_params params = {.period = DEFAULT_PERIOD};

static void sig_int(int signo)
{
    stop = 1;
}

static int get_pod_name(char *pod_id, char *pod_name, int len)
{
    char command[COMMAND_LEN] = {0};

    (void)snprintf(command, COMMAND_LEN, POD_NAME_CMD, pod_id);

    if (!exec_cmd((const char *)command, pod_name, len)) {
        return -1;
    }

    return 0;
}

static int get_pod_container_id(char *cgrp_path, char *pod_id, char *container_id)
{
    int full_path_len;
    char *p;
    int i,j;
    if (!cgrp_path) {
        return -1;
    }

    if (strstr(cgrp_path, KUBEPODS_PREFIX) == NULL) {
        return -1;
    }

    p = strstr(cgrp_path, PODID_PREFIX);
    if (p == NULL) {
        return -1;
    }

    // only pod cgroup, not container cgroup
    if (strstr(p+1, "/") == NULL) {
        return -1;
    }

    // get pod id
    p += 4;
    full_path_len = strlen(cgrp_path);
    i = 0;
    while (i < POD_ID_LEN && i + p - cgrp_path < full_path_len) {
        if (p[i] == '/') {
            pod_id[i++] = 0;
            break;
        }
        pod_id[i] = p[i];
        i++;
    }
    pod_id[POD_ID_LEN - 1] = 0;
    if (i + p - cgrp_path == full_path_len) {
        return 0;
    }
    
    // get container id
    p += i;
    j = 0;
    while (j < CONTAINER_ABBR_ID_LEN && j + p - cgrp_path < full_path_len) {
        if (p[j] == '/') {
            container_id[j++] = 0;
            break;
        }
        container_id[j] = p[j];
        j++;
    }
    container_id[CONTAINER_ABBR_ID_LEN - 1] = 0;
    return 0;
}

static void msg_handler(void *ctx, int cpu, void *data, unsigned int size)
{
    struct msg_data_t *msg_data = (struct msg_data_t *)data;
    char pod_name[POD_NAME_LEN] = {0};
    char pod_id[POD_ID_LEN] = {0};
    char constainer_id[CONTAINER_ABBR_ID_LEN] = {0};
    char constainer_name[CONTAINER_ABBR_ID_LEN] = {0};

    if (get_pod_container_id(msg_data->cgrp_path, pod_id, constainer_id) != 0) {
        return;
    }

    if (get_pod_name(pod_id, pod_name, POD_NAME_LEN)!= 0) {
        pod_name[0] = 0;
    }

    if (constainer_id[0] != 0) {
        (void)get_container_name(constainer_id, constainer_name, CONTAINER_NAME_LEN);
    }

    fprintf(stdout,
            "|%s|%s|%s|%s|%s|%s|%d|\n",
            POD_TBL_NAME,
            pod_id,
            pod_name,
            constainer_id,
            constainer_name,
            msg_data->cgrp_event == CGRP_MK ? "create_container" : "destroy_container",
            0);

    (void)fflush(stdout);
    return;
}

int main(int argc, char **argv)
{
    int err;

    err = args_parse(argc, argv, &params);
    if (err != 0) {
        return -1;
    }
    printf("arg parse interval time:%us\n", params.period);

    INIT_BPF_APP(podprobe, EBPF_RLIM_LIMITED);
    LOAD(podprobe, out);

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "Can't set signal handler: %d\n", errno);
        goto out;
    }

    struct perf_buffer *pb = create_pref_buffer(GET_MAP_FD(podprobe, msg_map), msg_handler);
    if (pb == NULL) {
        fprintf(stderr, "Failed to create perf buffer.\n");
        goto out;
    }
    
    printf("pod probe successfully started!\n");

    while (!stop) {
        err = perf_buffer__poll(pb, params.period * 1000);
        if (err < 0) {
            break;
        }
    }

    perf_buffer__free(pb);
out:
    UNLOAD(podprobe);
    return -err;
}
