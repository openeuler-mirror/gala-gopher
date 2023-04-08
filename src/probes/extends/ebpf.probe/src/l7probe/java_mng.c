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
 * Author: dowzyx
 * Create: 2023-04-07
 * Description: jvm probe prog lifecycle management
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "args.h"
#include "common.h"
#include "object.h"
#include "java_support.h"

#define JSSE_AGENT_FILE     "JSSEProbeAgent.jar"
#define JSSE_TMP_FILE       "jsse-metrics.txt"

enum java_index_t {
    JAVA_INDEX_JSSE,

    JAVA_INDEX_MAX
};
typedef int (*LoadFunc)(struct probe_params *args);

typedef struct {
    enum java_index_t java_index;
    LoadFunc func;
} JavaProc;

int proc_obj_map_fd;

static int __jsse_read_metric_file(struct probe_params *args)
{
    struct stat st = {0};
    if (stat("/tmp", &st) < 0) {
        ERROR("[L7PROBE]: java_mng stat /tmp failed.\n");
        return -1;
    }

    DIR *dir = opendir("/tmp");
    if (dir == NULL) {
        ERROR("[L7PROBE]: java_mng opendir /tmp failed.\n");
        return -1;
    }

    struct dirent *entry;
    while (entry = readdir(dir)) {
        if (strstr(entry->d_name, "java-data-") == NULL) {
            continue;
        }
        int pid = atoi(entry->d_name + strlen("java-data-"));
        char tmp_file_path[PATH_LEN];
        tmp_file_path[0] = 0;
        (void)get_host_java_tmp_file(pid, JSSE_TMP_FILE, tmp_file_path, PATH_LEN);

        int fd = open(tmp_file_path, O_RDWR);
        if (fd < 0) {
            DEBUG("[L7PROBE]: java_mng open tmp file: %s failed.\n", tmp_file_path);
            continue;
        }
        if (lockf(fd, F_LOCK, 0) != 0) {
            DEBUG("[L7PROBE]: java_mng lockf failed.\n");
            continue;
        }
        FILE *fp = fdopen(fd, "r");
        if (fp == NULL) {
            DEBUG("[L7PROBE]: java_mng fopen tmp file: %s failed.\n", tmp_file_path);
            continue;
        }
        char line[LINE_BUF_LEN];
        line[0] = 0;
        while (fgets(line, LINE_BUF_LEN, fp)) {
            (void)fprintf(stdout, "%s", line);
            line[0] = 0;
        }
        (void)fflush(stdout);
        (void)ftruncate(fd, 0);
        (void)fclose(fp);
    }

    return 0;
}

static void* l7_jsse_msg_handler(void *args)
{
    struct probe_params *msg_args = (struct probe_params *)args;

    while (1) {
        if (__jsse_read_metric_file(msg_args) < 0) {
            break;
        }
        sleep(msg_args->period);
    }
    return NULL;
}

static int l7_load_probe_jsse(struct probe_params *args)
{
    int err;
    pthread_t attach_thd, msg_hd_thd;
    struct java_attach_args attach_args = {0};

    attach_args.proc_obj_map_fd = proc_obj_map_fd;
    (void)snprintf(attach_args.agent_file_name, FILENAME_LEN, JSSE_AGENT_FILE);
    (void)snprintf(attach_args.tmp_file_name, FILENAME_LEN, JSSE_TMP_FILE);

    err = pthread_create(&attach_thd, NULL, java_support, (void *)&attach_args);
    if (err != 0) {
        ERROR("[L7PROBE]: Failed to create java_support_pthread.\n");
        return -1;
    }
    (void)pthread_detach(attach_thd);

    err = pthread_create(&msg_hd_thd, NULL, l7_jsse_msg_handler, (void *)args);
    if (err != 0) {
        ERROR("L7PROBE]: Failed to create jsse msg handler thread.\n");
        return -1;
    }
    (void)pthread_detach(msg_hd_thd);

    INFO("[L7PROBE]: init jsse bpf prog succeed.\n");

    return 0;
}

static char is_load_probe(struct probe_params *args)
{
    return 1;
}

int init_java_progs(struct probe_params *args)
{
    proc_obj_map_fd = obj_get_proc_obj_map_fd();

    static JavaProc java_procs[] = {
        { JAVA_INDEX_JSSE,  l7_load_probe_jsse },
    };

    for (int i = 0; i < JAVA_INDEX_MAX; i++) {
        if (!is_load_probe(args) || !java_procs[i].func) {
            continue;
        }
        if (java_procs[i].func(args)) {
            return -1;
        }
    }

    return 0;
}

