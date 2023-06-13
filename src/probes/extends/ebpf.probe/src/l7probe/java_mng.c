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
#include <pthread.h>
#include <sys/types.h>
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
    LoadFunc load_func;
    LoadFunc unload_func;
} JavaProc;

static struct probe_params params = {.period = DEFAULT_PERIOD};

static void* l7_jsse_msg_handler(void *args)
{
    struct java_attach_args *attach_args = (struct java_attach_args *)args;

    while (1) {
        java_msg_handler(1, attach_args);  // TODO: 先打桩，待适配最新java_support
        sleep(attach_args->loop_period);
    }
    return NULL;
}

static int l7_load_probe_jsse(struct probe_params *args)
{
    int err;
    pthread_t attach_thd, msg_hd_thd;
    struct java_attach_args attach_args = {0};

    attach_args.proc_obj_map_fd = obj_get_proc_obj_map_fd();
    attach_args.loop_period = DEFAULT_PERIOD;
    attach_args.is_only_attach_once = 1;
    (void)snprintf(attach_args.agent_file_name, FILENAME_LEN, JSSE_AGENT_FILE);
    (void)snprintf(attach_args.tmp_file_name, FILENAME_LEN, JSSE_TMP_FILE);

    err = pthread_create(&attach_thd, NULL, java_support, (void *)&attach_args);
    if (err != 0) {
        ERROR("[L7PROBE]: Failed to create java_support_pthread.\n");
        return -1;
    }
    (void)pthread_detach(attach_thd);

    err = pthread_create(&msg_hd_thd, NULL, l7_jsse_msg_handler, (void *)&attach_args);
    if (err != 0) {
        ERROR("L7PROBE]: Failed to create jsse msg handler thread.\n");
        return -1;
    }
    (void)pthread_detach(msg_hd_thd);

    INFO("[L7PROBE]: init jsse prog succeed.\n");

    return 0;
}

static int l7_unload_probe_jsse(struct probe_params *args)
{
    struct java_attach_args attach_args = {0};

    attach_args.proc_obj_map_fd = obj_get_proc_obj_map_fd();
    (void)snprintf(attach_args.agent_file_name, FILENAME_LEN, JSSE_AGENT_FILE);
    (void)snprintf(attach_args.tmp_file_name, FILENAME_LEN, JSSE_TMP_FILE);

    java_unload(&attach_args);
    INFO("[L7PROBE]: unload jsse agent succeed.\n");

    return 0;
}

static char is_load_probe(struct probe_params *args)
{
    return 1;
}

static JavaProc java_procs[] = {
    { JAVA_INDEX_JSSE,  l7_load_probe_jsse,  l7_unload_probe_jsse },

};

int init_java_progs(struct probe_params *args)
{
    if (args != NULL) {
        params.period = args->period;
    }

    for (int i = 0; i < JAVA_INDEX_MAX; i++) {
        if (!is_load_probe(args) || !java_procs[i].load_func) {
            continue;
        }
        if (java_procs[i].load_func(args)) {
            return -1;
        }
    }

    return 0;
}

void unload_java_progs(struct probe_params *args)
{
    for (int i = 0; i < JAVA_INDEX_MAX; i++) {
        if (!java_procs[i].unload_func) {
            continue;
        }
        java_procs[i].unload_func(args);
    }
    return;
}

