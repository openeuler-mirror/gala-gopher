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

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "common.h"
#include "object.h"
#include "ipc.h"
#include "l7_common.h"
#include "java_support.h"

#define JSSE_AGENT_FILE     "JSSEProbeAgent.jar"
#define JSSE_TMP_FILE       "jsse-metrics.txt"
#define JSSE_LOAD_TIMES     3

static int g_period = DEFAULT_PERIOD;
static int g_proc_obj_map_fd = -1;

static int l7_load_jsse_agent(struct java_attach_args *args)
{
    int result = 0;
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s obj;
    char comm[TASK_COMM_LEN];

    while (bpf_map_get_next_key(g_proc_obj_map_fd, &key, &next_key) != -1) {
        if (bpf_map_lookup_elem(g_proc_obj_map_fd, &next_key, &obj) != 0) {
            key = next_key;
            continue;
        }
        comm[0] = 0;
        if (detect_proc_is_java(next_key.proc_id, comm, TASK_COMM_LEN) == 0) {
            key = next_key;
            continue;
        }
        // execute java_load only when the proc is a java proc
        int count = 0;
        while (count < JSSE_LOAD_TIMES) {
            if (!java_load(next_key.proc_id, args)) {
                break;
            }
            count++;
        }
        if (count >= JSSE_LOAD_TIMES) {
            ERROR("[L7Probe]: execute java_load to proc: %d failed.\n", next_key.proc_id);
            result = -1;
        }
        key = next_key;
    }

    return result;
}

// TODO：待改进，目前该线程会将jsse相关信息直接输出
static void* l7_jsse_msg_handler(void *arg)
{
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s obj;
    struct java_attach_args args = {0};
    (void)snprintf(args.tmp_file_name, FILENAME_LEN, JSSE_TMP_FILE);

    while (1) {
        sleep(g_period);
        (void)memset(&key, 0, sizeof(key));
        while (bpf_map_get_next_key(g_proc_obj_map_fd, &key, &next_key) != -1) {
            if (bpf_map_lookup_elem(g_proc_obj_map_fd, &next_key, &obj) == 0) {
                java_msg_handler(next_key.proc_id, (void *)&args);
            }
            key = next_key;
        }
    }
    return NULL;
}

int l7_load_probe_jsse(struct l7_mng_s *l7_mng)
{
    int err = 0;
    pthread_t msg_hd_thd;
    struct java_attach_args attach_args = {0};
    (void)strcpy(attach_args.action, "start");
    (void)snprintf(attach_args.agent_file_name, FILENAME_LEN, JSSE_AGENT_FILE);
    (void)snprintf(attach_args.tmp_file_name, FILENAME_LEN, JSSE_TMP_FILE);

    g_period = l7_mng->ipc_body.probe_param.period;
    g_proc_obj_map_fd = l7_mng->bpf_progs.proc_obj_map_fd;

    // 1. load agent, action: start
    if (!l7_load_jsse_agent(&attach_args)) {
        INFO("[L7PROBE]: jsseagent load(action:start) succeed.\n");
    } else {
        INFO("[L7PROBE]: jsseagent load(action:start) end and some proc load failed.\n");
    }

    // 2. create msg_handler thread
    err = pthread_create(&msg_hd_thd, NULL, l7_jsse_msg_handler, NULL);
    if (err != 0) {
        ERROR("L7PROBE]: Failed to create jsse_msg_handler thread.\n");
        return -1;
    }
    l7_mng->java_progs.jss_msg_hd_thd = msg_hd_thd;
    (void)pthread_detach(msg_hd_thd);
    INFO("[L7PROBE]: jsse_msg_handler thread create succeed.\n");

    return 0;
}

void l7_unload_probe_jsse(struct l7_mng_s *l7_mng)
{
    struct java_attach_args attach_args = {0};
    (void)strcpy(attach_args.action, "stop");
    (void)snprintf(attach_args.agent_file_name, FILENAME_LEN, JSSE_AGENT_FILE);
    (void)snprintf(attach_args.tmp_file_name, FILENAME_LEN, JSSE_TMP_FILE);

    g_period = l7_mng->ipc_body.probe_param.period;
    g_proc_obj_map_fd = l7_mng->bpf_progs.proc_obj_map_fd;

    // 1. load agent, action: stop
    if (!l7_load_jsse_agent(&attach_args)) {
        INFO("[L7PROBE]: jsseagent unload(action:stop) succeed.\n");
    } else {
        INFO("[L7PROBE]: jsseagent unload(action:stop) end and some proc unload failed.\n");
    }

    // 2. kill msg_handler thread
    if (l7_mng->java_progs.jss_msg_hd_thd > 0) {
        if (pthread_cancel(l7_mng->java_progs.jss_msg_hd_thd) != 0) {
            ERROR("[L7PROBE] Fail to kill jsse_msg_handler thread.\n");
        } else {
            INFO("[L7PROBE]: jsse_msg_handler thread kill succeed.\n");
        }
    }

    return;
}