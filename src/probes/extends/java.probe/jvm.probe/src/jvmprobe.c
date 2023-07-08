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
 * Create: 2023-04-12
 * Description: jvm probe main prog
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <uthash.h>
#include "args.h"
#include "ipc.h"
#include "common.h"
#include "java_support.h"
#include "jvmprobe.h"

static volatile sig_atomic_t g_stop = 0;
static struct ipc_body_s g_ipc_body;
static struct proc_hash_t *g_procmap = NULL;

static void sig_int(int signal)
{
    g_stop = 1;
}

static struct proc_hash_t *hash_find_key(u32 pid, u64 stime)
{
    struct proc_hash_t *p = NULL;
    struct proc_key_t key = {0};

    key.pid = pid;
    key.start_time = stime;
    HASH_FIND(hh, g_procmap, &key, sizeof(struct proc_key_t), p);

    return p;
}

static void load_jvm_probe(struct java_attach_args *args)
{
    int ret;
    char stime[TIME_STRING_LEN];
    struct proc_hash_t *r, *tmp;

    HASH_ITER(hh, g_procmap, r, tmp) {
        ret = get_proc_start_time(r->key.pid, stime, TIME_STRING_LEN);
        if (ret != 0) {
            WARN("[JVMPROBE] Gets proc %u start time failed\n", r->key.pid);
            continue;
        }

        if (r->key.start_time != (u64)atoll(stime)) {
            INFO("[JVMPROBE] Proc %u start time changed\n", r->key.pid);
            continue;
        }

        ret = java_load(r->key.pid, (void *)args);
        if (ret != 0) {
            WARN("[JVMPROBE]: Attach to proc %d failed\n", r->key.pid);
        }
    }
}

static void clear_proc_hash_t(void)
{
    if (g_procmap == NULL) {
        return;
    }

    struct proc_hash_t *r, *tmp;
    HASH_ITER(hh, g_procmap, r, tmp) {
        HASH_DEL(g_procmap, r);
        if (r != NULL) {
            (void)free(r);
        }
    }
}

static int add_to_hash_t(int pid, u64 stime)
{
    struct proc_hash_t *item, *p;

    p = hash_find_key(pid, stime);
    if (p == NULL) {
        item = (struct proc_hash_t *)malloc(sizeof(struct proc_hash_t));
        if (item == NULL) {
            ERROR("[JVMPROBE]: proc_hash_t malloc failed!\n");
            return -1;
        }
        (void)memset(item, 0, sizeof(struct proc_hash_t));
        item->key.pid = pid;
        item->key.start_time = stime;
        HASH_ADD(hh, g_procmap, key, sizeof(struct proc_key_t), item);
    }

    return 0;
}

static int refresh_proc_hash_t(struct ipc_body_s *ipc_body)
{
    int ret;
    int pid;
    char stime[TIME_STRING_LEN];
    char comm[TASK_COMM_LEN];

    clear_proc_hash_t();

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_PROC) {
            continue;
        }

        comm[0] = 0;
        pid = (u32)ipc_body->snooper_objs[i].obj.proc.proc_id;

        ret = detect_proc_is_java(pid, comm, TASK_COMM_LEN);
        if (ret == 0) {
            INFO("[JVMPROBE]: The proc %u is not a java, skipped!\n", pid);
            continue;
        }

        ret = get_proc_start_time(pid, stime, TIME_STRING_LEN);
        if (ret != 0) {
            WARN("[JVMPROBE] Gets proc %u start time failed!\n", pid);
            continue;
        }

        ret = add_to_hash_t(pid, (u64)atoll(stime));
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

static void output_java_msg(struct java_attach_args * args)
{
    struct proc_hash_t *r, *tmp;
    HASH_ITER(hh, g_procmap, r, tmp) {
        java_msg_handler(r->key.pid, (void *)args, NULL, NULL);
    }
}

int main(int argc, char **argv)
{
    int ret = 0;
    struct ipc_body_s ipc_body;
    struct java_attach_args attach_args = {0};

    (void)memset(&g_ipc_body, 0, sizeof(g_ipc_body));
    int msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        goto err;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        ERROR("[JVMPROBE]: can't set signal handler: %d\n", errno);
        goto err;
    }

    (void)snprintf(attach_args.agent_file_name, FILENAME_LEN, "%s", JVMPROBE_AGENT_FILE);
    (void)snprintf(attach_args.tmp_file_name, FILENAME_LEN, "%s", JVMPROBE_TMP_FILE);

    while (!g_stop) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_JVM, &ipc_body);
        if (ret == 0) {
            ret = refresh_proc_hash_t(&ipc_body);
            if (ret != 0) {
                ERROR("[JVMPROBE]: refresh proc_hash_t failed!\n");
                goto err;
            }
            destroy_ipc_body(&g_ipc_body);
            (void)memcpy(&g_ipc_body, &ipc_body, sizeof(g_ipc_body));
        }
        (void)load_jvm_probe(&attach_args);
        output_java_msg(&attach_args);
        if (g_ipc_body.probe_param.period == 0) {
            sleep(DEFAULT_PERIOD);
        } else {
            sleep(g_ipc_body.probe_param.period);
        }
    }

err:
    destroy_ipc_body(&g_ipc_body);
    return ret;
}
