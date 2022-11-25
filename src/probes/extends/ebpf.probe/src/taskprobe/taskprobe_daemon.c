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
 * Author: luzhihao
 * Create: 2022-02-25
 * Description: daemon task load
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "proc.h"
#include "thread.h"

#define TASK_PID_COMMAND \
    "ps -T -p %d | awk 'NR > 1 {print $2}'"

#define TASK_ID_COMMAND \
    "ps -o pid,tid,ppid,pgid,comm -p %u | awk '{print $1 \"|\" $2 \"|\" $3 \"|\" $4 \"|\" $5}'"

enum ps_type {
    PS_TYPE_PID = 0,
    PS_TYPE_TID,
    PS_TYPE_PPID,
    PS_TYPE_PGID,
    PS_TYPE_COMM,

    PS_TYPE_MAX,
};

void load_proc2bpf(u32 proc_id, const char *comm, int fd)
{
    struct proc_data_s proci = {0};

    proci.proc_id = proc_id;
    memcpy(proci.comm, comm, TASK_COMM_LEN);

    (void)bpf_map_update_elem(fd, &proc_id, &proci, BPF_ANY);

    DEBUG("[TASKPROBE]: load daemon proc '[proc=%u,comm=%s]'.\n", proc_id, comm);
}

static void do_load_thread2bpf(int fd, struct thread_id *id)
{
    FILE *f = NULL;
    int pid;
    char cmd[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    struct thread_data thr = {0};

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, TASK_PID_COMMAND, id->tgid);
    f = popen(cmd, "r");
    if (f == NULL) {
        return;
    }
    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            break;
        }
        SPLIT_NEWLINE_SYMBOL(line);
        pid = atoi(line);
        thr.id.pid  = pid;
        thr.id.tgid = id->tgid;
        thr.id.pgid = id->pgid;
        thr.id.ppid = id->ppid;
        (void)strncpy(thr.id.comm, id->comm, TASK_COMM_LEN - 1);
        /* update task map and daemon task map */
        (void)bpf_map_update_elem(fd, &pid, &thr, BPF_ANY);
        DEBUG("[TASKPROBE]: load daemon thread '[pid=%d,tgid=%d,pgid=%d,ppid=%d,comm=%s]'.\n",
              pid, id->tgid, id->pgid, id->ppid, id->comm);
    }

    pclose(f);
    return;
}

static void get_thr_id(char *ps, struct thread_id *id)
{
    int index = 0;
    char *ptoken = NULL;
    char *psave = NULL;
    char *id_str[PS_TYPE_MAX];

    ptoken = strtok_r(ps, "|", &psave);
    while (ptoken != NULL && index < PS_TYPE_MAX) {
        id_str[index++] = ptoken;
        ptoken = strtok_r(NULL, "|", &psave);
    }
    *(id_str[PS_TYPE_COMM] + TASK_COMM_LEN - 1) = '\0';

    id->tgid = atoi(id_str[PS_TYPE_PID]);
    id->pid  = atoi(id_str[PS_TYPE_TID]);
    id->ppid = atoi(id_str[PS_TYPE_PPID]);
    id->pgid = atoi(id_str[PS_TYPE_PGID]);
    (void)strncpy(id->comm, id_str[PS_TYPE_COMM], TASK_COMM_LEN - 1);

    return;
}

void load_thread2bpf(u32 proc_id, int fd)
{
    FILE *f = NULL;
    char cmd[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    struct thread_id id;

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, TASK_ID_COMMAND, proc_id);
    f = popen(cmd, "r");
    if (f == NULL) {
        return;
    }
    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            break;
        }
        SPLIT_NEWLINE_SYMBOL(line);
        get_thr_id((char *)line, &id);
        if (id.tgid > 0) {
            do_load_thread2bpf(fd, &id);
        }
    }

    pclose(f);
    return;
}

