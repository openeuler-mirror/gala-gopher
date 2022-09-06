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
#include "thread.h"

#define TASK_PID_COMMAND \
    "ps -T -p \"%d\" | awk 'NR > 1 {print $2}'"

#define TASK_ID_COMMAND \
    "ps -eo pid,tid,ppid,pgid,comm | grep %s | awk '{print $1 \"|\" $2 \"|\" $3 \"|\" $4 \"|\" $5}'"

enum ps_type {
    PS_TYPE_PID = 0,
    PS_TYPE_TID,
    PS_TYPE_PPID,
    PS_TYPE_PGID,
    PS_TYPE_COMM,

    PS_TYPE_MAX,
};

/*
[root@localhost ~]# ps -T -p 1396 | awk 'NR > 1 {print $2}'
1396
1397
1398
1399
*/
static void do_load_daemon_task(int fd, struct task_id *id)
{
    FILE *f = NULL;
    int pid;
    char cmd[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    struct task_data data = {0};

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
        data.id.pid  = pid;
        data.id.tgid = id->tgid;
        data.id.pgid = id->pgid;
        data.id.ppid = id->ppid;
        (void)strncpy(data.id.comm, id->comm, TASK_COMM_LEN - 1);
        /* update task map and daemon task map */
        (void)bpf_map_update_elem(fd, &pid, &data, BPF_ANY);
        DEBUG("[TASKPROBE]: load daemon task '[pid=%d,tgid=%d,pgid=%d,ppid=%d,comm=%s]'.\n",
              pid, id->tgid, id->pgid, id->ppid, id->comm);
    }

    pclose(f);
    return;
}

static int do_get_task_tgid(char *ps, struct task_id *id)
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

    return 0;
}


/* ps_rlt exemple:
    ps -eo pid,ppid,pgid,comm | grep -w nginx | awk '{print $1 "|" $2 "|" $3 "|" $4}'
    3144599|3144598|3144598
    3144600|3144598|3144598
 */
static void do_get_daemon_task_tgid(int fd, const char* name, int is_whole_word)
{
    FILE *f = NULL;
    char cmd[COMMAND_LEN];
    char filter_content[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    struct task_id id;

    filter_content[0] = 0;
    if (is_whole_word == 1) {
        (void)snprintf(filter_content, COMMAND_LEN, "-w %s", name);
    } else {
        (void)snprintf(filter_content, COMMAND_LEN, "%s", name);
    }
    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, TASK_ID_COMMAND, filter_content);
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
        
        if (do_get_task_tgid((char *)line, &id) == 0)
            do_load_daemon_task(fd, &id);
    }

    pclose(f);
    return;
}

void load_daemon_task_by_name(int fd, const char *name, int is_whole_word)
{
    do_get_daemon_task_tgid(fd, name, is_whole_word);
}
