/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: dowzyx
 * Create: 2022-11-10
 * Description: probe for virtualized process
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nprobe_fprintf.h"
#include "virt_proc.h"

#define METRICS_VIRT_NAME       "virt_proc"
#define ENTITY_VIRT_NAME        "proc"
#define VIRT_DETECT_HOST_TYPE   "systemd-detect-virt -v"
#define VIRT_GET_ALL_VM         "virsh list --uuid --name"
#define VIRT_GET_PROC_TGID      "ps -ef | grep %s | grep -v grep | awk '{print $2}'"

static int g_host_type_is_pm;

static int do_read_line(char *command, char line[])
{
    FILE *f = NULL;

    if (command == NULL) {
        return -1;
    }

    f = popen(command, "r");
    if (f == NULL) {
        return -1;
    }
    line[0] = 0;
    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        (void)pclose(f);
        return -1;
    }
    SPLIT_NEWLINE_SYMBOL(line);
    (void)pclose(f);
    return 0;
}

static void is_host_type_pm(int *is_host_type_pm)
{
    char line[LINE_BUF_LEN];

    if (do_read_line(VIRT_DETECT_HOST_TYPE, line) < 0) {
        ERROR("[VIRT_PROC] detect host type failed.\n");
        return;
    }

    if (!strcmp(line, "none")) {
        *is_host_type_pm = 1;
    } else {
        *is_host_type_pm = 0;
    }

    return;
}

static int is_virsh_installed(void)
{
    char line[LINE_BUF_LEN];
    int is_installed = 0;

    if (do_read_line("which virsh 2>&1", line) < 0) {
        ERROR("[VIRT_PROC] find virsh failed.\n");
        return -1;
    }
    if (strstr(line, "no virsh in") == NULL) {
        is_installed = 1;
    }

    return is_installed;
}

static void output_proc_infos(struct proc_infos *one_proc)
{
    nprobe_fprintf(stdout, "|%s|%d|%s|%s|%d|\n",
        METRICS_VIRT_NAME,
        one_proc->tgid,
        one_proc->uuid,
        one_proc->vm_name,
        1); // metric is a fixed number

    return;
}

static int get_qemu_proc_tgid(struct proc_infos *one_proc)
{
    char cmd[COMMAND_LEN];
    char line[LINE_BUF_LEN];

    if (one_proc == NULL || one_proc->uuid[0] == 0) {
        return -1;
    }

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, VIRT_GET_PROC_TGID, one_proc->uuid);
    if (do_read_line(cmd, line) < 0) {
        ERROR("[VIRT_PROC] get uuid(%s)'s tgid failed.\n", one_proc->uuid);
        return -1;
    }
    one_proc->tgid = atoi(line);

    output_proc_infos(one_proc);

    return 0;
}

static int get_vhost_proc_tgid(struct proc_infos *one_proc)
{
    FILE *f = NULL;
    char cmd[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    char vhost_comm[TASK_COMM_LEN];
    struct proc_infos tmp = {0};

    if (one_proc == NULL || one_proc->tgid <= 0) {
        return -1;
    }

    (void)snprintf(tmp.uuid, sizeof(tmp.uuid), "%s", one_proc->uuid);

    vhost_comm[0] = 0;
    (void)snprintf(vhost_comm, TASK_COMM_LEN, "vhost-%d", one_proc->tgid);

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, VIRT_GET_PROC_TGID, vhost_comm);
    f = popen(cmd, "r");
    if (f == NULL) {
        return -1;
    }
    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            (void)pclose(f);
            return -1;
        }
        SPLIT_NEWLINE_SYMBOL(line);
        tmp.tgid = atoi(line);
        output_proc_infos(&tmp);
    }

    (void)pclose(f);
    return 0;
}

int virt_proc_probe(void)
{
    FILE *f = NULL;
    char cmd[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    struct proc_infos one_proc;

    if (g_host_type_is_pm == 0) {
        // 非物理机直接退出
        DEBUG("[VIRT_PROC] this host is vm, no probe.\n");
        return 0;
    }
    if (is_virsh_installed() == 0) {
        ERROR("[VIRT_PROC] virsh not installed, please check.\n");
        return 0;
    }
    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, VIRT_GET_ALL_VM);
    f = popen(cmd, "r");
    if (f == NULL) {
        return -1;
    }
    while (!feof(f)) {
        (void)memset(line, 0, LINE_BUF_LEN);
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            (void)pclose(f);
            return -1;
        }
        (void)memset(&one_proc, 0, sizeof(struct proc_infos));
        if (sscanf(line, "%s %s", one_proc.uuid, one_proc.vm_name) < 2) {
            break;
        }
        (void)get_qemu_proc_tgid(&one_proc);
        (void)get_vhost_proc_tgid(&one_proc);
    }

    (void)pclose(f);
    return 0;
}

int virt_proc_init(void)
{
    g_host_type_is_pm = 0;
    is_host_type_pm(&g_host_type_is_pm);
}
