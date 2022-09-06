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
 * Author: Ernest
 * Create: 2022-06-21
 * Description: system probe just in 1 thread, include tcp/net/iostat/inode
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "nprobe_fprintf.h"
#include "system_cpu.h"

#define METRICS_CPU_NAME        "system_cpu"
#define SYSTEM_PROCESSOR_INFO   "cat /proc/softirqs | grep -E '\\sRCU:\\s|\\sTIMER:\\s|\\sSCHED:\\s|\\sNET_RX:\\s'"
#define SYSTEM_PROC_STAT_PATH   "/proc/stat"
#define PROC_STAT_FILEDS_NUM    6
#define BUF_SIZE                512
#define MAX_CPU_NUM             1024
#define LINE_SIZE               2048

static struct cpu_stat **cur_cpus = NULL;
static struct cpu_stat **old_cpus = NULL;
static int cpus_num = 0;
static bool is_first_get = true;

static int get_proc_stat_fileds(void)
{
    FILE *f = NULL;
    char line[LINE_SIZE];
    int ret;
    int index = 0;
    bool is_first_line = true;

    f = fopen(SYSTEM_PROC_STAT_PATH, "r");
    if (f == NULL) {
        return -1;
    }
    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_SIZE, f) == NULL) {
            fclose(f);
            return 0;
        }
        if (strstr(line, "cpu") == NULL || is_first_line) {
            is_first_line = false;
            continue;
        }
        if (index >= cpus_num) {
            printf("[SYSTEM_PROBE] cpu_probe records beyond max cpu nums(%d).\n", cpus_num);
            (void)fclose(f);
            return -1;
        }
        ret = sscanf(line,
            "%*s %llu %llu %llu %*llu %llu %llu %llu %*llu %*llu %*llu",
            &cur_cpus[index]->cpu_user_total_second,
            &cur_cpus[index]->cpu_nice_total_second,
            &cur_cpus[index]->cpu_system_total_second,
            &cur_cpus[index]->cpu_iowait_total_second,
            &cur_cpus[index]->cpu_irq_total_second,
            &cur_cpus[index]->cpu_softirq_total_second);
        if (ret < PROC_STAT_FILEDS_NUM) {
            printf("system_cpu.probe faild get proc_stat metrics.\n");
        }
        index++;
    }
    (void)fclose(f);
    return 0;
}

static int get_cpu_info(void)
{
    FILE *f = NULL;
    char *field, *save;
    char line[LINE_SIZE] = {0};

    f = popen(SYSTEM_PROCESSOR_INFO, "r");
    if (f == NULL) {
        return -1;
    }
    while (fgets(line, LINE_SIZE, f) != NULL) {
        field = __strtok_r(line, " ", &save);
        if (strcmp(field, "RCU:") == 0) {
            for (size_t i = 0; i < cpus_num; i++) {
                cur_cpus[i]->rcu = atoll(__strtok_r(NULL, " ", &save));
            }
        } else if (strcmp(field, "TIMER:") == 0) {
            for (size_t i = 0; i < cpus_num; i++) {
                cur_cpus[i]->timer = atoll(__strtok_r(NULL, " ", &save));
            }
        } else if (strcmp(field, "SCHED:") == 0) {
            for (size_t i = 0; i < cpus_num; i++) {
                cur_cpus[i]->sched = atoll(__strtok_r(NULL, " ", &save));
            }
        } else if (strcmp(field, "NET_RX:") == 0) {
            for (size_t i = 0; i < cpus_num; i++) {
                cur_cpus[i]->net_rx = atoll(__strtok_r(NULL, " ", &save));
            }
        }
        line[0] = 0;
    }
    pclose(f);
    if (get_proc_stat_fileds()) {
        printf("[SYSTEM_PROBE] fail to collect cpus info\n");
        return -1;
    }
    return 0;
}

static struct cpu_stat **alloc_memory(void)
{
    struct cpu_stat **cpus = NULL;
    
    cpus = (struct cpu_stat **)malloc(cpus_num * sizeof(struct cpu_stat *));
    if (cpus == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < cpus_num; i++) {
        cpus[i] = (struct cpu_stat *)malloc(sizeof(struct cpu_stat));
        if (cpus[i] == NULL) {
            for (size_t j = 0; j < i; j++) {
                free(cpus[j]);
            }
            free(cpus);
            cpus = NULL;
            return NULL;
        }
        cpus[i]->cpu_num = i;
    }
    return cpus;
}

static void dealloc_memory(struct cpu_stat **cpus)
{
    for (size_t i = 0; i < cpus_num; i++) {
        free(cpus[i]);
    }
    free(cpus);
}

int system_cpu_init(void)
{
    cpus_num = (int)sysconf(_SC_NPROCESSORS_CONF);
    if (cpus_num < 0 || cpus_num > MAX_CPU_NUM) {
        printf("[SYSTEM_PROBE] sysconf to read the number of cpus error\n");
        return -1;
    }
    cur_cpus = alloc_memory();
    old_cpus = alloc_memory();
    if (cur_cpus == NULL || old_cpus == NULL) {
        printf("[SYSTEM_PROBE] fail alloc memory for cpu probe structure\n");
        if (cur_cpus != NULL) {
            dealloc_memory(cur_cpus);
            cur_cpus = NULL;
        }
        if (old_cpus != NULL) {
            dealloc_memory(old_cpus);
            old_cpus = NULL;
        }
        return -1;
    }
    return 0;
}

void system_cpu_destroy(void)
{
    dealloc_memory(cur_cpus);
    dealloc_memory(old_cpus);
    cur_cpus = NULL;
    old_cpus = NULL;
}

int system_cpu_probe(void)
{
    struct cpu_stat **tmp_pptr;
    struct cpu_stat *tmp_ptr;
    int ret;
    if (get_cpu_info()) {
        printf("[SYSTEM_PROBE] fail to collect cpus info\n");
        return -1;
    }
    if (is_first_get == true) {
        tmp_pptr = old_cpus;
        old_cpus = cur_cpus;
        cur_cpus = tmp_pptr;
        is_first_get = false;
        return 0;
    }
    for (size_t i = 0; i < cpus_num; i++) {
        ret = nprobe_fprintf(stdout, "|%s|%d|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|\n",
            METRICS_CPU_NAME,
            cur_cpus[i]->cpu_num,
            cur_cpus[i]->rcu - old_cpus[i]->rcu,
            cur_cpus[i]->timer - old_cpus[i]->timer,
            cur_cpus[i]->sched - old_cpus[i]->sched,
            cur_cpus[i]->net_rx - old_cpus[i]->net_rx,
            cur_cpus[i]->cpu_user_total_second - old_cpus[i]->cpu_user_total_second,
            cur_cpus[i]->cpu_nice_total_second - old_cpus[i]->cpu_nice_total_second,
            cur_cpus[i]->cpu_system_total_second - old_cpus[i]->cpu_system_total_second,
            cur_cpus[i]->cpu_iowait_total_second - old_cpus[i]->cpu_iowait_total_second,
            cur_cpus[i]->cpu_irq_total_second - old_cpus[i]->cpu_irq_total_second,
            cur_cpus[i]->cpu_softirq_total_second - old_cpus[i]->cpu_softirq_total_second);
        tmp_ptr = old_cpus[i];
        old_cpus[i] = cur_cpus[i];
        cur_cpus[i] = tmp_ptr;
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}
