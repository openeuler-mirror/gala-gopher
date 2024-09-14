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
 * Author: Ernest, ChenHua Li, Haiyue Fung
 * Create: 2022-06-21
 * Description: system cpu probe
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "common.h"
#include "nprobe_fprintf.h"
#include "event.h"
#include "system_cpu.h"

#define METRICS_CPU_NAME            "system_cpu"
#define METRICS_CPU_UTIL_NAME       "system_cpu_util"
#define ENTITY_NAME                 "cpu"
#define SYSTEM_PROCESSOR_INFO       "cat /proc/softirqs | grep -E '\\sRCU:\\s|\\sTIMER:\\s|\\sSCHED:\\s|\\sNET_RX:\\s'"
#define SYSTEM_PROC_STAT_PATH       "/proc/stat"
#define SYSTEM_CPU_MHZ_INFO         "cat /proc/cpuinfo | grep MHz"
#define SOFTNET_STAT_PATH           "/proc/net/softnet_stat"
#define PROC_STAT_FILEDS_NUM        6
#define PROC_STAT_COL_NUM           8
#define PROC_STAT_IDLE_COL          4
#define PROC_STAT_IOWAIT_COL        5
#define SOFTNET_DROP_COL            2
#define SOFTNET_RPS_COL             10
#define BASE_HEX                    16
#define MAX_CPU_NUM                 1024
#define FULL_PER                    100
#define MAX_COL_NUM                 20

static struct cpu_stat **cur_cpus = NULL;
static struct cpu_stat **old_cpus = NULL;
static int cpus_num = 0;
static bool is_first_get = true;
static u64 last_time_total, cur_time_total, last_time_used, cur_time_used;
static float util_per;
static int softirq_line_num = 0;
char *softirq_line = NULL;

/*
 * time_total = user + nice + sys + irq + softirq + steal + idle + iowait (前8列)
 * time_idle = idle + iowait
 * time_used = user + nice + sys + irq + softirq + steal
 */
static void get_cpu_time_in_jiff(char *cpu_total_line, u64 *time_total, u64 *time_used)
{
    char *retrieved_time = NULL, *save;
    int i = 0;
    *time_total = 0;
    *time_used = 0;
    u64 time;

    (void)__strtok_r(cpu_total_line, " ", &save);

    while (i++ < PROC_STAT_COL_NUM) {
        retrieved_time = __strtok_r(NULL, " ", &save);
        time = strtoll(retrieved_time, NULL, 10);

        *time_total += time;

        if (i != PROC_STAT_IDLE_COL && i != PROC_STAT_IOWAIT_COL) {
            *time_used += time;
        }
    }
}

static void report_cpu_status(struct ipc_body_s *ipc_body)
{
#ifdef ENABLE_REPORT_EVENT
    char entityId[INT_LEN];
    struct event_info_s evt = {0};
    if (ipc_body->probe_param.logs == 0) {
        return;
    }

    entityId[0] = 0;
    (void)snprintf(entityId, sizeof(entityId), "%s", "cpu");

    evt.entityName = ENTITY_NAME;
    evt.entityId = entityId;
    evt.metrics = "total_used_per";

    if (ipc_body->probe_param.res_percent_upper > 0 && util_per > ipc_body->probe_param.res_percent_upper) {
        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Too high cpu utilization(%.2f%%).",
                    util_per);
    }
#endif
    return;
}

static float get_cpu_util(char *src, u64 *last_total, u64 *last_used, u64 *cur_total, u64 *cur_used)
{
    float util;

    get_cpu_time_in_jiff(src, cur_total, cur_used);

    util = (*cur_used - *last_used) * FULL_PER * 1.0 / (*cur_total - *last_total);

    return util;
}

static int get_proc_stat_info(void)
{
    FILE *f = NULL;
    char line[LINE_BUF_LEN];
    char dst_line[LINE_BUF_LEN];
    int ret;
    int index = 0;
    bool is_first_line = true;

    f = fopen(SYSTEM_PROC_STAT_PATH, "r");
    if (f == NULL) {
        return -1;
    }
    while (!feof(f)) {
        dst_line[0] = 0;
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            fclose(f);
            return 0;
        }
        strncpy(dst_line, line, LINE_BUF_LEN - 1);
        if (is_first_line) {
            util_per = get_cpu_util(dst_line, &last_time_total, &last_time_used,
                                    &cur_time_total, &cur_time_used);
            last_time_total = cur_time_total;
            last_time_used = cur_time_used;
            is_first_line = false;
            continue;
        }
        if (strstr(line, "cpu") == NULL) {
            continue;
        }
        cur_cpus[index]->cpu_util_per = get_cpu_util(dst_line, &old_cpus[index]->cpu_time_total,
                                                     &old_cpus[index]->cpu_time_used,
                                                     &cur_cpus[index]->cpu_time_total,
                                                     &cur_cpus[index]->cpu_time_used);
        ret = sscanf(line,
            "%*s %llu %llu %llu %llu %llu %llu %llu %llu %*llu %*llu",
            &cur_cpus[index]->cpu_user_total_second,
            &cur_cpus[index]->cpu_nice_total_second,
            &cur_cpus[index]->cpu_system_total_second,
            &cur_cpus[index]->cpu_idle_total_second,
            &cur_cpus[index]->cpu_iowait_total_second,
            &cur_cpus[index]->cpu_irq_total_second,
            &cur_cpus[index]->cpu_softirq_total_second,
            &cur_cpus[index]->cpu_steal_total_second);
        if (ret < PROC_STAT_FILEDS_NUM) {
            DEBUG("system_cpu.probe faild get proc_stat metrics.\n");
        }
        index++;
    }
    (void)fclose(f);
    return 0;
}

static int get_softirq_info(void)
{
    FILE *f = NULL;
    char *field, *save;

    softirq_line[0] = 0;
    f = popen(SYSTEM_PROCESSOR_INFO, "r");
    if (f == NULL) {
        return -1;
    }
    while (fgets(softirq_line, softirq_line_num - 1, f) != NULL) {
        field = __strtok_r(softirq_line, " ", &save);
        if (strcmp(field, "RCU:") == 0) {
            for (size_t i = 0; i < cpus_num; i++) {
                cur_cpus[i]->rcu = strtoul(__strtok_r(NULL, " ", &save), NULL, 10);
            }
        } else if (strcmp(field, "TIMER:") == 0) {
            for (size_t i = 0; i < cpus_num; i++) {
                cur_cpus[i]->timer = strtoul(__strtok_r(NULL, " ", &save), NULL, 10);
            }
        } else if (strcmp(field, "SCHED:") == 0) {
            for (size_t i = 0; i < cpus_num; i++) {
                cur_cpus[i]->sched = strtoul(__strtok_r(NULL, " ", &save), NULL, 10);
            }
        } else if (strcmp(field, "NET_RX:") == 0) {
            for (size_t i = 0; i < cpus_num; i++) {
                cur_cpus[i]->net_rx = strtoul(__strtok_r(NULL, " ", &save), NULL, 10);
            }
        }
        softirq_line[0] = 0;
    }

    pclose(f);
    return 0;
}

static int get_softnet_stat_info(void)
{
    FILE *f = fopen(SOFTNET_STAT_PATH, "r");
    char line[LINE_BUF_LEN];
    char *val, *save;

    if (f == NULL) {
        return -1;
    }

    int i = 0;
    line[0] = 0;
    while (fgets(line, LINE_BUF_LEN, f) != NULL) {
        int t = 2;
        val = __strtok_r(line, " ", &save);
        while (val != NULL) {
            val = __strtok_r(NULL, " ", &save);
            if (t == SOFTNET_DROP_COL) {
                cur_cpus[i]->backlog_drops = strtoll(val, NULL, BASE_HEX);
            }
            if (t == SOFTNET_RPS_COL) {
                cur_cpus[i]->rps_count = strtoll(val, NULL, BASE_HEX);
                break;
            }
            t++;
        }
        line[0] = 0;
        i++;
    }

    (void)fclose(f);
    return 0;
}

static int get_cpu_mhz_info(void)
{
    FILE *f = NULL;
    char line[LINE_BUF_LEN];
    char *token, *last_token;

    f = popen(SYSTEM_CPU_MHZ_INFO, "r");
    if (f == NULL) {
        return -1;
    }
    int index = 0;
    line[0] = 0;
    while (fgets(line, LINE_BUF_LEN, f) != NULL) {
        last_token = NULL;
        token = strtok(line, ":");
        while (token != NULL) {
            last_token = token;
            token = strtok(NULL, ":");
        }
        if (last_token != NULL && index < cpus_num) {
            cur_cpus[index]->mhz = strtod(last_token, NULL);
            index++;
        }
    }

    pclose(f);
    return 0;
}

static int get_cpu_info(void)
{
    if (get_softirq_info() < 0) {
        ERROR("[SYSTEM_PROBE] fail to collect softirq info\n");
        return -1;
    }
    if (get_proc_stat_info() < 0) {
        ERROR("[SYSTEM_PROBE] fail to collect proc stat info\n");
        return -1;
    }
    if (get_softnet_stat_info() < 0) {
        ERROR("[SYSTEM_PROBE] fail to collect softnet stat info\n");
        return -1;
    }
    if (get_cpu_mhz_info() < 0) {
        ERROR("[SYSTEM_PROBE] fail to collect cpu mhz info\n");
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

static u64 jiffies_to_msecs(u64 j)
{
    return (USEC_PER_MSEC / HZ) * j;
}

int system_cpu_init(void)
{
    cpus_num = (int)sysconf(_SC_NPROCESSORS_CONF);
    if (cpus_num < 0 || cpus_num > MAX_CPU_NUM) {
        ERROR("[SYSTEM_PROBE] sysconf to read the number of cpus error\n");
        return -1;
    }
    cur_cpus = alloc_memory();
    old_cpus = alloc_memory();
    if (cur_cpus == NULL || old_cpus == NULL) {
        ERROR("[SYSTEM_PROBE] fail alloc memory for cpu probe structure\n");
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
    softirq_line_num = MAX_COL_NUM * (1 + cpus_num);
    softirq_line = (char*)malloc(softirq_line_num);
    return 0;
}

void system_cpu_destroy(void)
{
    dealloc_memory(cur_cpus);
    dealloc_memory(old_cpus);
    if (softirq_line != NULL) {
        free(softirq_line);
        softirq_line = NULL;
    }
    cur_cpus = NULL;
    old_cpus = NULL;
}

int system_cpu_probe(struct ipc_body_s *ipc_body)
{
    struct cpu_stat **tmp_pptr;
    struct cpu_stat *tmp_ptr;
    int ret;
    if (get_cpu_info() < 0) {
        ERROR("[SYSTEM_PROBE] fail to collect cpus info\n");
        return -1;
    }
    if (is_first_get == true) {
        tmp_pptr = old_cpus;
        old_cpus = cur_cpus;
        cur_cpus = tmp_pptr;
        is_first_get = false;
        return 0;
    }
    report_cpu_status(ipc_body);
    for (size_t i = 0; i < cpus_num; i++) {
        ret = nprobe_fprintf(stdout, "|%s|%d|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%.2f|%.3f|\n",
            METRICS_CPU_NAME,
            cur_cpus[i]->cpu_num,
            cur_cpus[i]->rcu - old_cpus[i]->rcu,
            cur_cpus[i]->timer - old_cpus[i]->timer,
            cur_cpus[i]->sched - old_cpus[i]->sched,
            cur_cpus[i]->net_rx - old_cpus[i]->net_rx,
            (cur_cpus[i]->cpu_user_total_second > old_cpus[i]->cpu_user_total_second) ?
                jiffies_to_msecs(cur_cpus[i]->cpu_user_total_second - old_cpus[i]->cpu_user_total_second) : 0,
            (cur_cpus[i]->cpu_nice_total_second > old_cpus[i]->cpu_nice_total_second) ?
                jiffies_to_msecs(cur_cpus[i]->cpu_nice_total_second - old_cpus[i]->cpu_nice_total_second) : 0,
            (cur_cpus[i]->cpu_system_total_second > old_cpus[i]->cpu_system_total_second) ?
                jiffies_to_msecs(cur_cpus[i]->cpu_system_total_second - old_cpus[i]->cpu_system_total_second) : 0,
            (cur_cpus[i]->cpu_idle_total_second > old_cpus[i]->cpu_idle_total_second) ?
                jiffies_to_msecs(cur_cpus[i]->cpu_idle_total_second - old_cpus[i]->cpu_idle_total_second) : 0,
            (cur_cpus[i]->cpu_iowait_total_second > old_cpus[i]->cpu_iowait_total_second) ?
                jiffies_to_msecs(cur_cpus[i]->cpu_iowait_total_second - old_cpus[i]->cpu_iowait_total_second) : 0,
            (cur_cpus[i]->cpu_irq_total_second > old_cpus[i]->cpu_irq_total_second) ?
                jiffies_to_msecs(cur_cpus[i]->cpu_irq_total_second - old_cpus[i]->cpu_irq_total_second) : 0,
            (cur_cpus[i]->cpu_softirq_total_second > old_cpus[i]->cpu_softirq_total_second) ?
                jiffies_to_msecs(cur_cpus[i]->cpu_softirq_total_second - old_cpus[i]->cpu_softirq_total_second) : 0,
            (cur_cpus[i]->cpu_steal_total_second > old_cpus[i]->cpu_steal_total_second) ?
                jiffies_to_msecs(cur_cpus[i]->cpu_steal_total_second - old_cpus[i]->cpu_steal_total_second) : 0,
            cur_cpus[i]->backlog_drops - old_cpus[i]->backlog_drops,
            cur_cpus[i]->rps_count - old_cpus[i]->rps_count,
            cur_cpus[i]->cpu_util_per,
            cur_cpus[i]->mhz);
        tmp_ptr = old_cpus[i];
        old_cpus[i] = cur_cpus[i];
        cur_cpus[i] = tmp_ptr;
        if (ret < 0) {
            return -1;
        }
    }
    ret = nprobe_fprintf(stdout, "|%s|%s|%.2f|\n",
        METRICS_CPU_UTIL_NAME,
        "cpu",
        util_per);
    if (ret < 0) {
        return -1;
    }
    return 0;
}
