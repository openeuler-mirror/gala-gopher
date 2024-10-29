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
 * Author: algorithmofdish
 * Create: 2024-10-24
 * Description: memory usage probe
 ******************************************************************************/
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "common.h"
#include "oom_detector.h"
#include "mem_usage.h"

#define LIST_ALL_PID_MEM_CMD "ps -eo pid,%mem,comm --sort=-%mem"

#define MEM_USAGE_LOW_BOUND (0.1f)      // 忽略对内存使用率一直小于 0.1% 的进程的采集
#define MEM_USAGE_SAMPLE_INTV 60        // unit: second
#define MEM_USAGE_SAMPLE_VALID_NUM 10   // 用于检测内存增长的最小的采样点数量
#define TOP_MEM_USAGE_PROC_NUM 1000

#define MEM_USAGE_EXPIRE_DURATION (MEM_USAGE_SAMPLE_INTV * MEM_USAGE_SAMPLE_VALID_NUM)  // unit: second
#define MEM_USAGE_TABLE_MAX_NUM (TOP_MEM_USAGE_PROC_NUM * 2)

static time_t g_last_stat = 0;
static struct proc_mem_usage *mem_usage_tbl = NULL;

struct proc_mem_usage **get_mem_usage_tbl(void)
{
    return &mem_usage_tbl;
}

static void mrq_init(struct mem_round_queue *mrq)
{
    mrq->front = 0;
    mrq->rear = 0;
}

static __maybe_unused bool mrq_is_empty(struct mem_round_queue *mrq)
{
    return mrq->front == mrq->rear;
}

static bool mrq_is_full(struct mem_round_queue *mrq)
{
    return (mrq->rear + 1) % MEM_USAGE_CACHED_NUM == mrq->front;
}

static int mrq_length(struct mem_round_queue *mrq)
{
    return (mrq->rear + MEM_USAGE_CACHED_NUM - mrq->front) % MEM_USAGE_CACHED_NUM;
}

static void mrq_enqueue(struct mem_round_queue *mrq, float mem_usage, time_t ts)
{
    mrq->metric[mrq->rear].ts = ts;
    mrq->metric[mrq->rear].mem_usage = mem_usage;
    if (mrq_is_full(mrq)) {
        mrq->front = (mrq->front + 1) % MEM_USAGE_CACHED_NUM;
    }
    mrq->rear = (mrq->rear + 1) % MEM_USAGE_CACHED_NUM;
}

#define MRQ_FOREACH(mrq, metric, i) \
    for (i = (mrq)->front, (metric) = &(mrq)->metric[i]; i != (mrq)->rear; \
         i = (i + 1) % MEM_USAGE_CACHED_NUM, (metric) = &(mrq)->metric[i])

void mem_usage_append_metric(struct proc_mem_usage *proc_item, float mem_usage, time_t ts)
{
    mrq_enqueue(&proc_item->mrq, mem_usage, ts);
    proc_item->last_stat_ts = ts;
}

int process_one_sample(u32 pid, const char *comm, float mem_usage, time_t cur_ts)
{
    struct proc_mem_usage *proc_item = NULL;

    HASH_FIND(hh, mem_usage_tbl, &pid, sizeof(pid), proc_item);
    if (proc_item == NULL) {
        if (mem_usage < MEM_USAGE_LOW_BOUND) {
            return 0;
        }
        proc_item = calloc(1, sizeof(*proc_item));
        if (proc_item == NULL) {
            TP_ERROR("Failed to malloc proc_mem_usage item\n");
            return -1;
        }
        proc_item->pid = pid;
        (void)snprintf(proc_item->comm, sizeof(proc_item->comm), "%s", comm);
        mrq_init(&proc_item->mrq);
        mem_usage_append_metric(proc_item, mem_usage, cur_ts);
        HASH_ADD(hh, mem_usage_tbl, pid, sizeof(pid), proc_item);
    } else {
        /* 说明上一次没有统计到该进程的信息，这里认为该进程和上次统计到的不是同一个进程，选择覆盖历史进程的数据 */
        if (proc_item->last_stat_ts != g_last_stat) {
            if (mem_usage < MEM_USAGE_LOW_BOUND) {
                HASH_DEL(mem_usage_tbl, proc_item);
                free(proc_item);
                return 0;
            }

            (void)snprintf(proc_item->comm, sizeof(proc_item->comm), "%s", comm);
            mrq_init(&proc_item->mrq);
        }
        mem_usage_append_metric(proc_item, mem_usage, cur_ts);
    }
    return 0;
}

static void mem_usage_tbl_clear_expired_item(struct proc_mem_usage **mem_usage_tbl, time_t cur_ts)
{
    struct proc_mem_usage *proc_item, *tmp;

    HASH_ITER(hh, *mem_usage_tbl, proc_item, tmp) {
        if (proc_item->last_stat_ts + MEM_USAGE_EXPIRE_DURATION < cur_ts) {
            HASH_DEL(*mem_usage_tbl, proc_item);
            free(proc_item);
        }
    }
}

int get_mem_usage(time_t cur_ts)
{
    FILE *fp = NULL;
    char line[64];
    u32 pid;
    char comm[TASK_COMM_LEN];
    float mem_usage;
    int num = 0;

    fp = popen(LIST_ALL_PID_MEM_CMD, "r");
    if (fp == NULL) {
        TP_ERROR("Failed to list all process memory usage\n");
        return -1;
    }

    // skip first title line
    fgets(line, sizeof(line), fp);
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (num >= TOP_MEM_USAGE_PROC_NUM) {
            break;
        }
        if (sscanf(line, "%u %f %[^\n]", &pid, &mem_usage, comm) != 3) {
            TP_DEBUG("Failed to resolve line data: %s\n", line);
            continue;
        }
        if (process_one_sample(pid, comm, mem_usage, cur_ts)) {
            pclose(fp);
            return -1;
        }
        ++num;
    }

    if (HASH_COUNT(mem_usage_tbl) > MEM_USAGE_TABLE_MAX_NUM) {
        mem_usage_tbl_clear_expired_item(&mem_usage_tbl, cur_ts);
    }

    pclose(fp);
    return 0;
}

int mem_usage_probe(void)
{
    time_t now;

    (void)time(&now);
    if (now < g_last_stat + MEM_USAGE_SAMPLE_INTV) {
        return 0;
    }

    if (get_mem_usage(now)) {
        TP_ERROR("Failed to get memory usage\n");
        return -1;
    }
    g_last_stat = now;
    TP_DEBUG("Stats of get_mem_usage: time consumed = %ld s\n", time(NULL) - now);
    return 0;
}

void clean_mem_usage_tbl(void)
{
    struct proc_mem_usage *proc_item, *tmp;

    HASH_ITER(hh, mem_usage_tbl, proc_item, tmp) {
        HASH_DEL(mem_usage_tbl, proc_item);
        free(proc_item);
    }
    mem_usage_tbl = NULL;
}

void clean_mem_usage_probe(void) {
    clean_mem_usage_tbl();
    g_last_stat = 0;
}

int mem_usage_detect_oom(struct proc_mem_usage *proc_item, char *is_grow)
{
    struct mem_round_queue *mrq = &proc_item->mrq;
    int size = mrq_length(mrq);
    double *ts, *mem_usage;
    struct mem_usage_metric *metric;
    int i, j;

    if (size < MEM_USAGE_SAMPLE_VALID_NUM) {
        *is_grow = 0;
        return 0;
    }

    ts = malloc(sizeof(*ts) * size);
    mem_usage = malloc(sizeof(*mem_usage) * size);
    if (ts == NULL || mem_usage == NULL) {
        TP_ERROR("Failed to alloc memory\n");
        free(ts);
        free(mem_usage);
        return -1;
    }

    j = 0;
    MRQ_FOREACH(mrq, metric, i) {
        ts[j] = (double)metric->ts;
        mem_usage[j] = (double)metric->mem_usage;
        ++j;
    }

    *is_grow = is_mem_growing(ts, mem_usage, size);
    free(ts);
    free(mem_usage);
    return 0;
}