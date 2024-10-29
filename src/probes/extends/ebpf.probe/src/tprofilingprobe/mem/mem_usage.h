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
#ifndef __TP_MEM_USAGE_H__
#define __TP_MEM_USAGE_H__
#include <stdbool.h>
#include <time.h>
#include <uthash.h>

#include "tprofiling.h"
#include "ipc.h"

#define MEM_USAGE_CACHED_NUM 1000

struct mem_usage_metric {
    time_t ts;
    float mem_usage;    // 单位为百分比(%)
};

struct mem_round_queue {
    struct mem_usage_metric metric[MEM_USAGE_CACHED_NUM];
    int front;  // 队头下标
    int rear;   // 队尾下标
};

struct proc_mem_usage {
    u32 pid;    /* hash key */
    char comm[TASK_COMM_LEN];
    time_t last_stat_ts;
    struct mem_round_queue mrq;
    UT_hash_handle hh;
};

struct proc_mem_usage **get_mem_usage_tbl(void);

int mem_usage_probe(void);
void clean_mem_usage_probe(void);
int mem_usage_detect_oom(struct proc_mem_usage *proc_item, char *is_grow);

#endif