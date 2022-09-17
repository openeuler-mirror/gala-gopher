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
#ifndef SYSTEM_CPU_RPOBE__H
#define SYSTEM_CPU_RPOBE__H

#pragma once

#include "args.h"
#include "common.h"

struct cpu_stat {
    int cpu_num;
    u64 rcu;
    u64 timer;
    u64 sched;
    u64 net_rx;
    u64 cpu_user_total_second;
    u64 cpu_nice_total_second;
    u64 cpu_system_total_second;
    u64 cpu_iowait_total_second;
    u64 cpu_irq_total_second;
    u64 cpu_softirq_total_second;
    u64 backlog_drops;
    u64 rps_count;
};

int system_cpu_init(void);
int system_cpu_probe(struct probe_params *params);
void system_cpu_destroy(void);

#endif
