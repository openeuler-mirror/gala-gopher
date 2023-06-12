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
 * Create: 2022-11-07
 * Description: sched probe
 ******************************************************************************/
#ifndef __SCHED_PROBE__H
#define __SCHED_PROBE__H

#pragma once

enum sched_evt_t {
    SCHED_LAT_START = 0,
    SCHED_LAT_CONT,
    SCHED_LAT_END,
    SCHED_LAT_MAX
};

struct sched_args_s {
    char is_target_wl;
    char pad[3];
    u64 latency_thr;        // unit: nanosecond
};

struct syscall_info_s {
    long int sysid;

    u64 csw, enter, exit;   // unit: nanosecond
    u64 wait, sleep;        // unit: nanosecond
};

struct systime_info_s {
    u64 start, end;         // unit: nanosecond
    u64 delay, issue;       // unit: nanosecond
};

enum event_t {
    EVT_SYSTIME = 0,
    EVT_SYSCALL,
    EVT_MAX
};

struct event {
    char comm[TASK_COMM_LEN];
    u32 proc_id;
    int cpu;
    u32 stack_id;

    enum event_t e;

    union {
        struct systime_info_s systime;
        struct syscall_info_s syscall;
    } body;
};

#endif
