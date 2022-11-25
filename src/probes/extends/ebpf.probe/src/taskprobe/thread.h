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
 * Create: 2022-06-10
 * Description: basic thread struct
 ******************************************************************************/
#ifndef __GOPHER_THREAD_H__
#define __GOPHER_THREAD_H__

#pragma once

struct thread_cpu_data {
    int off_cpu_no;
    __u64 off_cpu_ns;
    __u64 off_cpu_start;
    int preempt_id;                     // Preemptor process ID
    char preempt_comm[TASK_COMM_LEN];   // Preemptor process name

    u32 migration_count;
    int current_cpu_no;
};

struct thread_id {
    int tgid;                   // task group id
    int pid;                    // tid: thread id
    int ppid;                   // parent process id
    int pgid;                   // process group id
    char comm[TASK_COMM_LEN];   // process comm
};

struct thread_ts_s {
    u64 ts_cpu;
};

struct thread_data {
    u32 flags;
    struct thread_ts_s stats_ts;
    struct thread_id id;
    struct thread_cpu_data cpu;
};


#endif
