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
 * Description: basic task struct
 ******************************************************************************/
#ifndef __GOPHER_THREAD_H__
#define __GOPHER_THREAD_H__

#pragma once

#define SHARE_MAP_TASK_MAX_ENTRIES (10 * 1024)

enum task_status_type {
    TASK_STATUS_ACTIVE = 0,
    TASK_STATUS_INACTIVE,
    TASK_STATUS_INVALID,
    TASK_STATUS_MAX,
};

struct task_io_data {
    __u64 bio_bytes_read;
    __u64 bio_bytes_write;

    __u64 iowait_us;
    __u32 hang_count;

    __u32 bio_err_count;
};

struct task_cpu_data {
    int off_cpu_no;
    __u64 off_cpu_ns;
    __u64 off_cpu_start;
    int preempt_id;                     // Preemptor process ID
    char preempt_comm[TASK_COMM_LEN];   // Preemptor process name

    u32 migration_count;
    int current_cpu_no;
};

struct task_id {
    int tgid;                   // task group id
    int pid;                    // tid: thread id
    int ppid;                   // parent process id
    int pgid;                   // process group id
    char comm[TASK_COMM_LEN];   // process comm
};

struct task_ts_s {
    u64 ts_io;
    u64 ts_cpu;
};

struct task_data {
    u32 flags;
    struct task_ts_s stats_ts;
    struct task_id id;
    struct task_io_data io;
    struct task_cpu_data cpu;
};

#endif
