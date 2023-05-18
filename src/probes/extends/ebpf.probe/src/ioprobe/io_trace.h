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
 * Create: 2022-10-22
 * Description: io trace
 ******************************************************************************/
#ifndef __IO_TRACE__H
#define __IO_TRACE__H

#pragma once

#define RWBS_LEN    8
#define MINORBITS    20
#define MINORMASK    ((1U << MINORBITS) - 1)

#define MAJOR(dev)    ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)    ((unsigned int) ((dev) & MINORMASK))

#define IS_LOAD_PROBE(LOAD_TYPE, PROG_TYPE) (LOAD_TYPE & PROG_TYPE)

enum IO_ISSUE_E {
    IO_ISSUE_START = 0,
    IO_ISSUE_DRIVER,
    IO_ISSUE_DEVICE,
    IO_ISSUE_DEVICE_END,
    IO_ISSUE_END,
    IO_ISSUE_MAX
};

enum IO_STAGE_E {
    IO_STAGE_BLOCK = 0,
    IO_STAGE_DRIVER,
    IO_STAGE_DEVICE,
    IO_STAGE_MAX
};

struct io_report_s {
    u64 ts;
};

struct latency_stats {
    u64 max;          // MAX value of latency
    u64 last;         // LAST value of latency
    u64 sum;          // SUM value of latency
    u64 jitter;       // JITTER value of latency
    u32 count;        // COUNT of io operation
};

struct io_trace_s {
    int major;
    int first_minor;
    u32 proc_id;
    char comm[TASK_COMM_LEN];
    char rwbs[RWBS_LEN];
    unsigned int data_len;
    u64 ts[IO_ISSUE_MAX];
};

struct io_count_s {
    struct io_report_s io_count_ts;
    int major;
    int first_minor;
    u64 read_bytes;
    u64 write_bytes;
};

struct io_err_s {
    int major;
    int first_minor;
    u32 proc_id;
    char comm[TASK_COMM_LEN];
    char rwbs[RWBS_LEN];
    unsigned int data_len;
    int err_code;
    int scsi_tmout;
    int scsi_err;
};

struct io_req_s {
    void *request;
};

struct io_latency_s {
    struct io_report_s io_latency_ts;
    int major;
    int first_minor;
    u32 proc_id;
    char comm[TASK_COMM_LEN];
    char rwbs[RWBS_LEN];
    unsigned int data_len;
    struct latency_stats latency[IO_STAGE_MAX];
};

struct io_entity_s {
    int major;
    int first_minor;
};

struct pagecache_entity_s {
    int major;
    int first_minor;
};

struct pagecache_stats_s {
    struct io_report_s page_cache_ts;
    int major;
    int first_minor;
    u32 access_pagecache;
    u32 mark_buffer_dirty;
    u32 load_page_cache;
    u32 mark_page_dirty;
};

struct io_trace_args_s {
    int target_major;
    int target_first_minor;
    u64 report_period;      // unit: nanosecond
    u64 sample_interval;    // unit: nanosecond
};

#endif
