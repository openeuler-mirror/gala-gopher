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
 * Create: 2022-06-19
 * Description: include file for system_proc
 ******************************************************************************/
#ifndef SYSTEM_PROC_RPOBE__H
#define SYSTEM_PROC_RPOBE__H

#pragma once

#include <uthash.h>
#include "common.h"

#define PROC_NAME_MAX       64
#define PROC_CMD_LINE_MAX   128
#define PROC_MAX_RANGE      64
#define PROC_IN_PROBE_RANGE 1
#define PROC_CMDLINE_MAX    4096

#define CONTAINER_ID_BUF_LEN (CONTAINER_ABBR_ID_LEN + 4)

enum proc_io_e {
    PROC_IO_RCHAR = 0,
    PROC_IO_WCHAR,
    PROC_IO_SYSCR,
    PROC_IO_SYSCW,
    PROC_IO_READ_BYTES,
    PROC_IO_WRITE_BYTES,
    PROC_IO_CANCEL_WRITE_BYTES,

    PROC_IO_MAX
};

enum proc_stat_e {
    PROC_STAT_MIN_FLT = 0,
    PROC_STAT_MAJ_FLT,
    PROC_STAT_UTIME,
    PROC_STAT_STIME,
    PROC_STAT_VSIZE,
    PROC_STAT_RSS,

    PROC_STAT_MAX
};

enum proc_mss_e {
    PROC_MSS_RESIDENT = 0,
    PROC_MSS_SHARED_CLEAN,
    PROC_MSS_SHARED_DIRTY,
    PROC_MSS_PRIVATE_CLEAN,
    PROC_MSS_PROVATE_DIRTY,
    PROC_MSS_REFERENCED,
    PROC_MSS_ANONYMOUS,
    PROC_MSS_LAZYFREE,
    PROC_MSS_ANONYMOUS_THP,
    PROC_MSS_SWAP,
    PROC_MSS_SHARED_HUGETLB,
    PROC_MSS_PRIVATE_HUGETLB,
    PROC_MSS_PSS,
    PROC_MSS_PSS_LOCKED,
    PROC_MSS_SWAP_PSS,
    PROC_MSS_CHECK_SHNEM_SWAP,

    PROC_MSS_MAX
};

typedef struct {
    u32 pid;         // process id
    u64 start_time;  // time the process started
} proc_key_t;

typedef struct {
    char comm[PROC_NAME_MAX];
    int pgid;
    int ppid;
    char *cmdline;
    char container_id[CONTAINER_ID_BUF_LEN];
    u32 fd_count;              // FROM '/usr/bin/ls -l /proc/[PID]/fd | wc -l'
    u32 max_fd_limit;          // FROM 'cat /proc/[PID]/limits | grep -w "MAX open files"'
    u32 proc_syscr_count;      // FROM same as 'task_rchar_bytes'
    u32 proc_syscw_count;      // FROM same as 'task_rchar_bytes'
    u64 proc_rchar_bytes;    // FROM '/proc/[PID]/io'
    u64 proc_wchar_bytes;    // FROM same as 'task_rchar_bytes'
    u64 proc_read_bytes;     // FROM same as 'task_rchar_bytes'
    u64 proc_write_bytes;    // FROM same as 'task_rchar_bytes'
    u64 proc_cancelled_write_bytes;  // FROM same as 'task_rchar_bytes'
    u32 proc_oom_score_adj;    // FROM tracepoint 'oom_score_adj_update'
    u32 proc_shared_dirty;    // FROM '/usr/bin/cat /proc/%s/smaps_rollup'
    u32 proc_shared_clean;    // FROM same as proc_shared_dirty
    u32 proc_private_dirty;   // FROM same as proc_shared_dirty
    u32 proc_private_clean;   // FROM same as proc_shared_dirty
    u32 proc_referenced;      // FROM same as proc_shared_dirty
    u32 proc_lazyfree;        // FROM same as proc_shared_dirty
    u32 proc_swap;            // FROM same as proc_shared_dirty
    u32 proc_swappss;         // FROM same as proc_shared_dirty
    u64 proc_stat_min_flt;   // FROME '/usr/bin/cat /proc/%s/stat'
    u64 proc_stat_maj_flt;   // FROM same as proc_stat_min_flt
    u64 proc_stat_utime;     // FROM same as proc_stat_min_flt
    u64 proc_stat_stime;     // FROM same as proc_stat_min_flt
    u64 proc_stat_vsize;     // FROM same as proc_stat_min_flt
    u64 proc_stat_rss;       // FROM same as proc_stat_min_flt
} proc_info_t;

typedef struct {
    proc_key_t key;     // key
    char flag;          // whether in proc_range list, 1:yes/0:no
    proc_info_t info;  
    UT_hash_handle hh;
} proc_hash_t;

struct proc_match_s {
    char name[PROC_NAME_MAX];
    char cmd_line[PROC_CMD_LINE_MAX];
};

int system_proc_probe(void);
void system_proc_init(char *task_whitelist);
void system_proc_destroy(void);

#endif
