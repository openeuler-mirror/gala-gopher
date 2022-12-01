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
 * Author: luzhihao
 * Create: 2022-07-13
 * Description: proc object define
 ******************************************************************************/
#ifndef __GOPHER_PROC_H__
#define __GOPHER_PROC_H__

#pragma once

struct syscall_s {
    u64 syscall_start_ts;

    u32 failed;
    long last_syscall_id;
    long last_ret_code;

    // I/O syscall
    u64 ns_mount;
    u64 ns_umount;
    u64 ns_read;
    u64 ns_write;
    u64 ns_fsync;

    // Network I/O syscall
    u64 ns_sendmsg;
    u64 ns_recvmsg;

    // Schedule syscall
    u64 ns_sched_yield;
    u64 ns_futex;
    u64 ns_epoll_wait;
    u64 ns_epoll_pwait;

    // Process syscall
    u64 ns_fork;
    u64 ns_vfork;
    u64 ns_clone;
};

struct fs_op_s {
    u64 ns_read;
    u64 ns_write;
    u64 ns_open;
    u64 ns_flush;
};

struct page_op_s {
    u64 reclaim_start_ts;
    u64 reclaim_ns;
    u64 count_access_pagecache;
    u64 count_mark_buffer_dirty;
    u64 count_load_page_cache;
    u64 count_mark_page_dirty;
};

struct dns_op_s {
    u64 gethostname_start_ts;
    u64 gethostname_ns;
    u64 gethostname_failed;
};

struct proc_ts_s {
    u64 ts_syscall;
    u64 ts_syscall_io;
    u64 ts_syscall_net;
    u64 ts_syscall_sched;
    u64 ts_syscall_fork;

    u64 ts_ext4_op;
    u64 ts_overlay_op;
    u64 ts_tmpfs_op;

    u64 ts_page;
    u64 ts_dns;

    u64 ts_io;
};

struct proc_io_s {
    u32 less_4k_io_read;
    u32 less_4k_io_write;
    u32 greater_4k_io_read;
    u32 greater_4k_io_write;
    u32 bio_latency;
    u32 bio_err_count;
    u32 hang_count;
    u64 iowait_us;
};

struct proc_data_s {
    char comm[TASK_COMM_LEN];
    u32 proc_id;
    u32 flags;
    struct proc_ts_s stats_ts;
    u64 fs_op_start_ts;
    struct syscall_s syscall;
    struct fs_op_s op_ext4;
    struct fs_op_s op_overlay;
    struct fs_op_s op_tmpfs;
    struct page_op_s page_op;
    struct dns_op_s dns_op;
    struct proc_io_s proc_io;
};

struct proc_exec_evt {
    char filename[PATH_LEN];
    u32 pid;
};

#endif
