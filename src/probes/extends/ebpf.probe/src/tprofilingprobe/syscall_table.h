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
 * Create: 2023-04-03
 * Description: definition of the system calls that need to be profiled
 ******************************************************************************/
#ifndef __SYSCALL_TABLE_H__
#define __SYSCALL_TABLE_H__

#define MAX_SIZE_OF_SYSCALL_TABLE 512
#define SYSCALL_NAME_LEN 16

// file

#define SYSCALL_READ_ID   0
#define SYSCALL_READ_NAME "read"

#define SYSCALL_WRITE_ID   1
#define SYSCALL_WRITE_NAME "write"

#define SYSCALL_READV_ID   19
#define SYSCALL_READV_NAME "readv"

#define SYSCALL_WRITEV_ID   20
#define SYSCALL_WRITEV_NAME "writev"

#define SYSCALL_PREADV_ID   295
#define SYSCALL_PREADV_NAME "preadv"

#define SYSCALL_PWRITEV_ID   296
#define SYSCALL_PWRITEV_NAME "pwritev"

#define SYSCALL_PREADV2_ID   327
#define SYSCALL_PREADV2_NAME "preadv2"

#define SYSCALL_PWRITEV2_ID   328
#define SYSCALL_PWRITEV2_NAME "pwritev2"

#define SYSCALL_SYNC_ID   162
#define SYSCALL_SYNC_NAME "sync"

#define SYSCALL_FSYNC_ID   74
#define SYSCALL_FSYNC_NAME "fsync"

#define SYSCALL_FDATASYNC_ID   75
#define SYSCALL_FDATASYNC_NAME "fdatasync"

#define SYSCALL_SYNCFS_ID   306
#define SYSCALL_SYNCFS_NAME "syncfs"

#define SYSCALL_MSYNC_ID   26
#define SYSCALL_MSYNC_NAME "msync"

// process

#define SYSCALL_SCHED_YIELD_ID   24
#define SYSCALL_SCHED_YIELD_NAME "sched_yield"

#define SYSCALL_PAUSE_ID   34
#define SYSCALL_PAUSE_NAME "pause"

#define SYSCALL_NANOSLEEP_ID   35
#define SYSCALL_NANOSLEEP_NAME "nanosleep"

#define SYSCALL_CLOCK_NANOSLEEP_ID   230
#define SYSCALL_CLOCK_NANOSLEEP_NAME "clock_nanosleep"

#define SYSCALL_WAIT4_ID   61
#define SYSCALL_WAIT4_NAME "wait4"

#define SYSCALL_WAITPID_ID   247
#define SYSCALL_WAITPID_NAME "waitpid"

// network

#define SYSCALL_SENDTO_ID   44
#define SYSCALL_SENDTO_NAME "sendto"

#define SYSCALL_RECVFROM_ID   45
#define SYSCALL_RECVFROM_NAME "recvfrom"

#define SYSCALL_SENDMSG_ID   46
#define SYSCALL_SENDMSG_NAME "sendmsg"

#define SYSCALL_RECVMSG_ID   47
#define SYSCALL_RECVMSG_NAME "recvmsg"

#define SYSCALL_SENDMMSG_ID   307
#define SYSCALL_SENDMMSG_NAME "sendmmsg"

#define SYSCALL_RECVMMSG_ID   299
#define SYSCALL_RECVMMSG_NAME "recvmmsg"

#define SYSCALL_SENDFILE_ID   40
#define SYSCALL_SENDFILE_NAME "sendfile"

#define SYSCALL_SELECT_ID   23
#define SYSCALL_SELECT_NAME "select"

#define SYSCALL_PSELECT6_ID   270
#define SYSCALL_PSELECT6_NAME "pselect6"

#define SYSCALL_POLL_ID   7
#define SYSCALL_POLL_NAME "poll"

#define SYSCALL_PPOLL_ID   271
#define SYSCALL_PPOLL_NAME "ppoll"

#define SYSCALL_EPOLL_WAIT_ID   232
#define SYSCALL_EPOLL_WAIT_NAME "epoll_wait"

#define SYSCALL_EPOLL_CTL_ID   233
#define SYSCALL_EPOLL_CTL_NAME "epoll_ctl"

// IPC

#define SYSCALL_SEMOP_ID   65
#define SYSCALL_SEMOP_NAME "semop"

#define SYSCALL_MSGSND_ID   69
#define SYSCALL_MSGSND_NAME "msgsnd"

#define SYSCALL_MSGRCV_ID   70
#define SYSCALL_MSGRCV_NAME "msgrcv"

#define SYSCALL_RT_SIGTIMEDWAIT_ID   128
#define SYSCALL_RT_SIGTIMEDWAIT_NAME "rt_sigtimedwait"

#define SYSCALL_RT_SIGSUSPEND_ID   130
#define SYSCALL_RT_SIGSUSPEND_NAME "rt_sigsuspend"

#define SYSCALL_FUTEX_ID   202
#define SYSCALL_FUTEX_NAME "futex"

#define SYSCALL_MQ_TIMEDSEND_ID   242
#define SYSCALL_MQ_TIMEDSEND_NAME "mq_timedsend"

#define SYSCALL_MQ_TIMEDRECEIVE_ID   243
#define SYSCALL_MQ_TIMEDRECEIVE_NAME "mq_timedreceive"

// log

#define SYSCALL_SYSLOG_ID   103
#define SYSCALL_SYSLOG_NAME "syslog"

#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
#include <uthash.h>

#define MAX_LEN_OF_PROFILE_EVT_TYPE 8

typedef struct {
    unsigned long nr;
    char name[SYSCALL_NAME_LEN];
    unsigned int flag;
    char default_type[MAX_LEN_OF_PROFILE_EVT_TYPE];
    UT_hash_handle hh;
} syscall_meta_t;
#endif

#endif