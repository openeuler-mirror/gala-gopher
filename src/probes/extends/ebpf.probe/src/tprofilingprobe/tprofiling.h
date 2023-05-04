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
 * Description: the header file of thread profiling probe
 ******************************************************************************/
#ifndef __TPROFILING_H__
#define __TPROFILING_H__
#include "syscall_table.h"

#ifndef __u64
typedef unsigned long long __u64;
#endif

#ifndef __u32
typedef unsigned int __u32;
#endif

#define EVENT_NAME_LEN  16
#define MAX_SIZE_OF_THREAD 1024
#define MAX_SIZE_OF_STASH_EVENT 10240
#define THREAD_COMM_LEN 16

#define DFT_AGGR_DURATION (1000 * NSEC_PER_MSEC)

typedef struct {
    int filter_enabled;
    int filter_local;
    __u64 aggr_duration;
} profiling_setting_t;

typedef enum {
    EVT_TYPE_SYSCALL = 1,
    EVT_TYPE_ONCPU
} trace_event_type_t;

enum {
    SYSCALL_FLAG_FD = 1,            // 获取 fd 信息的标记
    SYSCALL_FLAG_STACK = 1 << 1,    // 获取函数调用栈信息的标记
};
#define SYSCALL_FLAG_FD_STACK (0 | SYSCALL_FLAG_FD | SYSCALL_FLAG_STACK)

typedef struct {
    unsigned long nr;
    int flag;
} syscall_m_meta_t;

typedef struct {
    int uid;    // 用户栈ID
    int kid;    // 内核栈ID
} stack_trace_t;

typedef struct {
    __u32 pid;
    unsigned long nr;
    __u64 start_time;
} syscall_m_enter_t;

typedef union {
    struct {
        int fd;
    } fd_info;
    struct {
        void *addr;
        int op;
    } futex_info;
} syscall_ext_info_t;

typedef struct {
    unsigned long nr;   // 系统调用号
    __u64 start_time;   // 系统调用的开始时间（若为多个系统调用事件聚合，则表示第一个事件的开始时间）
    __u64 end_time;     // 系统调用的结束时间（若为多个系统调用事件聚合，则表示最后一个事件的结束时间）
    __u64 duration;     // 系统调用的执行时间（若为多个系统调用事件聚合，则表示累计的执行时间）
    int count;          // 聚合的系统调用事件的数量
    syscall_ext_info_t ext_info;    // 不同系统调用类型的扩展信息
    stack_trace_t stack_info;       // 函数调用栈信息
} syscall_data_t;

typedef struct {
    int pid;
    unsigned long nr;
} syscall_m_stash_key_t;
typedef syscall_data_t syscall_m_stash_val_t;

typedef struct {
    int pid;
    __u64 start_time;
} oncpu_m_enter_t;

typedef struct {
    __u64 start_time;
    __u64 end_time;
    __u64 duration;
    int count;
} oncpu_data_t;

typedef struct {
    __u64 timestamp;
    int pid;
    int tgid;
    char comm[THREAD_COMM_LEN];
    trace_event_type_t type;
    union {
        syscall_data_t syscall_d;
        oncpu_data_t oncpu_d;
    };
} trace_event_data_t;

#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
#include "proc_info.h"
#include "thrd_bl.h"

typedef struct {
    int stackMapFd;             /* ebpf map，用于获取调用栈信息 */
    int threadBlMapFd;          /* ebpf map，用于更新线程黑名单 */
    int enableFilter;           /* 是否开启进程/线程过滤功能，默认开启。若探针启动时指定了 -A 参数，则关闭，此时会观测所有进程/线程 */
    int filterLocal;            /* 是否启用本地配置进行进程过滤。若值为 1 则启用，否则使用全局共享的进程白名单进行过滤 */
    __u64 aggrDuration;         /* 线程profiling事件聚合周期，单位：纳秒（ns） */
    syscall_meta_t *scmTable;   /* 系统调用元数据表，是一个 hash 表 */
    __u64 sysBootTime;          /* 系统启动时间，单位：纳秒（ns） */
    proc_info_t *procTable;     /* 缓存的进程信息表，是一个 hash 表 */
    ThrdBlacklist thrdBl;       /* 线程黑名单 */
} Tprofiler;

extern Tprofiler tprofiler;
#endif

#endif