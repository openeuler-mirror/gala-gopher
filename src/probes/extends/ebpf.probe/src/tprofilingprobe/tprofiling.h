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

// TODO: use config param instead
#define MIN_AGGR_INTERVAL_NS 1000000000

#define EVENT_NAME_LEN  16
#define MAX_SIZE_OF_THREAD 1024
#define MAX_SIZE_OF_STASH_EVENT 10240
#define THREAD_COMM_LEN 16

typedef struct {
    int filter_local;
} profiling_setting_t;

typedef enum {
    EVT_TYPE_SYSCALL = 1,
    EVT_TYPE_ONCPU
} trace_event_type_t;

enum {
    SYSCALL_FLAG_FD = 1,            // 获取 fd 信息的标记
    SYSCALL_FLAG_STACK = 1 << 1,    // 获取函数调用栈信息的标记
};

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

#endif