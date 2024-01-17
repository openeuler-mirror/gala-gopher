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
#define MIN_EXEC_DURATION NSEC_PER_MSEC

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

typedef union {
    struct {
        int fd;
    } fd_info;
    struct {
        int op;
    } futex_info;
} syscall_ext_info_t;

typedef struct {
    __u32 pid;
    __u64 start_time;
    __u64 end_time;
    syscall_ext_info_t ext_info;
} syscall_m_enter_t;

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
    __u64 end_time;
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
#include <time.h>
#include <pthread.h>
#include <uthash.h>

#include "proc_info.h"
#include "thrd_bl.h"

#define TP_DEBUG(fmt, ...) DEBUG("[TPROFILING] " fmt, ##__VA_ARGS__)
#define TP_INFO(fmt, ...) INFO("[TPROFILING] " fmt, ##__VA_ARGS__)
#define TP_WARN(fmt, ...) WARN("[TPROFILING] " fmt, ##__VA_ARGS__)
#define TP_ERROR(fmt, ...) ERROR("[TPROFILING] " fmt, ##__VA_ARGS__)

typedef struct {
    trace_event_type_t type;
    union {
        syscall_data_t syscall_d;
        oncpu_data_t oncpu_d;
    };
} event_data_t;

#define EVT_DATA(evt_elem) ((event_data_t *)(evt_elem)->data)
#define EVT_DATA_TYPE(evt_elem) (EVT_DATA(evt_elem)->type)
#define EVT_DATA_SC(evt_elem) (&EVT_DATA(evt_elem)->syscall_d)
#define EVT_DATA_CPU(evt_elem) (&EVT_DATA(evt_elem)->oncpu_d)

typedef struct {
    int stackMapFd;             /* ebpf map，用于获取调用栈信息 */
    int procFilterMapFd;        /* ebpf map，用于更新进程白名单 */
    int threadBlMapFd;          /* ebpf map，用于更新线程黑名单 */
    syscall_meta_t *scmTable;   /* 系统调用元数据表，是一个 hash 表 */
    __u64 sysBootTime;          /* 系统启动时间，单位：纳秒（ns） */
    proc_info_t *procTable;     /* 缓存的进程信息表，是一个 hash 表 */
    ThrdBlacklist thrdBl;       /* 线程黑名单 */
    int report_period;          /* 线程 profiling 事件上报周期 */
} Tprofiler;

extern Tprofiler tprofiler;
#else
#include "bpf.h"

#define BPF_F_INDEX_MASK  0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK

#ifndef BPF_F_FAST_STACK_CMP
#define BPF_F_FAST_STACK_CMP    (1ULL << 9)
#endif

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK    (1ULL << 8)
#endif

#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct proc_s));
    __uint(value_size, sizeof(struct obj_ref_s));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} proc_filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} thrd_bl_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64) * PERF_MAX_STACK_DEPTH);
    __uint(max_entries, 1024);
} stack_map SEC(".maps");

static __always_inline bool is_proc_enabled(u32 tgid)
{
    struct proc_s proc_k = {.proc_id = tgid};
    void *proc_v;

    proc_v = bpf_map_lookup_elem(&proc_filter_map, &proc_k);
    if (proc_v != (void *)0) {
        return true;
    }

    return false;
}

static __always_inline bool is_thrd_enabled(u32 pid, u32 tgid)
{
    u32 *val;
    val = (u32 *)bpf_map_lookup_elem(&thrd_bl_map, &pid);
    if (val == (void *)0) {
        return true;
    }

    if (*val == tgid) {
        return false;
    } else {
        // invalid thread item in blacklist map
        bpf_map_delete_elem(&thrd_bl_map, &pid);
        return true;
    }
}

static __always_inline __maybe_unused bool is_proc_thrd_enabled()
{
    u64 pid_tgid;
    u32 tgid, pid;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> INT_LEN;
    pid = (u32)pid_tgid;

    return is_proc_enabled(tgid) && is_thrd_enabled(pid, tgid);
}

static __always_inline bool can_emit(u64 stime, u64 etime)
{
    if (etime >= stime + DFT_AGGR_DURATION) {
        return true;
    }
    return false;
}

#endif

#endif