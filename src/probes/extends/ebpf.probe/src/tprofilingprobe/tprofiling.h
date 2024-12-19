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
#include "common.h"
#include "syscall_table.h"
#include "pthread_table.h"
#include "py_stack.h"

#define TPROFILING_PROBE_SYSCALL_ALL \
    (u32)(PROBE_RANGE_TPROFILING_SYSCALL_FILE | PROBE_RANGE_TPROFILING_SYSCALL_NET \
    | PROBE_RANGE_TPROFILING_SYSCALL_SCHED | PROBE_RANGE_TPROFILING_SYSCALL_LOCK)
#define TPROFILING_EBPF_PROBE_ALL \
    (u32)(PROBE_RANGE_TPROFILING_ONCPU | TPROFILING_PROBE_SYSCALL_ALL | PROBE_RANGE_TPROFILING_PYTHON_GC \
    | PROBE_RANGE_TPROFILING_PTHREAD_SYNC | PROBE_RANGE_TPROFILING_ONCPU_SAMPLE | PROBE_RANGE_TPROFILING_MEM_GLIBC)
#define TPROFILING_PROBE_ALL (u32)(TPROFILING_EBPF_PROBE_ALL | PROBE_RANGE_TPROFILING_MEM_USAGE)

#define TPROFILING_PROBES_WITH_STACK (u32)(TPROFILING_PROBE_SYSCALL_ALL | PROBE_RANGE_TPROFILING_PYTHON_GC \
    | PROBE_RANGE_TPROFILING_PTHREAD_SYNC | PROBE_RANGE_TPROFILING_ONCPU_SAMPLE | PROBE_RANGE_TPROFILING_MEM_GLIBC)

#define EVENT_NAME_LEN      16
#define MAX_SIZE_OF_PROC    128
#define MAX_SIZE_OF_THREAD  (128 * MAX_SIZE_OF_PROC)
#define THREAD_COMM_LEN     16

#define DFT_AGGR_DURATION   (100 * NSEC_PER_MSEC)   // 100ms
#define DFT_STATS_DURATION  (100 * NSEC_PER_MSEC)
#define MIN_EXEC_DURATION   (1 * NSEC_PER_USEC)     // 1us

typedef struct {
    __u64 min_exec_dur;
    __u64 min_aggr_dur;
    char is_pb_a;
} trace_setting_t;

typedef enum {
    EVT_TYPE_SYSCALL = 1,
    EVT_TYPE_SYSCALL_STUCK,
    EVT_TYPE_ONCPU,
    EVT_TYPE_OFFCPU,
    EVT_TYPE_PYGC,
    EVT_TYPE_PTHREAD,
    EVT_TYPE_ONCPU_PERF,
    EVT_TYPE_MEM_GLIBC
} trace_event_type_t;

enum {
    SYSCALL_FLAG_FD = 1,            // 获取 fd 信息的标记
    SYSCALL_FLAG_STACK = 1 << 1,    // 获取函数调用栈信息的标记
};
#define SYSCALL_FLAG_FD_STACK (0 | SYSCALL_FLAG_FD | SYSCALL_FLAG_STACK)

typedef struct {
    unsigned long nr;
    unsigned int flag;
} syscall_m_meta_t;

typedef struct {
    int uid;    // 用户栈ID
    int kid;    // 内核栈ID
    __u64 pyid;   // py栈ID
} stack_trace_t;

typedef union {
    struct {
        int fd;
    } fd_info;
    struct {
        int op;
    } futex_info;
    struct {
        unsigned int cmd;
    } ioctl_info;
} syscall_ext_info_t;

typedef struct {
    __u64 ptid;
    __u64 start_time;
    __u64 end_time;
    unsigned long nr;
    syscall_ext_info_t ext_info;
} syscall_m_enter_t;

#define PTID_GET_PID(ptid) ((u32)((ptid) >> 32))
#define PTID_GET_TID(ptid) ((u32)(ptid))

struct stats_stack_elem {
    stack_trace_t stack;
    __u64 duration;
};

struct stats_fd_elem {
    int fd;
    unsigned long ino;
    unsigned short imode;
    __u64 duration;
};

struct stats_futex_elem {
    int op;
    __u64 duration;
};

struct stats_ioctl_elem {
    unsigned int cmd;
    __u64 duration;
};

typedef struct {
    struct stats_stack_elem stats_stack;
    union {
        struct stats_fd_elem stats_fd;
        struct stats_futex_elem stats_futex;
        struct stats_ioctl_elem stats_ioctl;
    };
} stats_syscall_t;

typedef struct {
    unsigned long nr;   // 系统调用号
    __u64 start_time;   // 系统调用的开始时间（若为多个系统调用事件聚合，则表示第一个事件的开始时间）
    __u64 end_time;     // 系统调用的结束时间（若为多个系统调用事件聚合，则表示最后一个事件的结束时间）
    __u64 duration;     // 系统调用的执行时间（若为多个系统调用事件聚合，则表示累计的执行时间）
    int count;          // 聚合的系统调用事件的数量
    stats_syscall_t stats;
} syscall_data_t;

typedef struct {
    int pid;
    unsigned long nr;
} syscall_m_stash_key_t;

typedef struct {
    int pid;
    __u64 start_time;
    __u64 end_time;
} common_m_enter_t;

typedef struct {
    __u64 start_time;
    __u64 end_time;
    __u64 duration;
    int count;
} common_data_t;

typedef common_m_enter_t oncpu_m_enter_t;
typedef common_data_t oncpu_data_t;

typedef struct {
    __u64 start_time;
    __u64 end_time;
    __u64 duration;
    int count;
    struct stats_stack_elem stats_stack;
} offcpu_data_t;

typedef struct {
    __u64 start_time;
    __u64 end_time;
    __u64 duration;
    int count;
    struct stats_stack_elem stats_stack;
} pygc_data_t;

typedef common_m_enter_t pygc_m_enter_t;

typedef struct {
    int pid;
    int id;
} pthrd_m_key_t;

typedef struct {
    pthrd_m_key_t key;
    __u64 start_time;
    __u64 end_time;
} pthrd_m_enter_t;

typedef struct {
    __u64 start_time;
    __u64 end_time;
    __u64 duration;
    int count;
    int id;
    struct stats_stack_elem stats_stack;
} pthrd_data_t;

typedef struct {
    __u64 time;
    __u32 cpu;
    struct stats_stack_elem stats_stack;
} oncpu_sample_data_t;

typedef struct {
    u64 addr;   // allocated memory address
    s64 size;   // unit: byte
    u64 ts;
    struct stats_stack_elem stats_stack;
} mem_glibc_data_t;

typedef struct {
    int pid;
    int tgid;
    char comm[THREAD_COMM_LEN];
    trace_event_type_t type;
    union {
        syscall_data_t syscall_d;
        oncpu_data_t oncpu_d;
        offcpu_data_t offcpu_d;
        pygc_data_t pygc_d;
        pthrd_data_t pthrd_d;
        oncpu_sample_data_t sample_d;
        mem_glibc_data_t mem_glibc_d;
    };
} trace_event_data_t;

#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
#include <time.h>
#include <pthread.h>
#include <uthash.h>

#include "gopher_elf.h"
#include "proc_info.h"
#include "thrd_bl.h"
#include "trace_viewer_fmt.h"
#include "proc_mem_addr.h"

#define TP_DEBUG(fmt, ...) DEBUG("[TPROFILING] " fmt, ##__VA_ARGS__)
#define TP_INFO(fmt, ...) INFO("[TPROFILING] " fmt, ##__VA_ARGS__)
#define TP_WARN(fmt, ...) WARN("[TPROFILING] " fmt, ##__VA_ARGS__)
#define TP_ERROR(fmt, ...) ERROR("[TPROFILING] " fmt, ##__VA_ARGS__)

#define ERR_TP_NO_BUFF 2

#define DEFAULT_OUTPUT_DIR "/var/log/gala-gopher/tprofiling/"

#define DFT_PERF_SAMPLE_FREQ 99   // unit: Hz
#define DFT_STACK_SYMB_NAME "[unknown]"

typedef struct {
    trace_event_type_t type;
    union {
        syscall_data_t syscall_d;
        oncpu_data_t oncpu_d;
        offcpu_data_t offcpu_d;
        pygc_data_t pygc_d;
        pthrd_data_t pthrd_d;
        oncpu_sample_data_t sample_d;
        mem_glibc_data_t mem_glibc_d;
    };
} event_data_t;

#define EVT_DATA(evt_elem) ((event_data_t *)(evt_elem)->data)
#define EVT_DATA_TYPE(evt_elem) (EVT_DATA(evt_elem)->type)
#define EVT_DATA_SC(evt_elem) (&EVT_DATA(evt_elem)->syscall_d)
#define EVT_DATA_ONCPU(evt_elem) (&EVT_DATA(evt_elem)->oncpu_d)
#define EVT_DATA_OFFCPU(evt_elem) (&EVT_DATA(evt_elem)->offcpu_d)
#define EVT_DATA_PYGC(evt_elem) (&EVT_DATA(evt_elem)->pygc_d)
#define EVT_DATA_PTHRD(evt_elem) (&EVT_DATA(evt_elem)->pthrd_d)
#define EVT_DATA_CPU_SAMPLE(evt_elem) (&EVT_DATA(evt_elem)->sample_d)

#define MAX_UBPF_PROG_NUM 32

typedef struct {
    char elf_path[PATH_LEN];
    char build_id[ELF_BUILD_ID_LEN];
    int link_num;
    struct bpf_link *links[MAX_UBPF_PROG_NUM];
} ubpf_link_t;

enum lang_type {
    LANG_TYPE_UNDEF = 0,
    LANG_TYPE_JAVA,
    LANG_TYPE_PYTHON
};

typedef struct {
    int pid;    // key
    char exe_path[PATH_LEN];
    enum lang_type lang;
    char is_active;
    ubpf_link_t *pygc_link;
    ubpf_link_t *pthrd_sync_link;
    ubpf_link_t *mem_glibc_link;
    UT_hash_handle hh;
} proc_ubpf_link_t;

#define MAX_STACK_NODE_NUM 2000000  // 保证调用栈树的内存占用小于500M
#define STUCK_EVT_REPORT_DURATION 60    // unit: second
#define STUCK_EVT_REPORT_THRD 60        // unit: second
#define MEM_SNAP_EVT_REPORT_THRD 60     // unit: second
#define PERF_BUFFER_SWITCH_DURATION 100 // unit: second

#define MEM_SNAP_TOP_STACK_NUM 3

typedef struct {
    char is_pb_a;
    struct bpf_buffer *perf_buffer_a;
    struct bpf_buffer *perf_buffer_b;
    time_t pb_switch_timer;
} PerfBufferMgmt;

typedef struct {
    struct bpf_prog_s *bpf_progs;
    int settingMapFd;           /* ebpf map，用于设置配置信息 */
    int stackMapAFd;            /* ebpf map，用于获取调用栈信息 */
    int stackMapBFd;            /* ebpf map，用于获取调用栈信息 */
    int procFilterMapFd;        /* ebpf map，用于更新进程白名单 */
    int threadBlMapFd;          /* ebpf map，用于更新线程黑名单 */
    int pyProcMapFd;
    int pyStackMapAFd;          /* ebpf map，用于获取py调用栈信息 */
    int pyStackMapBFd;          /* ebpf map，用于获取py调用栈信息 */
    int pySymbMapFd;            /* ebpf map，py符号信息 */
    int pyHeapMapFd;
    int scEnterMapFd;           /* ebpf map，用于巡检长时间未结束的系统调用事件 */
    syscall_meta_t *scmTable;   /* 系统调用元数据表，是一个 hash 表 */
    __u64 sysBootTime;          /* 系统启动时间，单位：纳秒（ns） */
    proc_info_t *procTable;     /* 缓存的进程信息表，是一个 hash 表 */
    ThrdBlacklist thrdBl;       /* 线程黑名单 */
    int report_period;          /* 线程 profiling 事件上报周期 */
    unsigned int output_chan;   /* Profiling 结果的输出方式，默认值为0，表示本地存储方式 */
    struct local_store_s localStorage;
    void *pygc_skel;            /* 用于后续挂载进程的 uprobe 探针 */
    void *pthrd_sync_skel;      /* 用于后续挂载进程的 uprobe 探针 */
    void *mem_glibc_skel;       /* 用于后续挂载进程的 uprobe 探针 */
    void **oncpu_sample_bpf_links;  /* 用于 oncpu_sample 子探针 */
    int oncpu_sample_link_num;      /* 用于 oncpu_sample 子探针 */
    time_t stuck_evt_timer;     /* 记录上次巡检长时间未结束的事件的时间点 */
    PerfBufferMgmt pbMgmt;
    // TODO: 做一下容量控制
    struct mem_alloc_s *mem_alloc_tbl;  // mem_glibc探针中使用，用于记录进程已分配的地址和对应的原始堆栈地址
    time_t mem_snap_timer;      // mem_glibc探针中使用
    char output_dir[PATH_LEN];
} Tprofiler;

extern Tprofiler tprofiler;

static inline struct bpf_buffer *get_current_perf_buffer(PerfBufferMgmt *pbMgmt)
{
    return pbMgmt->is_pb_a ? pbMgmt->perf_buffer_a : pbMgmt->perf_buffer_b;
}

static inline int get_current_stack_map()
{
    char is_pb_a = tprofiler.pbMgmt.is_pb_a;

    return is_pb_a ? tprofiler.stackMapAFd : tprofiler.stackMapBFd;
}

static inline int get_current_py_stack_map()
{
    char is_pb_a = tprofiler.pbMgmt.is_pb_a;

    return is_pb_a ? tprofiler.pyStackMapAFd : tprofiler.pyStackMapBFd;
}

#else
#include "bpf.h"
#include "py_stack_bpf.h"

#define BPF_F_INDEX_MASK  0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK

#ifndef BPF_F_FAST_STACK_CMP
#define BPF_F_FAST_STACK_CMP    (1ULL << 9)
#endif

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK    (1ULL << 8)
#endif

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(trace_setting_t));
    __uint(max_entries, 1);
} setting_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} event_map_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} event_map_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct proc_s));
    __uint(value_size, sizeof(struct obj_ref_s));
    __uint(max_entries, MAX_SIZE_OF_PROC);
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
    __uint(max_entries, (128 * 1024));   // TODO: 当前设置为一个大的值，待优化，如根据cpu数量/采样周期/stack_map更新周期等进行动态设置
} stack_map_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64) * PERF_MAX_STACK_DEPTH);
    __uint(max_entries, (128 * 1024));
} stack_map_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(trace_event_data_t));
    __uint(max_entries, 1);
} event_stash_heap SEC(".maps");

static __always_inline trace_setting_t *get_trace_setting()
{
    trace_setting_t *setting;
    u32 zero = 0;

    setting = (trace_setting_t *)bpf_map_lookup_elem(&setting_map, &zero);
    return setting;
}

static __always_inline char is_proc_enabled(u32 tgid)
{
    struct proc_s proc_k = {.proc_id = tgid};
    void *proc_v;

    proc_v = bpf_map_lookup_elem(&proc_filter_map, &proc_k);
    if (proc_v != (void *)0) {
        return 1;
    }

    return 0;
}

static __always_inline char is_thrd_enabled(u32 pid, u32 tgid)
{
    u32 *val;
    val = (u32 *)bpf_map_lookup_elem(&thrd_bl_map, &pid);
    if (val == (void *)0) {
        return 1;
    }

    if (*val == tgid) {
        return 0;
    } else {
        // invalid thread item in blacklist map
        bpf_map_delete_elem(&thrd_bl_map, &pid);
        return 1;
    }
}

static __always_inline __maybe_unused char is_proc_thrd_enabled()
{
    u64 pid_tgid;
    u32 tgid, pid;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> INT_LEN;
    pid = (u32)pid_tgid;

    return is_proc_enabled(tgid) && is_thrd_enabled(pid, tgid);
}

static __always_inline char can_emit(u64 stime, u64 etime)
{
    u64 aggr_dur = DFT_AGGR_DURATION;
    trace_setting_t *setting;

    setting = get_trace_setting();
    if (setting) {
        aggr_dur = setting->min_aggr_dur;
    }

    if (etime >= stime + aggr_dur) {
        return 1;
    }
    return 0;
}

static __always_inline trace_event_data_t *new_trace_event()
{
    u32 zero = 0;
    trace_event_data_t *evt;

    evt = (trace_event_data_t *)bpf_map_lookup_elem(&event_stash_heap, &zero);
    return evt;
}

static __always_inline __maybe_unused void init_trace_event_common(trace_event_data_t *evt_data, trace_event_type_t type)
{
    u64 ptid = bpf_get_current_pid_tgid();

    evt_data->type = type;
    evt_data->pid = (u32)ptid;
    evt_data->tgid = (u32)(ptid >> INT_LEN);
    (void)bpf_get_current_comm(evt_data->comm, sizeof(evt_data->comm));
}

static __always_inline void *bpf_get_current_stack_map()
{
    trace_setting_t *setting;

    setting = get_trace_setting();
    if (setting != NULL) {
        return setting->is_pb_a ? (void *)&stack_map_a : (void *)&stack_map_b;
    }

    return NULL;
}

static __always_inline void *bpf_get_current_event_map()
{
    trace_setting_t *setting;

    setting = get_trace_setting();
    if (setting != NULL) {
        return setting->is_pb_a ? (void *)&event_map_a : (void *)&event_map_b;
    }

    return NULL;
}

static __always_inline void *bpf_get_current_py_stack_map()
{
    trace_setting_t *setting;

    setting = get_trace_setting();
    if (setting != NULL) {
        return setting->is_pb_a ? (void *)&py_stack_a : (void *)&py_stack_b;
    }

    return NULL;
}

static __always_inline __maybe_unused int stats_append_stack(struct stats_stack_elem *stack_elem, u64 duration, void *ctx)
{
    void *cur_stack_map;
    void *cur_py_stack;
    int uid;
    int tgid;

    cur_stack_map = bpf_get_current_stack_map();
    if (cur_stack_map == NULL) {
        return -1;
    }
    uid = bpf_get_stackid(ctx, cur_stack_map, USER_STACKID_FLAGS);
    if (uid < 0) {
        return -1;
    }
    stack_elem->stack.uid = uid;

    cur_py_stack = bpf_get_current_py_stack_map();
    if (cur_py_stack == NULL) {
        return -1;
    }
    tgid = (int)(bpf_get_current_pid_tgid() >> INT_LEN);
    stack_elem->stack.pyid = get_py_stack_id(tgid, cur_py_stack); // 拿不到堆栈，返回0值
    stack_elem->duration = duration;
    return 0;
}

#endif

#endif
