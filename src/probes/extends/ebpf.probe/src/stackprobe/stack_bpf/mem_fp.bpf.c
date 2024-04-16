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
 * Author: wo_cow
 * Create: 2022-11-3
 * Description: stack tracing based on syscall(brk/mmap)
 *     WARN: If user state lib does not contain fp pointer, this program cannot track it.
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "../stack.h"
#include "stackprobe_bpf.h"
#include "../py_stack_bpf.h"

char g_linsence[] SEC("license") = "GPL";

struct pid_addr_t {
    u32 tgid;
    u64 addr;
};

struct mmap_info_t {
    s64 size;
    u64 timestamp_ns;
    enum trace_lang_type lang_type;
    struct stack_id_s stack_id;
    u64 py_stack_id;
};

struct brk_info_t {
    u64 old_brk;
    u64 new_brk;
};

struct combined_alloc_info_t {
    u64 total_size;
    u64 number_of_allocs;
};

// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_brk/format
struct sys_enter_brk_args {
    u64 __unused__;
    int __syscall_nr;
    unsigned long brk;
};

// cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_brk/format
struct sys_exit_brk_args {
    u64 __unused__;
    int __syscall_nr;
    long ret;
};

// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/format
struct sys_enter_mmap_args {
    u64 __unused__;
    int __syscall_nr;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

// cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_mmap/format
struct sys_exit_mmap_args {
    u64 __unused__;
    int __syscall_nr;
    long ret;
};

// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_munmap/format
struct sys_enter_munmap_args {
    u64 __unused__;
    int __syscall_nr;
    unsigned long addr;
    u64 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} stackmap_perf_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} stackmap_perf_b SEC(".maps");

// memory to be allocated for the process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));  // tgid + pid
    __uint(value_size, sizeof(u64));  // size
    __uint(max_entries, 1000);
} to_allocate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct pid_addr_t));
    __uint(value_size, sizeof(struct mmap_info_t));
    __uint(max_entries, 1000000);
} mmap_allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct py_stack));
    __uint(max_entries, 100000);
} py_stack_cached SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct brk_info_t));
    __uint(max_entries, 1000);
} sys_brk_match SEC(".maps");

static __always_inline u64 get_real_start_time()
{
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (task) {
        struct task_struct* group_leader = _(task->group_leader);
        if (group_leader) {
            if (bpf_core_field_exists(((struct task_struct *)0)->start_boottime)) {
                return _(group_leader->start_boottime);
            }
            if (bpf_core_field_exists(((struct task_struct *)0)->real_start_time)) {
                return _(group_leader->real_start_time);
            }
        }
    }
    return 0;
}


static __always_inline char is_proc_traced(u32 tgid)
{
    struct proc_s obj = {.proc_id = tgid};
    return is_proc_exist(&obj);
}

static __always_inline char is_stackmap_a() {
    const u32 zero = 0;
    struct convert_data_t *convert_data = (struct convert_data_t *)bpf_map_lookup_elem(&convert_map, &zero);
    if (!convert_data) {
        return -1;
    }

    // Obtains the data channel used to collect stack-trace data.
    char ret = ((convert_data->convert_counter % 2) == 0);

    return ret;
}

static __always_inline int get_stack_id(void *ctx, char stackmap_cur, struct stack_id_s *stack_id) {
    stack_id->pid.proc_id = bpf_get_current_pid_tgid() >> INT_LEN;
    stack_id->pid.real_start_time = get_real_start_time();
    (void)bpf_get_current_comm(&stack_id->comm, sizeof(stack_id->comm));
    stack_id->py_stack = 0;

    if (stackmap_cur) {
        stack_id->kern_stack_id = bpf_get_stackid(ctx, &stackmap_a, KERN_STACKID_FLAGS);
        stack_id->user_stack_id = bpf_get_stackid(ctx, &stackmap_a, USER_STACKID_FLAGS);
    } else {
        stack_id->kern_stack_id = bpf_get_stackid(ctx, &stackmap_b, KERN_STACKID_FLAGS);
        stack_id->user_stack_id = bpf_get_stackid(ctx, &stackmap_b, USER_STACKID_FLAGS);
    }

    if (stack_id->kern_stack_id < 0 && stack_id->user_stack_id < 0) {
        // error.
        return -1;
    }

    return 0;
}

static __always_inline int get_py_stack_id(u32 tgid, u64 *py_stack_id)
{
    struct py_proc_data *py_proc_data;
    struct py_sample *py_sample;

    py_proc_data = (struct py_proc_data *)bpf_map_lookup_elem(&py_proc_map, &tgid);
    if (!py_proc_data) {
        return -1;
    }
    py_sample = get_py_sample();
    if (!py_sample) {
        return -1;
    }

    py_sample->cpu_id = bpf_get_smp_processor_id();
    if (get_py_stack(py_sample, py_proc_data)) {
        return -1;
    }

    *py_stack_id = py_sample->py_stack_counter * py_sample->nr_cpus + py_sample->cpu_id;
    if (bpf_map_update_elem(&py_stack_cached, py_stack_id, &py_sample->event.py_stack, BPF_ANY)) {
        *py_stack_id = 0;
        return -1;
    }
    py_sample->py_stack_counter++;
    return 0;
}

static __always_inline struct py_raw_trace_s *get_py_raw_trace_from_cache(
    struct raw_trace_s *raw_trace, u64 py_stack_id)
{
    struct py_sample *py_sample;
    struct py_stack *py_stack;

    py_sample = get_py_sample();
    if (!py_sample) {
        return 0;
    }
    py_stack = (struct py_stack *)bpf_map_lookup_elem(&py_stack_cached, &py_stack_id);
    if (!py_stack) {
        return 0;
    }

    __builtin_memcpy(&py_sample->event.raw_trace, raw_trace, sizeof(struct raw_trace_s));
    __builtin_memcpy(&py_sample->event.py_stack, py_stack, sizeof(struct py_stack));
    return &py_sample->event;
}
static __always_inline void update_statistics(void *ctx, char stackmap_cur, s64 count, struct mmap_info_t *mmap_info) {
    struct raw_trace_s raw_trace = {
        .count = count,
        .lang_type = mmap_info->lang_type
    };
    struct py_raw_trace_s *py_trace;
    void *event = (void *)&raw_trace;
    size_t event_size = sizeof(struct raw_trace_s);

    bpf_probe_read(&raw_trace.stack_id, sizeof(raw_trace.stack_id), &mmap_info->stack_id);
    if (mmap_info->lang_type == TRACE_LANG_TYPE_PYTHON) {
        py_trace = get_py_raw_trace_from_cache(&raw_trace, mmap_info->py_stack_id);
        if (!py_trace) {
            return;
        }
        event = (void *)py_trace;
        event_size = sizeof(struct py_raw_trace_s);
    }

    if (stackmap_cur) {
        (void)bpfbuf_output(ctx, &stackmap_perf_a, event, event_size);
    } else {
        (void)bpfbuf_output(ctx, &stackmap_perf_b, event, event_size);
    }
}

static __always_inline void alloc_exit(void *ctx, u64 addr) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> INT_LEN;
    struct pid_addr_t pa = {0};
    pa.tgid = tgid;
    pa.addr = addr;
    u64 *alloc_size_ptr;
    u64 alloc_size;
    struct mmap_info_t mmap_info = {0};
    char stackmap_cur;

    alloc_size_ptr = (u64 *)bpf_map_lookup_elem(&to_allocate, &pid_tgid);
    if (!alloc_size_ptr) {
        return;
    }
    alloc_size = *alloc_size_ptr;
    bpf_map_delete_elem(&to_allocate, &pid_tgid);

    if (addr != 0) {
        mmap_info.lang_type = TRACE_LANG_TYPE_DEFAULT;
        stackmap_cur = is_stackmap_a();
        if (get_stack_id(ctx, stackmap_cur, &mmap_info.stack_id) != 0) {
            return;
        }
        if (get_py_stack_id(pa.tgid, &mmap_info.py_stack_id) == 0) {
            mmap_info.lang_type = TRACE_LANG_TYPE_PYTHON;
        }

        mmap_info.timestamp_ns = bpf_ktime_get_ns();
        mmap_info.size = (s64)alloc_size;
        bpf_map_update_elem(&mmap_allocs, &pa, &mmap_info, BPF_ANY);
        update_statistics(ctx, stackmap_cur, mmap_info.size, &mmap_info);
    }

    return;
}

static __always_inline void alloc_enter(u64 size) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> INT_LEN;

    if (is_proc_traced(tgid)) {
        bpf_map_update_elem(&to_allocate, &pid_tgid, &size, BPF_ANY);
    }
}

static __always_inline void free_enter(void *ctx, u64 addr) {
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    struct pid_addr_t pa = {0};
    pa.tgid = tgid;
    pa.addr = addr;
    char stackmap_cur;
    struct mmap_info_t *mmap_info = (struct mmap_info_t *)bpf_map_lookup_elem(&mmap_allocs, &pa);
    if (mmap_info == 0)
        return;

    stackmap_cur = is_stackmap_a();
    update_statistics(ctx, stackmap_cur, -mmap_info->size, mmap_info);
    if (mmap_info->lang_type == TRACE_LANG_TYPE_PYTHON) {
        bpf_map_delete_elem(&py_stack_cached, &mmap_info->py_stack_id);
    }
    bpf_map_delete_elem(&mmap_allocs, &pa);
    return;
}

static __always_inline void process_sys_exit_brk(struct brk_info_t *brk_info, void *ctx)
{
    struct raw_trace_s raw_trace = {0};
    struct py_raw_trace_s *py_trace;
    char stackmap_cur;

    stackmap_cur = is_stackmap_a();
    raw_trace.lang_type = TRACE_LANG_TYPE_DEFAULT;
    raw_trace.count = (s64)brk_info->new_brk - (s64)brk_info->old_brk;
    if (raw_trace.count <= 0) {
        return;
    }
    if (get_stack_id(ctx, stackmap_cur, &raw_trace.stack_id) != 0) {
        return;
    }

    py_trace = get_py_raw_trace(&raw_trace);
    if (py_trace) {
        if (stackmap_cur) {
            (void)bpfbuf_output(ctx, &stackmap_perf_a, py_trace, sizeof(struct py_raw_trace_s));
        } else {
            (void)bpfbuf_output(ctx, &stackmap_perf_b, py_trace, sizeof(struct py_raw_trace_s));
        }
        return;
    }

    if (stackmap_cur) {
        (void)bpfbuf_output(ctx, &stackmap_perf_a, &raw_trace, sizeof(raw_trace));
    } else {
        (void)bpfbuf_output(ctx, &stackmap_perf_b, &raw_trace, sizeof(raw_trace));
    }
}

// MEM_SEC_NUM is the num of bpf_section

bpf_section("tracepoint/syscalls/sys_enter_brk")
int function_sys_enter_brk(struct sys_enter_brk_args *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> INT_LEN;
    struct brk_info_t brk_info;
    struct task_struct *task;

    if (!is_proc_traced(tgid)) {
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();
    brk_info.old_brk = (u64)BPF_CORE_READ(task, mm, brk);
    brk_info.new_brk = (u64)ctx->brk;
    bpf_map_update_elem(&sys_brk_match, &pid_tgid, &brk_info, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_brk")
int function_sys_exit_brk(struct sys_exit_brk_args *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct brk_info_t *brk_info = (struct brk_info_t *)bpf_map_lookup_elem(&sys_brk_match, &pid_tgid);

    if (!brk_info) {
        return 0;
    }
    if (ctx->ret == brk_info->new_brk) {
        process_sys_exit_brk(brk_info, (void *)ctx);
    }
    bpf_map_delete_elem(&sys_brk_match, &pid_tgid);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_enter_mmap")
int function_sys_enter_mmap(struct sys_enter_mmap_args *ctx)
{
    alloc_enter((u64)ctx->len);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_mmap")
int function_sys_exit_mmap(struct sys_exit_mmap_args *ctx)
{
    alloc_exit(ctx, (u64)ctx->ret);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_enter_munmap")
int function_sys_enter_munmap_args(struct sys_enter_munmap_args *ctx)
{
    free_enter(ctx, (u64)ctx->addr);
    return 0;
}
