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
 * Description: fp-based memleak stack tracing
 *     If user lib does not contain fp pointer, this program cannot track it.
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "../stack.h"
#include "stackprobe_bpf.h"

char g_linsence[] SEC("license") = "GPL";

struct pid_addr_t {
    u32 tgid;
    u64 addr;
};

struct mmap_info_t {
    s64 size;
    u64 timestamp_ns;
    struct stack_id_s stack_id;
};

struct brk_info_t {
    u64 addr;
    struct stack_id_s stack_id;
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
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, MAX_CPU);
} stackmap_perf_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, MAX_CPU);
} stackmap_perf_b SEC(".maps");

// memory to be allocated for the process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));  // tgid
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
    __uint(key_size, sizeof(u32)); // tgid
    __uint(value_size, sizeof(struct brk_info_t));
    __uint(max_entries, 1000000);
} brk_allocs SEC(".maps");

static __always_inline u64 get_real_start_time()
{
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (task) {
        struct task_struct* group_leader = _(task->group_leader);
        if (group_leader) {
#if (CURRENT_KERNEL_VERSION >= KERNEL_VERSION(5, 10, 0))
        return _(group_leader->start_boottime);
#else
        return _(group_leader->real_start_time);
#endif
        }
    }
    return 0;
}

static inline char is_stackmap_a() {
    const u32 zero = 0;
    struct convert_data_t *convert_data = (struct convert_data_t *)bpf_map_lookup_elem(&convert_map, &zero);
    if (!convert_data) {
        return -1;
    }

    // Obtains the data channel used to collect stack-trace data.
    char ret = ((convert_data->convert_counter % 2) == 0);

    return ret;
}
static inline int get_stack_id(void *ctx, char stackmap_cur, struct stack_id_s *stack_id) {
    stack_id->pid.proc_id = bpf_get_current_pid_tgid() >> INT_LEN;
    stack_id->pid.real_start_time = get_real_start_time();
    (void)bpf_get_current_comm(&stack_id->comm, sizeof(stack_id->comm));

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

static inline void update_statistics(void *ctx, char stackmap_cur, s64 count, struct stack_id_s stack_id) {
    struct raw_trace_s raw_trace = {
        .count = count,
        .stack_id = stack_id
    };

    if (stackmap_cur) {
        (void)bpf_perf_event_output(ctx, &stackmap_perf_a, BPF_F_CURRENT_CPU, &raw_trace, sizeof(raw_trace));
    } else {
        (void)bpf_perf_event_output(ctx, &stackmap_perf_b, BPF_F_CURRENT_CPU, &raw_trace, sizeof(raw_trace));
    }
}

static inline int alloc_exit(void *ctx, u64 addr) {
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    struct pid_addr_t pa = {0};
    pa.tgid = tgid;
    pa.addr = addr;
    u64 *alloc_size = (u64 *)bpf_map_lookup_elem(&to_allocate, &tgid);
    struct mmap_info_t mmap_info = {0};

    if (alloc_size == 0)
        return 0;

    bpf_map_delete_elem(&to_allocate, &tgid);

    if (addr != 0) {
        char stackmap_cur = is_stackmap_a();
        if (get_stack_id(ctx, stackmap_cur, &mmap_info.stack_id) != 0) {
            return 0;
        }

        mmap_info.timestamp_ns = bpf_ktime_get_ns();
        mmap_info.size = (s64)*alloc_size;
        bpf_map_update_elem(&mmap_allocs, &pa, &mmap_info, BPF_ANY);
        update_statistics(ctx, stackmap_cur, mmap_info.size, mmap_info.stack_id);
    }

    return 0;
}

static inline int alloc_enter(u64 size) {
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    bpf_map_update_elem(&to_allocate, &tgid, &size, BPF_ANY);

    return 0;
}

static inline int free_enter(void *ctx, u64 addr) {
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    struct pid_addr_t pa = {0};
    pa.tgid = tgid;
    pa.addr = addr;
    struct mmap_info_t *mmap_info = (struct mmap_info_t *)bpf_map_lookup_elem(&mmap_allocs, &pa);
    if (mmap_info == 0)
        return 0;

    bpf_map_delete_elem(&mmap_allocs, &pa);

    char stackmap_cur = is_stackmap_a();
    update_statistics(ctx, stackmap_cur, -mmap_info->size, mmap_info->stack_id);
    return 0;
}

// MEMLEAK_SEC_NUM is the num of bpf_section

bpf_section("tracepoint/syscalls/sys_enter_brk")
int function_sys_enter_brk(struct sys_enter_brk_args *ctx)
{
    char stackmap_cur;
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    struct brk_info_t *brk_info = (struct brk_info_t *)bpf_map_lookup_elem(&brk_allocs, &tgid);
    u64 new_brk = (u64)ctx->brk;
    if (new_brk == 0) {
        return 0;
    }
    if (brk_info == 0) {
        struct brk_info_t brk_info_new = {0};
        stackmap_cur = is_stackmap_a();
        if (get_stack_id(ctx, stackmap_cur, &brk_info_new.stack_id) != 0) {
            return 0;
        }
        brk_info_new.addr = new_brk;
        bpf_map_update_elem(&brk_allocs, &tgid, &brk_info_new, BPF_ANY);
        return 0;
    }
    
    stackmap_cur = is_stackmap_a();
    s64 count = new_brk - brk_info->addr;

    if (count > 0) {
        if (get_stack_id(ctx, stackmap_cur, &brk_info->stack_id) != 0) {
            return 0;
        }
    }
    brk_info->addr = new_brk;
    update_statistics(ctx, stackmap_cur, count, brk_info->stack_id);

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
