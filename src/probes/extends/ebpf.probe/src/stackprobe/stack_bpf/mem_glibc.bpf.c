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
 * Create: 2022-11-26
 * Description: mem stack tracing based on glibc function
 ******************************************************************************/
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#define BPF_PROG_USER
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
    __uint(key_size, sizeof(u64));  // pid
    __uint(value_size, sizeof(u64));  // size
    __uint(max_entries, 1000);
} to_allocate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64)); // pid
    __uint(value_size, sizeof(u64)); // size
    __uint(max_entries, 10000);
} memalign_allocate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct pid_addr_t));
    __uint(value_size, sizeof(struct mmap_info_t));
    __uint(max_entries, 10000);
} allocs SEC(".maps");

static __always_inline char is_stackmap_a(void)
{
    const u32 zero = 0;
    struct convert_data_t *convert_data = (struct convert_data_t *)bpf_map_lookup_elem(&convert_map, &zero);
    if (!convert_data) {
        return -1;
    }

    // Obtains the data channel used to collect stack-trace data.
    char ret = ((convert_data->convert_counter % 2) == 0);

    return ret;
}

static __always_inline int get_stack_id(struct pt_regs *ctx, char stackmap_cur, struct stack_id_s *stack_id)
{
    stack_id->pid.proc_id = bpf_get_current_pid_tgid() >> INT_LEN;
    stack_id->pid.real_start_time = 0;
    (void)bpf_get_current_comm(&stack_id->comm, sizeof(stack_id->comm));

    if (stackmap_cur) {
        stack_id->kern_stack_id = bpf_get_stackid(ctx, &stackmap_a, KERN_STACKID_FLAGS);
        stack_id->user_stack_id = bpf_get_stackid(ctx, &stackmap_a, USER_STACKID_FLAGS);
    } else {
        stack_id->kern_stack_id = bpf_get_stackid(ctx, &stackmap_b, KERN_STACKID_FLAGS);
        stack_id->user_stack_id = bpf_get_stackid(ctx, &stackmap_b, USER_STACKID_FLAGS);
    }

    if (stack_id->kern_stack_id < 0 && stack_id->user_stack_id < 0) {
        return -1;
    }

    return 0;
}

static __always_inline void update_statistics(struct pt_regs *ctx, char stackmap_cur, s64 count,
                                              struct stack_id_s stack_id)
{
    struct raw_trace_s raw_trace = {
        .count = count,
        .stack_id = stack_id
    };

    if (stackmap_cur) {
        (void)bpfbuf_output(ctx, &stackmap_perf_a, &raw_trace, sizeof(raw_trace));
    } else {
        (void)bpfbuf_output(ctx, &stackmap_perf_b, &raw_trace, sizeof(raw_trace));
    }
}

static __always_inline int alloc_exit(struct pt_regs *ctx, u64 addr)
{
    u64 pid = bpf_get_current_pid_tgid();
    struct pid_addr_t pa = {0};
    pa.tgid = pid >> INT_LEN;
    pa.addr = addr;
    u64 *alloc_size = (u64 *)bpf_map_lookup_elem(&to_allocate, &pid);
    struct mmap_info_t mmap_info = {0};

    if (alloc_size == 0)
        return 0;

    bpf_map_delete_elem(&to_allocate, &pid);

    if (addr != 0) {
        char stackmap_cur = is_stackmap_a();
        if (get_stack_id(ctx, stackmap_cur, &mmap_info.stack_id) != 0) {
            return 0;
        }

        mmap_info.timestamp_ns = bpf_ktime_get_ns();
        mmap_info.size = (s64)*alloc_size;
        bpf_map_update_elem(&allocs, &pa, &mmap_info, BPF_ANY);
        update_statistics(ctx, stackmap_cur, mmap_info.size, mmap_info.stack_id);
    }

    return 0;
}

static __always_inline int alloc_enter(u64 size)
{
    u64 pid = bpf_get_current_pid_tgid();
    u32 tgid = pid >> INT_LEN;
    if (tgid > 1) {
        const u32 zero = 0;
        struct convert_data_t *convert_data = (struct convert_data_t *)bpf_map_lookup_elem(&convert_map, &zero);
        if (!convert_data) {
            return -1;
        }
        if (convert_data->whitelist_enable) {
            struct proc_s obj = {.proc_id = tgid};
            if (!is_proc_exist(&obj)) {
                return 0;
            }
        }
    }
    bpf_map_update_elem(&to_allocate, &pid, &size, BPF_ANY);

    return 0;
}

static __always_inline int free_enter(struct pt_regs *ctx, u64 addr)
{
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    struct pid_addr_t pa = {0};
    pa.tgid = tgid;
    pa.addr = addr;
    struct mmap_info_t *mmap_info = (struct mmap_info_t *)bpf_map_lookup_elem(&allocs, &pa);
    if (mmap_info == 0) {
        return 0;
    }

    bpf_map_delete_elem(&allocs, &pa);

    char stackmap_cur = is_stackmap_a();
    update_statistics(ctx, stackmap_cur, -mmap_info->size, mmap_info->stack_id);
    return 0;
}

UPROBE(malloc, pt_regs)
{
    u64 size = (u64)PT_REGS_PARM1(ctx);
    alloc_enter(size);
    return 0;
}

URETPROBE(malloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(calloc, pt_regs)
{
    u64 nmemb = (u64)PT_REGS_PARM1(ctx);
    u64 size = (u64)PT_REGS_PARM2(ctx);
    alloc_enter(nmemb * size);
    return 0;
}

URETPROBE(calloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(realloc, pt_regs)
{
    u64 ptr = (u64)PT_REGS_PARM1(ctx);
    u64 size = (u64)PT_REGS_PARM2(ctx);

    free_enter(ctx, ptr);
    alloc_enter(size);
    return 0;
}

URETPROBE(realloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(mmap, pt_regs)
{
    u64 size = (u64)PT_REGS_PARM2(ctx);
    alloc_enter(size);
    return 0;
}

URETPROBE(mmap, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(posix_memalign, pt_regs)
{
    u64 memptr = (u64)PT_REGS_PARM1(ctx);
    u64 size = (u64)PT_REGS_PARM2(ctx);
    u64 pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&memalign_allocate, &pid, &memptr, BPF_ANY);
    alloc_enter(size);
    return 0;
}

URETPROBE(posix_memalign, pt_regs)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 addr;
    u64 *memptr = (u64 *)bpf_map_lookup_elem(&memalign_allocate, &pid);
    if (memptr == 0)
        return 0;
    bpf_map_delete_elem(&memalign_allocate, &pid);

    if (bpf_core_read_user(&addr, sizeof(u64), &memptr))
        return 0;

    alloc_exit(ctx, addr);
    return 0;
}

UPROBE(valloc, pt_regs)
{
    u64 size = (u64)PT_REGS_PARM1(ctx);
    alloc_enter(size);
    return 0;
}

URETPROBE(valloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(memalign, pt_regs)
{
    u64 size = (u64)PT_REGS_PARM1(ctx);
    alloc_enter(size);
    return 0;
}

URETPROBE(memalign, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(pvalloc, pt_regs)
{
    u64 size = (u64)PT_REGS_PARM1(ctx);
    alloc_enter(size);
    return 0;
}

URETPROBE(pvalloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(aligned_alloc, pt_regs)
{
    u64 size = (u64)PT_REGS_PARM2(ctx);
    alloc_enter(size);
    return 0;
}

URETPROBE(aligned_alloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(free, pt_regs)
{
    u64 size = (u64)PT_REGS_PARM2(ctx);
    free_enter(ctx, size);
    return 0;
}

UPROBE(munmap, pt_regs)
{
    u64 size = (u64)PT_REGS_PARM1(ctx);
    free_enter(ctx, size);
    return 0;
}

