/*
 * bpf code runs in the Linux kernel
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#define BPF_PROG_USER
#include "bpf.h"
#include "tprofiling.h"

struct pid_addr_t {
    u32 tgid;
    u64 addr;
};

struct mmap_info_t {
    s64 size;
    u64 ts;
};

// memory to be allocated for the process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));  // pid
    __uint(value_size, sizeof(u64));  // size
    __uint(max_entries, 1000);
} to_allocate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct pid_addr_t));
    __uint(value_size, sizeof(struct mmap_info_t));
    __uint(max_entries, 10000);
} allocs SEC(".maps");

static __always_inline void emit_alloc_event(struct pt_regs *ctx, u64 addr, s64 size, u32 tgid)
{
    trace_event_data_t evt_data = {0};
    struct pid_addr_t pa = {0};
    struct mmap_info_t mmap_info = {0};
    void *cur_event_map;

    init_trace_event_common(&evt_data, EVT_TYPE_MEM_GLIBC);
    evt_data.mem_glibc_d.addr = addr;
    evt_data.mem_glibc_d.size = size;
    evt_data.mem_glibc_d.ts = bpf_ktime_get_ns();
    if (stats_append_stack(&evt_data.mem_glibc_d.stats_stack, 0, ctx)) {    // 调用栈获取失败时，不上报内存申请事件
        return;
    }

    cur_event_map = bpf_get_current_event_map();
    if (cur_event_map) {
        if (bpfbuf_output(ctx, cur_event_map, &evt_data, sizeof(evt_data)) < 0) {
            return;
        }

        pa.tgid = tgid;
        pa.addr = addr;
        mmap_info.size = size;
        mmap_info.ts = evt_data.mem_glibc_d.ts;
        (void)bpf_map_update_elem(&allocs, &pa, &mmap_info, BPF_ANY);
    }
}

static __always_inline void alloc_exit(struct pt_regs *ctx, u64 addr)
{
    u64 ptid = bpf_get_current_pid_tgid();
    u64 *alloc_size;

    alloc_size = (u64 *)bpf_map_lookup_elem(&to_allocate, &ptid);
    if (alloc_size == NULL) {
        return;
    }

    if (addr != 0) {
        emit_alloc_event(ctx, addr, (s64)*alloc_size, (u32)(ptid >> INT_LEN));
    }

    bpf_map_delete_elem(&to_allocate, &ptid);
}

static __always_inline void alloc_enter(u64 size)
{
    u64 ptid = bpf_get_current_pid_tgid();
    u32 tgid = ptid >> INT_LEN;

    if (size == 0) {
        return;
    }

    if (is_proc_enabled(tgid)) {
        bpf_map_update_elem(&to_allocate, &ptid, &size, BPF_ANY);
    }
}

static __always_inline void emit_free_event(struct pt_regs *ctx, u64 addr, struct mmap_info_t *mmap_info)
{
    trace_event_data_t evt_data = {0};
    void *cur_event_map;

    init_trace_event_common(&evt_data, EVT_TYPE_MEM_GLIBC);
    evt_data.mem_glibc_d.addr = addr;
    evt_data.mem_glibc_d.size = -mmap_info->size;
    evt_data.mem_glibc_d.ts = mmap_info->ts;

    cur_event_map = bpf_get_current_event_map();
    if (cur_event_map) {
        (void)bpfbuf_output(ctx, cur_event_map, &evt_data, sizeof(evt_data));
    }
}

static __always_inline void free_enter(struct pt_regs *ctx, u64 addr)
{
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    struct pid_addr_t pa = {0};
    struct mmap_info_t *mmap_info;

    pa.tgid = tgid;
    pa.addr = addr;
    mmap_info = (struct mmap_info_t *)bpf_map_lookup_elem(&allocs, &pa);
    if (mmap_info == NULL) {
        return;
    }

    emit_free_event(ctx, addr, mmap_info);

    bpf_map_delete_elem(&allocs, &pa);
}

UPROBE(PyMem_RawMalloc, pt_regs)
{
    u64 size = (u64)PT_REGS_PARM1(ctx);
    alloc_enter(size);
    return 0;
}

URETPROBE(PyMem_RawMalloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(PyMem_RawCalloc, pt_regs)
{
    u64 nmemb = (u64)PT_REGS_PARM1(ctx);
    u64 size = (u64)PT_REGS_PARM2(ctx);
    alloc_enter(nmemb * size);
    return 0;
}

URETPROBE(PyMem_RawCalloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(PyMem_RawRealloc, pt_regs)
{
    u64 ptr = (u64)PT_REGS_PARM1(ctx);
    u64 size = (u64)PT_REGS_PARM2(ctx);

    free_enter(ctx, ptr);
    alloc_enter(size);
    return 0;
}

URETPROBE(PyMem_RawRealloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(PyMem_Malloc, pt_regs)
{
    u64 size = (u64)PT_REGS_PARM1(ctx);
    alloc_enter(size);
    return 0;
}

URETPROBE(PyMem_Malloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(PyMem_Calloc, pt_regs)
{
    u64 nmemb = (u64)PT_REGS_PARM1(ctx);
    u64 size = (u64)PT_REGS_PARM2(ctx);
    alloc_enter(nmemb * size);
    return 0;
}

URETPROBE(PyMem_Calloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(PyMem_Realloc, pt_regs)
{
    u64 ptr = (u64)PT_REGS_PARM1(ctx);
    u64 size = (u64)PT_REGS_PARM2(ctx);

    free_enter(ctx, ptr);
    alloc_enter(size);
    return 0;
}

URETPROBE(PyMem_Realloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(PyObject_Malloc, pt_regs)
{
    u64 size = (u64)PT_REGS_PARM1(ctx);
    alloc_enter(size);
    return 0;
}

URETPROBE(PyObject_Malloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(PyObject_Calloc, pt_regs)
{
    u64 nmemb = (u64)PT_REGS_PARM1(ctx);
    u64 size = (u64)PT_REGS_PARM2(ctx);
    alloc_enter(nmemb * size);
    return 0;
}

URETPROBE(PyObject_Calloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(PyObject_Realloc, pt_regs)
{
    u64 ptr = (u64)PT_REGS_PARM1(ctx);
    u64 size = (u64)PT_REGS_PARM2(ctx);

    free_enter(ctx, ptr);
    alloc_enter(size);
    return 0;
}

URETPROBE(PyObject_Realloc, pt_regs)
{
    u64 ret = (u64)PT_REGS_RC(ctx);
    alloc_exit(ctx, ret);
    return 0;
}

UPROBE(PyMem_RawFree, pt_regs)
{
    u64 ptr = (u64)PT_REGS_PARM1(ctx);
    free_enter(ctx, ptr);
    return 0;
}

UPROBE(PyMem_Free, pt_regs)
{
    u64 ptr = (u64)PT_REGS_PARM1(ctx);
    free_enter(ctx, ptr);
    return 0;
}

UPROBE(PyObject_Free, pt_regs)
{
    u64 ptr = (u64)PT_REGS_PARM1(ctx);
    free_enter(ctx, ptr);
    return 0;
}

char g_license[] SEC("license") = "GPL";