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
 * Author: Mr.lu
 * Create: 2022-06-16
 * Description: object map defined
 ******************************************************************************/
#ifndef __OBJ_MAP_H__
#define __OBJ_MAP_H__

#if defined( BPF_PROG_KERN ) || defined( BPF_PROG_USER )

#ifdef BPF_PROG_USER
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#endif

#ifdef BPF_PROG_KERN

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#endif

#include "bpf.h"
#include "object.h"

/* !!! NOTICE
 * The 'cgrp_obj_map' and 'nm_obj_map' MAP object can be read in the kernel,
 * and read and write operations in user mode.
 * MUST NOT BE perform write operations in kernel mode.
*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct cgroup_s));
    __uint(value_size, sizeof(struct obj_ref_s));
    __uint(max_entries, CGRP_MAP_MAX_ENTRIES);
} cgrp_obj_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct nm_s));
    __uint(value_size, sizeof(struct obj_ref_s));
    __uint(max_entries, NM_MAP_MAX_ENTRIES);
} nm_obj_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct proc_s));
    __uint(value_size, sizeof(struct obj_ref_s));
    __uint(max_entries, PROC_MAP_MAX_ENTRIES);
} proc_obj_map SEC(".maps");

static __always_inline __maybe_unused char is_cgrp_exist(struct cgroup_s *obj)
{
    if (bpf_map_lookup_elem(&cgrp_obj_map, obj) == (void *)0) {
        return 0;
    }
    return 1;
}

static __always_inline __maybe_unused char is_nm_exist(struct nm_s *obj)
{
    if (bpf_map_lookup_elem(&nm_obj_map, obj) == (void *)0) {
        return 0;
    }
    return 1;
}

static __always_inline __maybe_unused char is_proc_exist(struct proc_s *obj)
{
    if (bpf_map_lookup_elem(&proc_obj_map, obj) == (void *)0) {
        return 0;
    }
    return 1;
}

static __always_inline __maybe_unused int proc_add(struct proc_s *obj)
{
    struct obj_ref_s ref = {.count = 1};
    return bpf_map_update_elem(&proc_obj_map, obj, &ref, BPF_ANY);
}

static __always_inline __maybe_unused int proc_put(struct proc_s *obj)
{
    struct obj_ref_s *ref;

    ref = bpf_map_lookup_elem(&proc_obj_map, obj);
    if (ref == (void *)0) {
        return 0;
    }

    if (ref->count > 0) {
        __sync_fetch_and_sub(&ref->count, 1);
    }

    if (ref->count == 0) {
        return bpf_map_delete_elem(&proc_obj_map, obj);
    }
    return 0;
}

#endif

#endif
