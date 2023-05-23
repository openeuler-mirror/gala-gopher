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
 * Author: luzhihao
 * Create: 2022-07-13
 * Description: proc map defined
 ******************************************************************************/
#ifndef __PROC_MAP_H__
#define __PROC_MAP_H__

#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "proc.h"

#define __PROC_MAX      1000
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));  // proc id
    __uint(value_size, sizeof(struct proc_data_s));
    __uint(max_entries, __PROC_MAX);
} g_proc_map SEC(".maps");


static __always_inline __maybe_unused struct proc_data_s* get_proc_entry(u32 proc_id)
{
    return (struct proc_data_s *)bpf_map_lookup_elem(&g_proc_map, &proc_id);
}

#endif
