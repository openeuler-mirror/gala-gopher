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
 * Create: 2022-06-28
 * Description: task map defined
 ******************************************************************************/
#ifndef __TASK_MAP_H__
#define __TASK_MAP_H__

#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vmlinux.h"
#include "thread.h"

#define __TASK_MAX      1000
struct bpf_map_def SEC("maps") g_task_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(struct task_data),
    .max_entries = __TASK_MAX,
};

static __always_inline __maybe_unused struct task_data* get_task(int pid)
{
    return (struct task_data *)bpf_map_lookup_elem(&g_task_map, &pid);
}

static __always_inline __maybe_unused int task_add(int pid, struct task_data *data)
{
    return bpf_map_update_elem(&g_task_map, &pid, data, BPF_ANY);
}

static __always_inline __maybe_unused int task_put(int pid)
{
    return bpf_map_delete_elem(&g_task_map, &pid);
}


#endif
