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
 * Create: 2022-08-18
 * Description: stack defined
 ******************************************************************************/
#ifndef __STACK_PROBE_BPF_H__
#define __STACK_PROBE_BPF_H__

#pragma once

#ifndef BPF_F_FAST_STACK_CMP
#define BPF_F_FAST_STACK_CMP    (1ULL << 9)
#endif

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK    (1ULL << 8)
#endif

#ifndef BPF_F_INDEX_MASK
#define BPF_F_INDEX_MASK        0xffffffffULL
#endif

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU       BPF_F_INDEX_MASK
#endif

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

/*
  To ensure that BPF continuously collects stack-trace data, BPF provides two data channels (A/B).
  One data channel is used to collect stack-trace data, and the other is used to read stack-trace data in user mode.
  Two data channel periodically alternate roles.
*/

struct bpf_map_def SEC("maps") convert_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),    // const value 0
    .value_size = sizeof(struct convert_data_t),
    .max_entries = 1,
};

/* Data channel A */
struct bpf_map_def SEC("maps") stackmap_a = {
    .type = BPF_MAP_TYPE_STACK_TRACE,
    .key_size = sizeof(u32),
    .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
    .max_entries = PERCPU_SAMPLE_COUNT,
};

/* Data channel B */
struct bpf_map_def SEC("maps") stackmap_b = {
    .type = BPF_MAP_TYPE_STACK_TRACE,
    .key_size = sizeof(u32),
    .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
    .max_entries = PERCPU_SAMPLE_COUNT,
};


#endif
