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

#ifndef __STACK_PROBE_BPF_H__
#define __STACK_PROBE_BPF_H__

#pragma once

#ifndef BPF_F_FAST_STACK_CMP
#define BPF_F_FAST_STACK_CMP    (1ULL << 9)
#endif

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK    (1ULL << 8)
#endif

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

/*
  To ensure that BPF continuously collects stack-trace data, BPF provides two data channels (A/B).
  One data channel is used to collect stack-trace data, and the other is used to read stack-trace data in user mode.
  Two data channel periodically alternate roles.
*/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32)); // const value 0
    __uint(value_size, sizeof(struct convert_data_t));
    __uint(max_entries, 1);
} convert_map SEC(".maps");

/* Data channel A */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, MAX_PERCPU_SAMPLE_COUNT);
} stackmap_a SEC(".maps");


/* Data channel B */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, MAX_PERCPU_SAMPLE_COUNT);
} stackmap_b SEC(".maps");


#endif
