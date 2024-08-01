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

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN

#include "bpf.h"
#include "feat_probe.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct feature_probe));
    __uint(max_entries, 1);
} feature_map SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_nanosleep")
int probe_features(void *ctx)
{
    u32 key = 0;
    struct feature_probe *probe = bpf_map_lookup_elem(&feature_map, &key);
    if (probe == NULL) {
        return 0;
    }
    probe->is_tstamp_enabled = (int)probe_tstamp();
    probe->is_probed = 1;
    return 0;
}
