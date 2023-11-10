/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2023-11-13
 * Description: BPF program to probe kernel features
 ******************************************************************************/

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
