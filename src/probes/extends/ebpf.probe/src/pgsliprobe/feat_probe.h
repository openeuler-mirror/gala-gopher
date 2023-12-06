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
 * Description: Kernel feature probes
 ******************************************************************************/

#ifndef __FEAT_PROBE_H
#define __FEAT_PROBE_H


struct feature_probe {
    int is_probed;
    int is_tstamp_enabled;
};

#if defined(BPF_PROG_KERN) || defined(BPF_PROG_USER)

#include <bpf/bpf_core_read.h>

#if !defined(BPF_PROG_USER)
#include "vmlinux.h"
#else
struct sk_buff {
    u64 tstamp;
};
#endif

static inline char probe_tstamp()
{
    return (char)bpf_core_field_exists(((struct sk_buff *)0)->tstamp);
}
#endif

#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
bool probe_tstamp();
#endif

#endif
