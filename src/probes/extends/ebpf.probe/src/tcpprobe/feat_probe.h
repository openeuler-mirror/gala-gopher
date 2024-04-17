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
 * Author: Yang Hanlin
 * Create: 2023-09-19
 * Description: Kernel feature probes
 ******************************************************************************/

#ifndef __FEAT_PROBE_H
#define __FEAT_PROBE_H


struct feature_probe {
    bool is_probed;
    bool is_tstamp_enabled;
};

#ifdef BPF_PROG_KERN
#include <bpf/bpf_core_read.h>

#include "vmlinux.h"

static inline bool probe_tstamp(void)
{
    return bpf_core_field_exists(((struct sk_buff *)0)->tstamp);
}
#endif

#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
bool probe_tstamp(void);
#endif

#endif
