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
 * Author: lizhenxing
 * Create: 2022-05-30
 * Description: hardware probe args
 ******************************************************************************/

#ifndef __HW_PROBE_ARGS__H
#define __HW_PROBE_ARGS__H


#ifdef BPF_PROG_KERN

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hw.h"


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32)); // const value 0
    __uint(value_size, sizeof(struct hw_args_s));
    __uint(max_entries, 1);
} hw_args_map SEC(".maps");

#define __DEFAULT_REPORT_PERIOD (__u64)((__u64)5 * 1000000000)
static __always_inline u64 get_report_period()
{
    u32 key = 0;
    u64 period = __DEFAULT_REPORT_PERIOD;

    struct hw_args_s *args = (struct hw_args_s *)bpf_map_lookup_elem(&hw_args_map, &key);
    if (args != NULL && args->report_period != 0) {
        period = args->report_period;
    }

    return period;
}

static __always_inline char is_report_tmout(struct report_ts_s* report)
{
    u64 ts = bpf_ktime_get_ns();
    if (report->ts == 0) {
        report->ts = ts;
        return 0;
    }

    u64 report_period = get_report_period();
    if ((ts > report->ts) && ((ts - report->ts) >= report_period)) {
        report->ts = ts;
        return 1;
    }
    return 0;
}

#endif
#endif