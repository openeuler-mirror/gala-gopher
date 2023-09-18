/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2023-02-22
 * Description: l7 probe filter
 ******************************************************************************/

#ifndef __L7PROBE_FILTER_H__
#define __L7PROBE_FILTER_H__

#pragma once
#include "args.h"

enum filter_type_t {
    FILTER_TGID = 0,
    FILTER_CGRPID,
};

struct filter_args_s {
    char is_tracing;            // Support for L7 protocol tracing
    char is_support_ssl;        // Support for libSSL or GoSSL
    char is_report_telm;        // Report telemetry metrics data.
    char is_report_raw;         // Report raw metrics data.
    char is_report_res;         // Report pod/container resource data(eg. network tx/rx, vm/rss, i/o rd/wr).
    char is_filter_by_cgrp;     // Support for filter by cgroup of pod/container
    char pad[2];
    u32 proto_flags;
};

#endif
