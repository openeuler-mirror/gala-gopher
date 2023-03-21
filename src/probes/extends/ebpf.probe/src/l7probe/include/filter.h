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

enum filter_type_t {
    FILTER_TGID = 0,
    FILTER_CGRPID,
};

struct filter_id_s {
    enum filter_type_t filter_type;
    int filter_id;
};

// Used to define 'proto_flags'
#define L7PROBE_TRACING_HTTP    0x0001
#define L7PROBE_TRACING_DNS     0x0002
#define L7PROBE_TRACING_REDIS   0x0004
#define L7PROBE_TRACING_MYSQL   0x0008
#define L7PROBE_TRACING_PGSQL   0x0010
#define L7PROBE_TRACING_KAFKA   0x0012
#define L7PROBE_TRACING_MONGO   0x0014
#define L7PROBE_TRACING_CQL     0x0018
#define L7PROBE_TRACING_NATS    0x0020

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
