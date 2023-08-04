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
 * Author: luzhihao
 * Create: 2023-08-02
 * Description: glibc probe
 ******************************************************************************/
#ifndef __GLIBC_PROBE_H__
#define __GLIBC_PROBE_H__

#pragma once

#include "common.h"
#include "hash.h"

struct dns_id_s {
    u32 proc_id;
    char domain[DOMAIN_LEN];
};

struct dns_entry_s {
    H_HANDLE;
    struct dns_id_s id;
    time_t last_report;
    time_t last_rcv_data;
    u64 err_count;
    u64 latency_sum;
    u64 latency_max;
    u64 dns_op_count;
    float err_ratio;
};

#endif
