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
 * Description: glibc bpf
 ******************************************************************************/
#ifndef __GLIBC_BPF_H__
#define __GLIBC_BPF_H__

#pragma once

#include "common.h"

struct dns_cache_s {
    u32 proc_id;
    int error;
    u64 start_ts;
    u64 end_ts;
    char domain[DOMAIN_LEN];
};


#endif
