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
 * Create: 2024-10-09
 * Description: Python GC bpf
 ******************************************************************************/
#ifndef __GLIBC_BPF_H__
#define __GLIBC_BPF_H__

#pragma once

#include "common.h"

typedef u64 context_id;
#define GC_1MS  (u64)(1 * 1000 * 1000)
struct pygc_evt_s {
    u64 start_time;
    u64 end_time;
    context_id id;
};

#endif
