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
 * Create: 2023-06-28
 * Description: open telemetry histogram calculation
 ******************************************************************************/
#ifndef __GOPHER_HISTOGRAM_H__
#define __GOPHER_HISTOGRAM_H__

#pragma once

#include "common.h"

enum histo_type_t {
    HISTO_P50,
    HISTO_P90,
    HISTO_P99
};

struct histo_bucket_s {
    u64 min, max;
    u64 count;
};

int init_histo_bucket(struct histo_bucket_s *bucket, u64 min, u64 max);
int histo_bucket_add_value(struct histo_bucket_s bucket[], size_t bucket_size, u64 value);
int histo_bucket_value(struct histo_bucket_s bucket[], size_t bucket_size, enum histo_type_t type, float *value);
void histo_bucket_reset(struct histo_bucket_s bucket[], size_t bucket_size);

#endif

