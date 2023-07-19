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
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "histogram.h"

// Refer to https://zhuanlan.zhihu.com/p/608621390

static const float __histo_p50 = 0.5;
static const float __histo_p90 = 0.9;
static const float __histo_p99 = 0.99;

static u64 __get_histo_bucket_sum(struct histo_bucket_s bucket[], size_t bucket_size)
{
    u64 sum = 0;

    for (int i = 0; i < bucket_size; i++) {
        sum += bucket[i].count;
    }
    return sum;
}

static struct histo_bucket_s* __find_histo_bucket(struct histo_bucket_s bucket[], size_t bucket_size, size_t count, size_t *offset)
{
    size_t remain = count;

    for (int i = 0; i < bucket_size; i++) {
        if (remain > bucket[i].count) {
            remain = remain - bucket[i].count;
        } else {
            *offset = bucket[i].count - remain;
            return &(bucket[i]);
        }
    }
    return NULL;
}

int init_histo_bucket(struct histo_bucket_s *bucket, u64 min, u64 max)
{
    if (min >= max) {
        return -1;
    }

    bucket->min = min;
    bucket->max = max;
    bucket->count = 0;
    return 0;
}

int histo_bucket_add_value(struct histo_bucket_s bucket[], size_t bucket_size, u64 value)
{
    for (int i = 0; i < bucket_size; i++) {
        if ((value > bucket[i].min) && (value <= bucket[i].max)) {
            bucket[i].count++;
            return 0;
        }
    }
    return -1;
}

void histo_bucket_reset(struct histo_bucket_s bucket[], size_t bucket_size)
{
    for (int i = 0; i < bucket_size; i++) {
        bucket[i].count = 0;
    }
    return;
}

int histo_bucket_value(struct histo_bucket_s bucket[], size_t bucket_size, enum histo_type_t type, float *value)
{
    size_t offset = 0;
    u64 sum = __get_histo_bucket_sum(bucket, bucket_size);
    size_t histo_count;
    struct histo_bucket_s *bucket_finded;

    if (sum == 0) {
        *value = 0.0;
        return -1;
    }

    if (type == HISTO_P50) {
        histo_count = (size_t)(sum * __histo_p50);
    } else if (type == HISTO_P90) {
        histo_count = (size_t)(sum * __histo_p90);
    } else {
        histo_count = (size_t)(sum * __histo_p99);
    }

    bucket_finded = __find_histo_bucket(bucket, bucket_size, histo_count, &offset);
    if (offset == 0) {
        offset += 1;
    }

    if (bucket_finded->count == 0) {
        *value = 0.0;
        return -1;
    }

    if (bucket_finded) {
        *value = (float)(bucket_finded->max - bucket_finded->min) * ((float)offset / (float)bucket_finded->count) + (float)bucket_finded->min;
        return 0;
    }
    return -1;
}


