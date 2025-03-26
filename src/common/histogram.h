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

#define MAX_HISTO_SERIALIZE_SIZE 256

enum histo_type_t {
    HISTO_P50,
    HISTO_P90,
    HISTO_P99
};

struct histo_bucket_with_range_s {
    u64 count;
    u64 sum;
    u64 min;
    u64 max;
};

struct histo_bucket_s {
    u64 count;
    u64 sum;              // sum of all values in this bucket
    u64 max;
};

struct histo_bucket_array_s {
    struct histo_bucket_s **histo_buckets;
};

struct bucket_range_s {
    u64 min, max;
};

int init_bucket(struct histo_bucket_array_s *bucket_array, size_t bucket_size);
int init_bucket_with_content(struct histo_bucket_array_s *bucket_array, size_t bucket_size);
int histo_bucket_add_value(struct bucket_range_s bucket_range[], struct histo_bucket_array_s *bucket_array, size_t bucket_size, u64 value);
int histo_bucket_value(struct bucket_range_s latency_buckets[], struct histo_bucket_array_s *bucket_arr, size_t bucket_size, enum histo_type_t type, float *value);
void histo_bucket_reset(struct histo_bucket_array_s *bucket_arr, size_t bucket_size);
int init_bucket_range(struct bucket_range_s *bucket, u64 min, u64 max);
void free_histo_buckets(struct histo_bucket_array_s *his_bk_arr, int size);
int resolve_bucket_size(char *buf, char **new_buf);
/*
 * serialize histogram metric from a struct histo_bucket_s to a string.
 * string format like: "<bucket_size> <bucket1_max> <bucket1_count> <bucket2_max> <bucket2_count> ..."
 */
int serialize_histo(struct bucket_range_s bucket_ranges[], struct histo_bucket_array_s *buckets_arr, size_t bucket_size, char *buf, size_t buf_size);
/*
 * deserialize histogram metric from a string to a struct histo_bucket_s.
 */
int deserialize_histo(const char *buf, struct histo_bucket_with_range_s **bucket, size_t *bucket_size, u64 *bkt_sum, u64 *bkt_max);

#define HISTO_BUCKET_RANGE_INIT(buckets_rg, size, histios)                                                    \
do {                                                                                                          \
    for (int i = 0; i < (size); ++i) {                                                                        \
        int histogram_ret = init_bucket_range(&((buckets_rg)[i]), (histios)[i].min, (histios)[i].max);        \
        if (histogram_ret) {                                                                                  \
            ERROR("[HISTOGRAM] init %s bucket failed, min %ld, max %ld\n",                                    \
                #histios, (histios)[i].min, (histios)[i].max);                                                \
        }                                                                                                     \
    }                                                                                                         \
} while (0)

#endif

