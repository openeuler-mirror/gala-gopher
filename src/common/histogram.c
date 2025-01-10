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
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "strbuf.h"
#include "histogram.h"

// Refer to https://zhuanlan.zhihu.com/p/608621390

static const float __histo_p50 = 0.5;
static const float __histo_p90 = 0.9;
static const float __histo_p99 = 0.99;

static u64 __get_histo_bucket_sum(struct histo_bucket_s **bucket, size_t bucket_size)
{
    u64 sum = 0;

    for (int i = 0; i < bucket_size; i++) {
        sum += (bucket[i] == NULL ? 0 : bucket[i]->count);
    }
    return sum;
}


static struct histo_bucket_s* __find_histo_bucket(struct histo_bucket_s **bucket, size_t bucket_size, size_t count,
    size_t *offset, struct bucket_range_s *bucket_range, struct bucket_range_s bucket_ranges[])
{
    size_t remain = count;
    u64 count_tmp = 0;
    for (int i = 0; i < bucket_size; i++) {
        count_tmp = (bucket[i] == NULL) ? 0 : bucket[i]->count;
        if (remain > count_tmp) {
            remain = remain - count_tmp;
        } else {
            *offset = count_tmp - remain;
            *bucket_range = bucket_ranges[i];
            return bucket[i];
        }
    }
    return NULL;
}

int init_bucket_range(struct bucket_range_s *bucket, u64 min, u64 max)
{
    if (min >= max) {
        return -1;
    }
    bucket->min = min;
    bucket->max = max;
    return 0;
}

void free_histo_buckets(struct histo_bucket_array_s *his_bk_arr, int size)
{
    struct histo_bucket_s **buckets = his_bk_arr->histo_buckets;
    if (buckets) {
        for (int i = 0; i < size; ++i) {
            if (buckets[i]) {
                free(buckets[i]);
                buckets[i] = NULL;
            }
        }
        free(buckets);
        buckets = NULL;
    }
}

int init_bucket(struct histo_bucket_array_s *bucket_array, size_t bucket_size)
{
    bucket_array->histo_buckets = (struct histo_bucket_s **)malloc(bucket_size * sizeof(struct histo_bucket_s *));
    if (!bucket_array->histo_buckets) {
        ERROR("[TCP TRACKER] histo bucket init malloc failed");
        return -1;
    }
    memset(bucket_array->histo_buckets, 0, bucket_size * sizeof(struct histo_bucket_s *));
    return 0;
}

int init_bucket_with_content(struct histo_bucket_array_s *bucket_array, size_t bucket_size)
{
    if (init_bucket(bucket_array, bucket_size)) {
        return -1;
    }
    for (int i = 0; i < bucket_size; ++i) {
        bucket_array->histo_buckets[i] = malloc(sizeof(struct histo_bucket_s));
        if (!bucket_array->histo_buckets[i]) {
            return -1;
        }
    }
    return 0;
}

int histo_bucket_add_value(struct bucket_range_s bucket_range[], struct histo_bucket_array_s *bucket_array, size_t bucket_size, u64 value)
{
    if (!bucket_array->histo_buckets) {
        if (init_bucket(bucket_array, bucket_size)) {
            WARN("[Histogram] malloc bucket array failed !");
            return -1;
        }
    }
    struct histo_bucket_s **buckets = bucket_array->histo_buckets;
    for (int i = 0; i < bucket_size; i++) {
        if ((value > bucket_range[i].min) && (value <= bucket_range[i].max)) {
            if (!buckets[i]) {
                buckets[i] = (struct histo_bucket_s *)malloc(sizeof(struct histo_bucket_s));
                if (!buckets[i]) {
                    WARN("[Histogram] malloc bucket failed !");
                    return -1;
                }
                buckets[i]->count = 0;
                buckets[i]->sum = 0;
            }
            buckets[i]->count++;
            buckets[i]->sum += value;
            return 0;
        }
    }
    return -1;
}

void histo_bucket_reset(struct histo_bucket_array_s *bucket_arr, size_t bucket_size)
{
    struct histo_bucket_s **bucket = bucket_arr->histo_buckets;
    if (!bucket) {
        return;
    }
    for (int i = 0; i < bucket_size; ++i) {
        if (!bucket[i]) {
            continue;
        }
        free(bucket[i]);
        bucket[i] = NULL;
    }
    free(bucket_arr->histo_buckets);
    bucket_arr->histo_buckets = NULL;
}

int histo_bucket_value(struct bucket_range_s latency_buckets[], struct histo_bucket_array_s *bucket_arr, size_t bucket_size, enum histo_type_t type, float *value)
{
    size_t offset = 0;
    struct histo_bucket_s **bucket = bucket_arr->histo_buckets;
    if (!bucket) {
        return 0;
    }
    u64 sum = __get_histo_bucket_sum(bucket, bucket_size);
    size_t histo_count;
    struct histo_bucket_s *bucket_finded;
    struct bucket_range_s bucket_range;

    if (sum == 0) {
        *value = 0.0f;
        return -1;
    }

    if (type == HISTO_P50) {
        histo_count = (size_t)(sum * __histo_p50);
    } else if (type == HISTO_P90) {
        histo_count = (size_t)(sum * __histo_p90);
    } else {
        histo_count = (size_t)(sum * __histo_p99);
    }

    bucket_finded = __find_histo_bucket(bucket, bucket_size, histo_count, &offset, &bucket_range, latency_buckets);
    if (bucket_finded == NULL) {
        return -1;
    }

    if (offset == 0) {
        offset += 1;
    }

    if (bucket_finded->count == 0) {
        *value = 0.0f;
        return -1;
    }

    *value = (float)(bucket_range.max - bucket_range.min) * ((float)offset / (float)bucket_finded->count) + (float)bucket_range.min;
    return 0;
}

int serialize_histo(struct bucket_range_s bucket_ranges[], struct histo_bucket_array_s *buckets_arr, size_t bucket_size, char *buf, size_t buf_size)
{
    int ret;
    u64 count = 0, sum = 0;
    int i;
    strbuf_t strbuf = {
        .buf = buf,
        .size = (int)buf_size
    };
    struct histo_bucket_s **buckets = buckets_arr->histo_buckets;
    int is_empty_bucket_array = (!buckets);

    ret = snprintf(strbuf.buf, strbuf.size, "%lu", bucket_size);
    if (ret < 0 || ret >= strbuf.size) {
        goto err;
    }
    strbuf_update_offset(&strbuf, ret);

    for (i = 0; i < bucket_size; i++) {
        count += (is_empty_bucket_array || buckets[i] == NULL ? 0 : buckets[i]->count);
        sum += (is_empty_bucket_array || buckets[i] == NULL ? 0 : buckets[i]->sum);
        ret = snprintf(strbuf.buf, strbuf.size, " %llu %llu", bucket_ranges[i].max, count);
        if (ret < 0 || ret >= strbuf.size) {
            goto err;
        }
        strbuf_update_offset(&strbuf, ret);
    }

    ret = snprintf(strbuf.buf, strbuf.size, " %llu", sum);
    if (ret < 0 || ret >= strbuf.size) {
        goto err;
    }
    return 0;
err:
    ERROR("[HISTOGRAM] Failed to serialize histogram: buffer space not enough\n");
    return -1;
}

static int _deserialize_histo(char *buf, struct histo_bucket_with_range_s *bucket, size_t bucket_size, u64 *bkt_sum)
{
    char *cur_pos, *next_pos;
    u64 last_count = 0, count;
    size_t buf_size = strlen(buf);
    int i;

    cur_pos = buf;
    for (i = 0; i < bucket_size; i++) {
        next_pos = strchr(cur_pos, ' ');
        if (!next_pos) {
            return -1;
        }
        *next_pos = '\0';

        bucket[i].max = strtoull(cur_pos, NULL, 10);
        bucket[i].min = (i == 0) ? 0 : bucket[i - 1].max;
        cur_pos = next_pos + 1;
        if (cur_pos - buf >= buf_size) {
            return -1;
        }

        next_pos = strchr(cur_pos, ' ');
        if (!next_pos) {
            return -1;
        }
        *next_pos = '\0';
        count = strtoull(cur_pos, NULL, 10);
        if (count < last_count) {
            return -1;
        }
        bucket[i].count = count - last_count;
        last_count = count;
        cur_pos = next_pos + 1;
        if (cur_pos - buf >= buf_size) {
            return -1;
        }
    }

    *bkt_sum = strtoull(cur_pos, NULL, 10);
    return 0;
}

static int resolve_bucket_size(char *buf, char **new_buf)
{
    int ret;
    char *pos;

    pos = strchr(buf, ' ');
    if (!pos) {
        return -1;
    }
    *pos = '\0';

    ret = strtol(buf, NULL, 10);
    if (ret <= 0) {
        return -1;
    }

    *new_buf = pos + 1;
    return ret;
}

int deserialize_histo(const char *buf, struct histo_bucket_with_range_s **bucket, size_t *bucket_size, u64 *bkt_sum)
{
    struct histo_bucket_with_range_s *bkt = NULL;
    size_t bkt_sz = 0;
    char *buf_dup = NULL;
    char *pos;
    int ret;

    buf_dup = strdup(buf);
    if (!buf_dup) {
        ERROR("[HISTOGRAM] Failed to deserialize histogram: dup buffer failed\n");
        return -1;
    }

    ret = resolve_bucket_size(buf_dup, &pos);
    if (ret <= 0) {
        goto err;
    }
    bkt_sz = ret;

    bkt = (struct histo_bucket_with_range_s *)malloc(bkt_sz * sizeof(struct histo_bucket_with_range_s));
    if (!bkt) {
        ERROR("[HISTOGRAM] Failed to deserialize histogram: malloc bucket space failed\n");
        free(buf_dup);
        return -1;
    }
    ret = _deserialize_histo(pos, bkt, bkt_sz, bkt_sum);
    if (ret) {
        goto err;
    }

    *bucket = bkt;
    *bucket_size = bkt_sz;
    free(buf_dup);
    return 0;
err:
    ERROR("[HISTOGRAM] Failed to deserialize histogram: format error(%s)\n", buf);
    free(buf_dup);
    free(bkt);
    return -1;
}
