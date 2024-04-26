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
    if (bucket_finded == NULL) {
        return -1;
    }

    if (offset == 0) {
        offset += 1;
    }

    if (bucket_finded->count == 0) {
        *value = 0.0;
        return -1;
    }

    *value = (float)(bucket_finded->max - bucket_finded->min) * ((float)offset / (float)bucket_finded->count) + (float)bucket_finded->min;
    return 0;
}

int serialize_histo(struct histo_bucket_s bucket[], size_t bucket_size, char *buf, size_t buf_size)
{
    int ret;
    u64 sum = 0;
    int i;
    strbuf_t strbuf = {
        .buf = buf,
        .size = buf_size
    };

    ret = snprintf(strbuf.buf, strbuf.size, "%lu", bucket_size);
    if (ret < 0 || ret >= strbuf.size) {
        goto err;
    }
    strbuf_update_offset(&strbuf, ret);

    for (i = 0; i < bucket_size; i++) {
        sum += bucket[i].count;
        ret = snprintf(strbuf.buf, strbuf.size, " %llu %llu", bucket[i].max, sum);
        if (ret < 0 || ret >= strbuf.size) {
            goto err;
        }
        strbuf_update_offset(&strbuf, ret);
    }
    strbuf_append_chr(&strbuf, '\0');

    return 0;
err:
    ERROR("[HISTOGRAM] Failed to serialize histogram: buffer space not enough\n");
    return -1;
}

static int _deserialize_histo(char *buf, struct histo_bucket_s *bucket, size_t bucket_size)
{
    char *cur_pos, *next_pos;
    u64 sum = 0, count;
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
        next_pos = strchr(cur_pos, ' ');
        if (i + 1 < bucket_size) {
            if (!next_pos) {
                return -1;
            }
            *next_pos = '\0';
        } else {
            if (next_pos) {
                return -1;
            }
        }

        count = strtoull(cur_pos, NULL, 10);
        if (count < sum) {
            return -1;
        }
        bucket[i].count = count - sum;
        sum = count;

        if (i + 1 < bucket_size) {
            cur_pos = next_pos + 1;
        }
    }

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

int deserialize_histo(const char *buf, struct histo_bucket_s **bucket, size_t *bucket_size)
{
    struct histo_bucket_s *bkt = NULL;
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

    bkt = (struct histo_bucket_s *)malloc(bkt_sz * sizeof(struct histo_bucket_s));
    if (!bkt) {
        ERROR("[HISTOGRAM] Failed to deserialize histogram: malloc bucket space failed\n");
        free(buf_dup);
        return -1;
    }
    ret = _deserialize_histo(pos, bkt, bkt_sz);
    if (ret) {
        goto err;
    }

    *bucket = bkt;
    *bucket_size = bkt_sz;
    free(buf_dup);
    return 0;
err:
    ERROR("[HISTOGRAM] Failed to deserialize histogram: format error(%s)\n", buf);
    if (buf_dup) {
        free(buf_dup);
    }
    if (bkt) {
        free(bkt);
    }
    return -1;
}