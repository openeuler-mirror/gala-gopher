/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: ilyashakhat
 * Create: 2024-03-15
 * Description: A circular (ring) buffer with a time-based delay of reading operations
 ******************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common.h"
#include "delaying_ring_buffer.h"

struct delaying_ring_buffer *drb_new(int capacity, int delay_ms)
{
    struct delaying_ring_buffer *drb = malloc(sizeof(struct delaying_ring_buffer));
    if (!drb) {
        return NULL;
    }
    drb->reader_idx = drb->writer_idx = 0;
    drb->capacity = capacity;
    drb->delay_ms = delay_ms;
    drb->storage = malloc(sizeof(struct drb_item) * capacity);
    INFO("[DRB] Allocated a delaying ring buffer with capacity %d and delay %d ms\n", capacity, delay_ms);
    return drb;
}

void drb_destroy(struct delaying_ring_buffer *drb)
{
    if (drb) {
        if (drb->storage) {
            for (int idx = drb->reader_idx; idx < drb->writer_idx; idx++) {
                free(drb->storage[idx].data);
            }
            free(drb->storage);
        }
        free(drb);
    }
    INFO("[DRB] Delaying ring buffer destroyed\n");
}

int drb_put(struct delaying_ring_buffer *drb, const char *data, const int size)
{
    int writer_idx = drb->writer_idx;
    if ((writer_idx + 1) % drb->capacity == drb->reader_idx) {
        return -1; // storage is full
    }

    char *copy = malloc(size);
    memcpy(copy, data, size);
    drb->storage[writer_idx].data = copy;
    drb->storage[writer_idx].size = size;
    clock_gettime(CLOCK_MONOTONIC, &drb->storage[writer_idx].creation_time);

    drb->writer_idx = (drb->writer_idx + 1) % drb->capacity;
    return 0;
}

static void timespec_diff(struct timespec *now, struct timespec *past, struct timespec *diff) {
    diff->tv_sec = (now)->tv_sec - (past)->tv_sec;
    diff->tv_nsec = (now)->tv_nsec - (past)->tv_nsec;
    if (diff->tv_nsec < 0) {
      --diff->tv_sec;
      diff->tv_nsec += 1000000000;
    }
}

const struct drb_item *drb_look(struct delaying_ring_buffer *drb)
{
    if (drb->reader_idx == drb->writer_idx) {
        return NULL;
    }
    struct timespec now, diff;
    clock_gettime(CLOCK_MONOTONIC, &now);

    struct drb_item *item = &drb->storage[drb->reader_idx];

    timespec_diff(&now, &item->creation_time, &diff);
    if (diff.tv_sec == 0 && (diff.tv_nsec / 1000000) < drb->delay_ms) {
        return NULL;
    }
    return &drb->storage[drb->reader_idx];
}

int drb_pop(struct delaying_ring_buffer *drb) {
    if (drb->writer_idx == drb->reader_idx) {
        return -1;
    }
    struct drb_item *item = &drb->storage[drb->reader_idx];
    free(item->data);
    drb->reader_idx = (drb->reader_idx + 1) % drb->capacity;
    return 0;
}