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
#ifndef __DELAYING_RING_BUFFER_H__
#define __DELAYING_RING_BUFFER_H__

#include <sys/time.h>

struct drb_item {
    void *data;
    int size;
    struct timespec creation_time;
};

struct delaying_ring_buffer {
    struct drb_item *storage;
    int writer_idx;
    int reader_idx;
    int capacity;
    int delay_ms;
};

struct delaying_ring_buffer *drb_new(int capacity, int delay_ms);
void drb_destroy(struct delaying_ring_buffer *drb);
int drb_put(struct delaying_ring_buffer *drb, const char *data, const int size);
const struct drb_item *drb_look(struct delaying_ring_buffer *drb);
int drb_pop(struct delaying_ring_buffer *drb);

#endif