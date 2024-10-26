/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: algorithmofdish
 * Create: 2024-10-24
 * Description: topk heap
 ******************************************************************************/
#include "topk_heap.h"

struct mem_heap {
    struct stack_node_s **data;
    int size;
    int cap;
};

int heap_init(struct mem_heap *hp, int cap);
void heap_destroy(struct mem_heap *hp);
void heap_adjust(struct mem_heap *hp);
void heap_adjust_down(struct mem_heap *hp, int i, int size);
void heap_sort(struct mem_heap *hp);

struct stack_node_s **get_topk_mem_stack(heap_mem_elem_t *head, int k, int *top_num)
{
    struct mem_heap hp;
    heap_mem_elem_t *elem;
    int i = 0;

    if (heap_init(&hp, k)) {
        return NULL;
    }
    
    LL_FOREACH(head, elem) {
        if (elem->leaf == NULL || elem->leaf->count == 0) {
            continue;
        }

        if (i < k) {
            hp.data[i] = elem->leaf;
            ++hp.size;
        } else {
            if (i == k) {
                heap_adjust(&hp);
            }
            if (elem->leaf->count > hp.data[0]->count) {
                hp.data[0] = elem->leaf;
                heap_adjust_down(&hp, 0, hp.size);
            }
        }
        ++i;
    }
    if (i <= k) {
        heap_adjust(&hp);
    }

    heap_sort(&hp);
    *top_num = hp.size;
    return hp.data;
}

int heap_init(struct mem_heap *hp, int cap)
{
    hp->data = (struct stack_node_s **)calloc(cap, sizeof(struct stack_node_s *));
    if (hp->data == NULL) {
        return -1;
    }

    hp->size = 0;
    hp->cap = cap;
    return 0;
}

void heap_destroy(struct mem_heap *hp)
{
    free(hp->data);
    hp->data = NULL;
    hp->size = hp->cap = 0;
}

void heap_adjust(struct mem_heap *hp)
{
    for (int i = hp->size / 2 - 1; i >= 0; --i) {
        heap_adjust_down(hp, i, hp->size);
    }
}

void heap_adjust_down(struct mem_heap *hp, int i, int size)
{
    int cur_idx = i;
    struct stack_node_s *temp = hp->data[cur_idx];

    for (int k = cur_idx * 2 + 1; k < size; k = k * 2 + 1) {
        if (k + 1 < size && hp->data[k]->count > hp->data[k + 1]->count) {
            ++k;
        }
        if (hp->data[k]->count < temp->count) {
            hp->data[cur_idx] = hp->data[k];
            cur_idx = k;
        } else {
            break;
        }
    }
    hp->data[cur_idx] = temp;
}

void heap_sort(struct mem_heap *hp)
{
    for (int i = hp->size - 1; i > 0; --i) {
        struct stack_node_s *temp = hp->data[0];
        hp->data[0] = hp->data[i];
        hp->data[i] = temp;

        heap_adjust_down(hp, 0, i);
    }
}