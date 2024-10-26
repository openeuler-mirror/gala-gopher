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
#ifndef __TOPK_HEAP_H__
#define __TOPK_HEAP_H__
#include <utlist.h>

#include "stack_tree.h"

typedef struct _heap_mem_elem {
    struct stack_node_s *leaf;
    struct _heap_mem_elem *next;
} heap_mem_elem_t;

struct stack_node_s **get_topk_mem_stack(heap_mem_elem_t *head, int k, int *top_num);

#endif