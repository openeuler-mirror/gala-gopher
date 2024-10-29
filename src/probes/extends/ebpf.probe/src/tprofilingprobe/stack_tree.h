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
 * Description: stack tree
 ******************************************************************************/
#ifndef __STACK_TREE_H__
#define __STACK_TREE_H__
#include <stdbool.h>
#include <uthash.h>

#include "common.h"

#define STACK_FUNC_NAME_LEN 128

struct stack_node_s {
    char func_name[STACK_FUNC_NAME_LEN];
    u64 id;
    s64 count;  // 对于内存堆栈，表示该堆栈申请的内存大小，单位为字节
    struct stack_node_s *parent;
    struct stack_node_s *childs;
    UT_hash_handle hh;
};

struct stack_node_s *stack_tree_add_stack(struct stack_node_s *stack_root, char *stack_str, bool is_store_local);
void cleanup_stack_tree(struct stack_node_s *stack_node);
int stack_tree_get_stack_str(struct stack_node_s *leaf, char *buf, int buf_sz);
void stack_tree_remove_leaf(struct stack_node_s *leaf);

#endif