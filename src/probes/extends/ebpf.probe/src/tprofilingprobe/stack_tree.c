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
#include "tprofiling.h"
#include "trace_viewer_fmt.h"
#include "stack_tree.h"

static u64 stack_tree_id = 1;

static u64 gen_stack_tree_id()
{
    return stack_tree_id++;
}

static struct stack_node_s *create_stack_node(const char *func_name, struct stack_node_s *parent)
{
    struct stack_node_s *new_node;

    new_node = (struct stack_node_s *)calloc(1, sizeof(struct stack_node_s));
    if (!new_node) {
        return NULL;
    }
    (void)snprintf(new_node->func_name, sizeof(new_node->func_name), "%s", func_name);
    new_node->id = gen_stack_tree_id();
    new_node->count = 0;
    new_node->parent = parent;
    new_node->childs = NULL;

    return new_node;
}

static void check_func_name(char *func_name, int size)
{
    char is_valid = 1;
    char *p = func_name;
    int c;

    while (*p != '\0') {
        c = *p;
        if (c < 0 || c > 127) {
            is_valid = 0;
            break;
        }
        switch (*p) {
            case '\"':
            case '\\':
            case '/':
                is_valid = 0;
                break;
            default:
                break;
        }
        if (!is_valid) {
            break;
        }
        p++;
    }

    if (!is_valid) {
        func_name[0] = 0;
        (void)snprintf(func_name, size, DFT_STACK_SYMB_NAME);
    }
}

static void set_func_name(char *func_name, int size, char *begin, char *end)
{
    int len;

    len = min(end - begin, size - 1);
    func_name[0] = 0;
    strncpy(func_name, begin, len);
    func_name[len] = 0;
    check_func_name(func_name, size);
}

// 返回叶子节点
struct stack_node_s *stack_tree_add_stack(struct stack_node_s *stack_root, char *stack_str, bool is_store_local)
{
    struct stack_node_s *cur_node = stack_root;
    struct stack_node_s *child;
    struct stack_node_s *first_created_node = NULL;
    char func_name[STACK_FUNC_NAME_LEN];
    const char sep = ';';
    char *begin, *end;

    if (stack_str == NULL) {
        return NULL;
    }

    begin = stack_str;
    while (*begin != '\0') {
        end = begin;
        while (*end != '\0' && *end != sep) {
            end++;
        }
        set_func_name(func_name, sizeof(func_name), begin, end);

        HASH_FIND_STR(cur_node->childs, func_name, child);
        if (!child) {
            child = create_stack_node(func_name, cur_node == stack_root ? NULL : cur_node);
            if (!child) {
                TP_ERROR("Failed to create stack node\n");
                goto err;
            }
            HASH_ADD_STR(cur_node->childs, func_name, child);
            first_created_node = first_created_node != NULL ? first_created_node : child;
        }

        cur_node = child;
        begin = (*end == '\0') ? end : end + 1;
    }

    if (cur_node == stack_root) {
        goto err;
    }

    // 对于需要将堆栈保存到本地的场景，将新增的堆栈节点写入stack临时文件
    struct local_store_s *local_storage = &tprofiler.localStorage;
    if (first_created_node != NULL && is_store_local) {
        struct stack_node_s *tmp_node = cur_node;
        int count = 0;
        while (1) {
            if (stack_trace_file_fill_stack_node(local_storage, tmp_node)) {
                goto err;
            }
            count++;
            if (tmp_node == first_created_node) {
                break;
            }
            tmp_node = tmp_node->parent;
        }
        local_storage->stack_node_num += count;
    }

    return cur_node;
err:
    if (first_created_node != NULL) {
        if (first_created_node->parent != NULL) {
            HASH_DEL(first_created_node->parent->childs, first_created_node);
            cleanup_stack_tree(first_created_node);
        }
    }
    return NULL;
}

void cleanup_stack_tree(struct stack_node_s *stack_node)
{
    struct stack_node_s *child, *tmp;

    if (stack_node == NULL) {
        return;
    }

    if (stack_node->childs != NULL) {
        HASH_ITER(hh, stack_node->childs, child, tmp) {
            HASH_DEL(stack_node->childs, child);
            cleanup_stack_tree(child);
        }
    }

    free(stack_node);
}

struct stack_node_s **stack_tree_get_stack_path(struct stack_node_s *leaf, int *num)
{
    struct stack_node_s **stack_path;
    struct stack_node_s *cur;

    *num = 0;
    cur = leaf;
    while (cur->parent != NULL) {
        ++(*num);
        cur = cur->parent;
    }

    stack_path = (struct stack_node_s **)calloc(*num, sizeof(struct stack_node_s *));
    if (stack_path == NULL) {
        return NULL;
    }
    cur = leaf;
    for (int i = *num - 1; i >= 0; --i) {
        stack_path[i] = cur;
        cur = cur->parent;
    }
    return stack_path;
}

int stack_tree_get_stack_str(struct stack_node_s *leaf, char *buf, int buf_sz)
{
    struct stack_node_s **stack_path;
    int num;
    char *sep = ";";
    char *buf_pos = buf;
    int left_buf_sz = buf_sz;
    int ret;

    buf[0] = 0;
    stack_path = stack_tree_get_stack_path(leaf, &num);
    if (stack_path == NULL) {
        TP_ERROR("Failed to get stack path\n");
        return -1;
    }
    for (int i = 0; i < num; i++) {
        sep = (i == 0) ? "" : ";";
        ret = snprintf(buf_pos, left_buf_sz, "%s%s", sep, stack_path[i]->func_name);
        if (ret < 0 || ret >= left_buf_sz) {
            TP_ERROR("Failed to get stack str: buffer not large enough, ret=%d.\n", ret);
            return -1;
        }
        buf_pos += ret;
        left_buf_sz -= ret;
    }

    free(stack_path);
    return 0;
}

void stack_tree_remove_leaf(struct stack_node_s *leaf)
{
    struct stack_node_s *cur = leaf;
    struct stack_node_s *parent = cur->parent;

    while (parent != NULL && cur->childs == NULL) {
        HASH_DEL(parent->childs, cur);
        free(cur);
        cur = parent;
        parent = cur->parent;
    }
}