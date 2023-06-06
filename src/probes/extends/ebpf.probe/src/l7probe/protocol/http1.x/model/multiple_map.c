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
 * Author: eank
 * Create: 2023/6/16
 * Description:
 ******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "multiple_map.h"

value_node *init_value_node()
{
    value_node *node = (value_node *) malloc(sizeof(value_node *));
    if (node == NULL) {
        return NULL;
    }
    return node;
}

void free_value_node(value_node *node)
{
    if (node == NULL) {
        return;
    }
    if (node->next != NULL) {
        free_value_node(node->next);
    }
    free(node);
}

// 从value_node链表中递归寻找value
static bool find_value_in_node(value_node *node, char *value)
{
    if (strcmp(node->value, value)) {
        return true;
    }
    if (node->next != NULL) {
        return find_value_in_node(node->next, value);
    }
    return false;
}

// 从value_node中删除一个value
static value_node *remove_value_from_node(value_node *node, char *value)
{
    if (strcpy(node->value, value)) {
        return node->next;
    }
    if (node->next != NULL) {
        node->next = remove_value_from_node(node->next, value);
    }
    return node;
}

// value_node中添加value，如果链表中没有才插入，新插入的value放在链表头部（头插法）
static value_node *add_value_into_node(value_node *node, char *value)
{
    value_node *new_node;
    if (node == NULL) {
        return NULL;
    }
    if (find_value_in_node(node, value)) {
        return node;
    }

    new_node = (value_node *) malloc(sizeof(value_node *));
    strcpy(new_node->value, value);
    new_node->next = node;
    return new_node;
}

http_headers_map *init_http_headers_map(void)
{
    http_headers_map *headers = (http_headers_map *) malloc(sizeof(http_headers_map));
    if (headers == NULL) {
        return NULL;
    }
    return headers;
}

void free_http_headers_map(http_headers_map* map)
{
    if (map == NULL) {
        return;
    }
    if (map->values != NULL) {
        free_value_node(map->values);
    }
    free(map);
}

void insert_into_multiple_map(http_headers_map *map, const char *key, char *value)
{
    http_headers_map *pair;
    char *key_l = to_lower(*key);
    HASH_FIND_STR(map, key_l, pair);
    if (pair == NULL) {
        pair = (key_values_pair *) malloc(sizeof(key_values_pair));
        strncpy(pair->key, key_l, MAX_KEY_LEN);
        pair->values = NULL;
        HASH_ADD_STR(map, key_l, pair);
    }
    add_value_into_node(pair->values, value);
}

http_headers_map *get_values_by_key(http_headers_map *map, const char *key)
{
    http_headers_map *pair;
    char *key_l = to_lower(*key);
    HASH_FIND_STR(map, key, pair);
    return pair;
}

char *get_1st_value_by_key(http_headers_map *map, const char *key)
{
    char *key_l = to_lower(*key);
    http_headers_map *pair = get_values_by_key(map, key_l);
    if (pair == NULL) {
        return NULL;
    }
    return pair->values[0];
}

char *to_string(http_headers_map *map)
{
    // todo: map数据转string
    return NULL;
}