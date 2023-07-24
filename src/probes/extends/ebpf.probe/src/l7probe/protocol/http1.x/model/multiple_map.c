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
#include "common.h"
#include "hash.h"
#include "multiple_map.h"

http_headers_map *init_http_headers_map(void)
{
    http_headers_map *headers = (http_headers_map *) malloc(sizeof(http_headers_map));
    if (headers == NULL) {
        return NULL;
    }
    memset(headers, 0, sizeof(http_headers_map));
    return headers;
}

void free_http_headers_map(http_headers_map** map)
{
    if (*map == NULL) {
        return;
    }
    http_headers_map *item, *tmp;
    H_ITER(*map, item, tmp) {
        H_DEL(*map, item);
        if (item->key) {
            free(item->key);
        }
        for (int i = 0; i < item->val_len; i++) {
            if (item->values[i] != NULL) {
                free(item->values[i]);
            }
        }
        free(item);
    }
}

void insert_into_multiple_map(http_headers_map **map, const char *key, const char *value)
{
    http_headers_map *kv = NULL;
    H_FIND_S(*map, key, kv);
    bool found = kv != NULL;
    if (!found) {
        kv = init_http_headers_map();
        kv->key = strdup(key);
    }
    if (kv->val_len == MAX_HEADERS_SIZE) {
        WARN("[HTTP1.x PARSER] headers len: %d, exceeds MAX_HEADERS_SIZE(50).\n");
        if (!found) {
            free_http_headers_map(&kv);
        }
        return;
    }
    kv->values[kv->val_len] = strdup(value);
    kv->val_len++;
    H_ADD_S(*map, key, kv);
}

http_headers_map *get_values_by_key(http_headers_map *map, const char *key)
{
    if (map == NULL) {
        return NULL;
    }
    http_headers_map *kv;
    H_FIND_S(map, key, kv);
    return kv;
}

char *get_1st_value_by_key(http_headers_map *map, const char *key)
{
    if (map == NULL) {
        return NULL;
    }
    http_headers_map *kv;
    H_FIND_S(map, key, kv);
    if (kv == NULL) {
        return NULL;
    }
    return kv->values[0];
}