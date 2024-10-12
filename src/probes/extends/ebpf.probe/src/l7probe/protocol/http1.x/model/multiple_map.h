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
 * Create: 2023-04-20
 * Description: Implementation of MultipleMap using utHash.
 ******************************************************************************/
#ifndef __MULTIPLE_MAP_H__
#define __MULTIPLE_MAP_H__

#include <stddef.h>
#include <uthash.h>
#include <ctype.h>
#include "hash.h"
#include "utils/string_utils.h"

#define MAX_HEADERS_SIZE 50

/**
 * multiple map key-value pair
 *
 * http headers map, using UTHash
 * HTTP1.x headers can have multiple values for the same name, and filed names are case-insensitive.
 * key represents lower case of key
 */
typedef struct key_values_pair {
    H_HANDLE;
    char *key;
    char *values[MAX_HEADERS_SIZE];
    size_t val_len;
} http_headers_map;

http_headers_map *init_http_headers_map(void);

void free_http_headers_map(http_headers_map** map);

/**
 * insert key-value into the multiple-map
 *
 * @param map
 * @param key
 * @param value
 */
void insert_into_multiple_map(http_headers_map **map, const char *key, const char *value);

/**
 * get values from the multiple-map by key
 *
 * @param map
 * @param key
 * @return
 */
http_headers_map *get_values_by_key(http_headers_map *map, const char *key);

/**
 * get 1st value by key in the multiple map
 *
 * @param map
 * @param key
 * @return
 */
char *get_1st_value_by_key(http_headers_map *map, const char *key);

#endif // __MULTIPLE_MAP_H__
