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
 * Create: 2023-04-25
 * Description:
 ******************************************************************************/
#ifndef __STRING_UTILS_H__
#define __STRING_UTILS_H__

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

/**
 * get sub-string(start, end) of src_str
 *
 * @param src_str
 * @param start_pos
 * @param len
 * @return sub-string from start_pos to end_pos
 */
char *substr(char *src_str, size_t start_pos, size_t len);

/**
 * string to UPPER
 *
 * @param src_char
 * @return
 */
char* to_upper(const char *src_char);

/**
 * string to LOWER
 *
 * @param src_char
 * @return
 */
char* to_lower(const char *src_char);

/**
 * find char from string
 *
 * @param str
 * @param ch
 * @return
 */
int find(char *str, char ch);

/**
 * rfind char from string
 *
 * @param str
 * @param ch
 * @return
 */
int rfind(char *str, char ch);

/**
 * find sub-string from string
 *
 * @param str
 * @param sub
 * @param start_pos
 * @return
 */
size_t find_str(const char *str, const char *sub, const size_t start_pos);

/**
 * rfind sub-string from string
 *
 * @param str
 * @param sub
 * @return
 */
size_t rfind_str(const char *str, const char *sub);

/**
 * get char* array len
 *
 * @param arr
 * @return
 */
size_t get_array_len(const char *arr[]);

/**
 * judge str is contained substr
 *
 * @param str
 * @param substr
 * @return
 */
bool contains(char *str, char *substr);

/**
 * split string by delimiter and decrease blank
 *
 * @param str src string
 * @param delim delimiter
 * @param skip_empty is needed to decrease blank
 * @return
 */
char** str_split(const char* str, const char* delim, int skip_empty);

/**
 * split string by delimiter
 *
 * @param str
 * @param delim
 * @param max_splits
 * @return
 */
char** max_split(const char *str, const char *delim, int max_count);

/**
 * start_with for string
 *
 * @param str
 * @param prefix
 * @return
 */
int starts_with(const char *str, const char *prefix);

/**
 * simple atoi function
 *
 * @param str
 * @param result
 * @return
 */
int simple_atoi(const char *str, int *result);

/**
 * remove prefix
 *
 * @param str
 * @param prefix
 */
void remove_prefix(char *str, const char *prefix);

/**
 * simple hex atoi function
 *
 * @param hex_str
 * @return
 */
int simple_hex_atoi(const char* hex_str);

#endif // __STRING_UTILS_H__
