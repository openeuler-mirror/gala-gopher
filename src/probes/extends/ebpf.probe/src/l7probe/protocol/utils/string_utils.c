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
 * Author: niebin
 * Create: 2023-04-14
 * Description:
 ******************************************************************************/

#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include "common.h"
#include "string_utils.h"

/**
 * get sub-string(start, end) of src_str
 */
char *substr(char *src_str, size_t start_pos, size_t len)
{
    // Allocate memory for sub-string
    char *sub_str = (char *) malloc(sizeof(char) * (len + 1));
    if (sub_str == NULL) {
        return NULL;
    }

    // Copy sub-string into new memory
    strncpy(sub_str, src_str + start_pos, len);
    sub_str[len] = '\0';

    return sub_str;
}

size_t find_str(const char *str, const char *sub, const size_t start_pos)
{
    size_t str_len = strlen(str);
    size_t sub_len = strlen(sub);

    if (str_len < sub_len) {
        return -1;
    }

    for (int i = start_pos; i <= str_len - sub_len; i++) {
        int j;
        for (j = 0; j < sub_len; j++) {
            if (str[i + j] != sub[j]) {
                break;
            }
        }
        if (j == sub_len) {
            return i;
        }
    }
    return -1;
}

size_t rfind_str(const char *str, const char *sub)
{
    size_t str_len = strlen(str);
    size_t sub_len = strlen(sub);

    if (str_len < sub_len) {
        return -1;
    }

    for (int i = str_len - sub_len; i >= 0; i--) {
        if (strncmp(str + i, sub, sub_len) == 0) {
            return i;
        }
    }

    return -1;
}

int starts_with(const char *str, const char *prefix)
{
    size_t len_prefix = strlen(prefix);
    return strncmp(str, prefix, len_prefix) == 0;
}

bool is_end_with(char *str, const char *suffix)
{
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    if (str_len < suffix_len) {
        return false;
    }
    if (strcmp(str + str_len - suffix_len, suffix) == 0) {
        return true;
    }
    return false;
}

char *remove_suffix(char *str, size_t n)
{
    size_t len = strlen(str);
    if (n > len) {
        ERROR("Failed to remove suffix, the length to remove exceeds the max value.\n");
        return str;
    }
    char *p = str;
    *(p + (len - n)) = '\0';
    return str;
}

char *str_to_upper(char *str)
{
    char *p = str;
    while (*p) {
        *p = toupper((unsigned char) *p);
        p++;
    }
    return str;
}