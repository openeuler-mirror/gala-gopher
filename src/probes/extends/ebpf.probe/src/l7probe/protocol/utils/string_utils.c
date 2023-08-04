/*******************************************************************************
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