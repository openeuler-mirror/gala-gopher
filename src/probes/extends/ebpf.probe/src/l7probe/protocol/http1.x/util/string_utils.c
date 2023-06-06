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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "string_utils.h"

/**
 * get sub-string(start, end) of src_str
 *
 * @param src_str
 * @param start_pos
 * @param end_pos
 * @return
 */
char *substr(char *src_str, int start_pos, int end_pos)
{
    // 计算子字符串的长度
    int sub_len = end_pos - start_pos + 1;

    // 分配存储子字符串的内存空间
    char *sub_str = (char *) malloc(sizeof(char) * (sub_len + 1));
    if (sub_str == NULL) {
        return NULL;
    }

    // 将子字符串复制到新分配的内存空间中
    strncpy(sub_str, src_str + start_pos, sub_len);
    sub_str[sub_len] = '\0';

    return sub_str;
}

char *to_upper(char *src_char)
{
    char *upper_str = (char *) malloc(sizeof(char *));
    for (int i = 0; src_char[i] != '\0'; i++) {
        upper_str[i] = toupper(src_char[i]);
    }
    return upper_str;
}

char *to_lower(char *src_char)
{
    char *lower_str = (char *) malloc(sizeof(char *));
    for (int i = 0; src_char[i] != '\0'; i++) {
        lower_str[i] = tolower(src_char[i]);
    }
    return lower_str;
}

int find(char *str, char ch)
{
    int len = strlen(str);
    for (int i = 0; i < len; i++) {
        if (str[i] == ch) {
            return i;
        }
    }
    return -1;
}

int rfind(char *str, char ch)
{
    int len = strlen(str);
    for (int i = len - 1; i >= 0; i--) {
        if (str[i] == ch) {
            return i;
        }
    }
    return -1;
}

bool contains(char *str, char *substr)
{
    int i, j, k;
    for (i = 0; str[i] != '\0'; i++) {
        j = i;
        k = 0;
        while (substr[k] != '\0' && str[j] == substr[k]) {
            j++;
            k++;
        }
        if (substr[k] == '\0') {
            return true;
        }
    }
    return 0;
}

char **str_split(const char *str, const char *delim, int skip_empty)
{
    char **result = NULL;
    size_t count = 0;
    char *tmp = strdup(str);
    char *token = strtok(tmp, delim);

    while (token != NULL) {
        if (!skip_empty || strlen(token) > 0) {
            result = realloc(result, sizeof(char *) + count);
            result[count - 1] = strdup(token);
        }
        token = strtok(NULL, delim);
    }

    result = realloc(result, sizeof(char *) * (count + 1));
    result[count] = NULL;

    free(tmp);
    return result;
}

char **max_split(const char *str, const char *delim, int max_count)
{
    // 计算分隔符的长度
    int delim_len = strlen(delim);
    int i = 0;
    const char *p = str;

    // 分配指向每个子字符串的指针数组的内存空间
    char **result = (char **) malloc(sizeof(char *) * (max_count + 1));
    if (result == NULL) {
        return NULL;
    }

    while (*p != '\0' && i < max_count) {
        // 查找分隔符，找到后将其替换为字符串结束符号
        const char *q = strstr(p, delim);
        int len;
        if (q == NULL) {
            q = p + strlen(p);
        }
        len = q - p;

        // 分配存储子字符串的内存空间
        result[i] = (char *) malloc(sizeof(char) * (len + 1));
        if (result[i] == NULL) {
            // 释放之前分配的内存
            for (int j = 0; j < i; j++) {
                free(result[j]);
            }
            free(result);
            return NULL;
        }

        // 复制子字符串到新分配的内存空间中
        strncpy(result[i], p, len);
        result[i][len] = '\0';
        i++;
        p = q + delim_len;
    }

    // 处理字符串末尾的剩余部分
    if (*p != '\0') {
        result[i] = strdup(p);
        i++;
    }

    result[i] = NULL;  // 将指针数组的最后一个元素设置为 NULL，以便在使用时知道其结束位置
    return result;
}

int starts_with(const char *str, const char *prefix)
{
    size_t len_prefix = strlen(prefix);
    return strncmp(str, prefix, len_prefix) == 0;
}

int simple_atoi(const char *str, int *result)
{
    const char *p = str;
    int num = 0;
    while (*p != '\0') {
        if (*p >= '0' && *p <= '9') {
            num = num * 10 + (*p - '0');
        } else {
            return 0; // 如果遇到非数字字符则返回0表示转换失败
        }
        p++;
    }
    *result = num;
    return 1; // 返回1表示转换成功
}

void remove_prefix(char *str, const char *prefix)
{
    int len = strlen(prefix);
    if (strncmp(str, prefix, len) == 0) {
        memmove(str, str + len, strlen(str) - len + 1);
    }
}
