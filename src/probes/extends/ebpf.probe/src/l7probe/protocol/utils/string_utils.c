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

/**
 * get sub-string(start, end) of src_str
 */
char *substr(char *src_str, size_t start_pos, size_t len)
{
    // 分配存储子字符串的内存空间
    char *sub_str = (char *) malloc(sizeof(char) * (len + 1));
    if (sub_str == NULL) {
        return NULL;
    }

    // 将子字符串复制到新分配的内存空间中
    strncpy(sub_str, src_str + start_pos, len);
    sub_str[len] = '\0';

    return sub_str;
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

size_t get_array_len(const char *arr[])
{
    size_t len = 0;
    while(arr[len][0] != '\0') {
        len++;
    }
    return len;
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

int simple_hex_atoi(const char* hex_str) {
    int result = 0;
    int i = 0;

    // 跳过前导空格
    while (isspace(hex_str[i])) {
        i++;
    }

    // 检查是否有可选的"0x"前缀
    if (hex_str[i] == '0' && tolower(hex_str[i + 1]) == 'x') {
        i += 2;
    }

    // 转换每个十六进制字符并计算结果
    while (hex_str[i] != '\0') {
        char c = tolower(hex_str[i]);
        if (isdigit(c)) {
            result = result * 16 + (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            result = result * 16 + (c - 'a' + 10);
        } else {
            break;  // 遇到无效字符，停止转换
        }
        i++;
    }

    return result;
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