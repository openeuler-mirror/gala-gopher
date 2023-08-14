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
 * Author: zhaoguolin
 * Create: 2023-04-27
 * Description:
 ******************************************************************************/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "binary_decoder.h"
#include "../common/protocol_common.h"

parse_state_t decoder_extract_char(struct raw_data_s *raw_data, char *res)
{
    if ((raw_data->data_len - raw_data->current_pos) < sizeof(char)) {
        ERROR("[Binary Decoder] Buffer bytes are insufficient.\n");
        return STATE_NEEDS_MORE_DATA;
    }

    // 提取提一个字节
    *res = raw_data->data[raw_data->current_pos];
    parser_raw_data_offset(raw_data, sizeof(char));
    return STATE_SUCCESS;
}

parse_state_t decoder_extract_bool(struct raw_data_s *raw_data, bool *res)
{
    char res_char;
    parse_state_t decode_status = decoder_extract_char(raw_data, &res_char);
    if (decode_status != STATE_SUCCESS) {
        return STATE_INVALID;
    }
    *res = res_char;
    return STATE_SUCCESS;
}

/**
 * 大端法提取字符串中的整形数据。
 *
 * @param data_stream_buf 字符串缓存
 * @return int(u_int8_t, u_int16_t, u_int32_t)
 */
#define BIG_ENDIAN_BYTES_TO_INT(INT_TYPE)                            \
INT_TYPE big_endian_bytes_to_##INT_TYPE(const char *data_stream_buf) \
{                                                                    \
    INT_TYPE res = 0;                                                \
    for (size_t i = 0; i < sizeof(INT_TYPE); i++) {                  \
        res = (u_int8_t)(data_stream_buf[i]) | (res << 8);            \
    }                                                                \
    return res;                                                      \
}

BIG_ENDIAN_BYTES_TO_INT(int8_t)

BIG_ENDIAN_BYTES_TO_INT(int16_t)

BIG_ENDIAN_BYTES_TO_INT(int32_t)

BIG_ENDIAN_BYTES_TO_INT(int64_t)

// u_int8_t big_endian_bytes_to_u_int8_t(const char *data_stream_buf)
BIG_ENDIAN_BYTES_TO_INT(u_int8_t)

// u_int16_t big_endian_bytes_to_u_int16_t(const char *data_stream_buf)
BIG_ENDIAN_BYTES_TO_INT(u_int16_t)

// u_int32_t big_endian_bytes_to_u_int32_t(const char *data_stream_buf)
BIG_ENDIAN_BYTES_TO_INT(u_int32_t)

// u_int64_t big_endian_bytes_to_u_int64_t(const char *data_stream_buf)
BIG_ENDIAN_BYTES_TO_INT(u_int64_t)

/**
 * 从raw_data中提取int类型数据（u_int8_t, u_int16_t, u_int32_t......）
 *
 * @param raw_data 字符串缓存
 * @return 状态码
 */
#define DECODER_EXTRACT_INT(INT_TYPE)                                                \
parse_state_t decoder_extract_##INT_TYPE(struct raw_data_s *raw_data, INT_TYPE *res) \
{                                                                                    \
    if ((raw_data->data_len - raw_data->current_pos) < sizeof(INT_TYPE)) {           \
        ERROR("[Binary Decoder] Buffer bytes are insufficient.\n");                  \
        return STATE_NEEDS_MORE_DATA;                                                \
    }                                                                                \
    *res = big_endian_bytes_to_##INT_TYPE(&raw_data->data[raw_data->current_pos]);   \
    parser_raw_data_offset(raw_data, sizeof(INT_TYPE));                              \
    return STATE_SUCCESS;                                                            \
}

DECODER_EXTRACT_INT(int8_t)

DECODER_EXTRACT_INT(int16_t)

DECODER_EXTRACT_INT(int32_t)

DECODER_EXTRACT_INT(int64_t)

// parse_state_t decoder_extract_u_int8_t(raw_data_s *raw_data, u_int8_t *res)
DECODER_EXTRACT_INT(u_int8_t)

// parse_state_t decoder_extract_u_int16_t(raw_data_s *raw_data, u_int16_t *res)
DECODER_EXTRACT_INT(u_int16_t)

// parse_state_t decoder_extract_u_int32_t(raw_data_s *raw_data, u_int32_t *res)
DECODER_EXTRACT_INT(u_int32_t)

// parse_state_t decoder_extract_u_int64_t(raw_data_s *raw_data, u_int32_t *res)
DECODER_EXTRACT_INT(u_int64_t)

bool extract_prefix_bytes_string(struct raw_data_s *raw_data, char **res, size_t decode_len, size_t data_stream_offset)
{
    // 申请新内存，存放提取后字符串
    char *new_res = malloc(decode_len + 1);
    if (new_res == NULL) {
        return false;
    }

    // 拷贝raw_data前decode_len长度字节
    memcpy(new_res, &raw_data->data[raw_data->current_pos], decode_len);
    new_res[decode_len] = '\0';

    // 偏移缓存区指针
    parser_raw_data_offset(raw_data, data_stream_offset);

    // *res指向新内存
    if (*res != NULL) {
        free(*res);
    }
    *res = new_res;
    return true;
}

parse_state_t decoder_extract_raw_data_with_len(struct raw_data_s *src_raw_data, size_t decode_len,
                                                struct raw_data_s **dst_raw_data)
{
    if ((src_raw_data->data_len - src_raw_data->current_pos) < decode_len) {
        ERROR("[Binary Decoder] Buffer bytes are insufficient.\n");
        return STATE_NEEDS_MORE_DATA;
    }

    struct raw_data_s *raw_data = (struct raw_data_s *) malloc(sizeof(struct raw_data_s) + decode_len);
    if (raw_data == NULL) {
        ERROR("[Binary Decoder] Failed to malloc raw_data.\n");
        return STATE_INVALID;
    }
    raw_data->data_len = decode_len;
    raw_data->current_pos = 0;
    memcpy(raw_data->data, &src_raw_data->data[src_raw_data->current_pos], decode_len);

    *dst_raw_data = raw_data;

    // 偏移缓存区指针
    parser_raw_data_offset(src_raw_data, decode_len);
    return STATE_SUCCESS;
}

//1
parse_state_t decoder_extract_string(struct raw_data_s *raw_data, char **res, size_t decode_len)
{
    if ((raw_data->data_len - raw_data->current_pos) < decode_len) {
        ERROR("[Binary Decoder] Buffer bytes are insufficient.\n");
        return STATE_NEEDS_MORE_DATA;
    }
    if (!extract_prefix_bytes_string(raw_data, res, decode_len, decode_len)) {
        ERROR("[Binary Decoder] Extract %zu length of raw_data failed.\n", decode_len);
        return STATE_INVALID;
    }
    return STATE_SUCCESS;
}

parse_state_t decoder_extract_str_until_char(struct raw_data_s *raw_data, char **res, char search_char)
{
    size_t search_char_pos = -1;
    for (size_t i = raw_data->current_pos; i < raw_data->data_len; ++i) {
        if (raw_data->data[i] != search_char) {
            continue;
        }
        search_char_pos = i;
        break;
    }
    if (search_char_pos == -1) {
        ERROR("[Binary Decoder] Could not find search_char: %c in raw_data.\n", search_char);
        return STATE_NOT_FOUND;
    }

    // 提取子字符串至search_char所在位置（不包括search_char）
    size_t decode_len = search_char_pos - raw_data->current_pos;
    if (!extract_prefix_bytes_string(raw_data, res, decode_len, decode_len + 1)) {
        ERROR("[Binary Decoder] Extract %zu length of raw_data failed.\n", search_char_pos);
        return STATE_INVALID;
    }
    return STATE_SUCCESS;
}

static void* memmem_custom(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len) {
    if (needle_len == 0) {
        // 如果 needle 长度为 0，则直接返回 haystack 的起始地址
        return (void*)haystack;
    }

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp((char*)haystack + i, needle, needle_len) == 0) {
            // 找到匹配的子字符串，返回位置
            return (void*)((char*)haystack + i);
        }
    }

    // 未找到匹配的子字符串
    return NULL;
}

parse_state_t decoder_extract_str_until_str(struct raw_data_s *raw_data, char **res, const char *search_str)
{
    char *start_search_ptr = &raw_data->data[raw_data->current_pos];
    size_t unconsumed_len = raw_data->data_len - raw_data->current_pos;
    char *search_str_ptr = memmem_custom(start_search_ptr, unconsumed_len, search_str, strlen(search_str));
    if (search_str_ptr == NULL) {
        ERROR("[Binary Decoder] Could not find search_str: %s in raw_data.\n", search_str);
        return STATE_NOT_FOUND;
    }

    // 获取search_str在字符串缓存中的下标
    size_t str_pos = search_str_ptr - &raw_data->data[raw_data->current_pos];
    size_t data_stream_offset = str_pos + strlen(search_str);
    if (!extract_prefix_bytes_string(raw_data, res, str_pos, data_stream_offset)) {
        ERROR("[Binary Decoder] Extract %zu length of raw_data failed.\n", str_pos);
        return STATE_INVALID;
    }
    return STATE_SUCCESS;
}


parse_state_t decoder_extract_prefix_ignore(struct raw_data_s *raw_data, size_t prefix_len)
{
    if ((raw_data->data_len - raw_data->current_pos) < prefix_len) {
        ERROR("[Binary Decoder] Buffer bytes are insufficient for decoder_extract_prefix_ignore.\n");
        return STATE_NEEDS_MORE_DATA;
    }
    parser_raw_data_offset(raw_data, prefix_len);
    return STATE_SUCCESS;
}
