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
 * Create: 2023-04-12
 * Description:
 ******************************************************************************/

#ifndef __BINARY_DECODER_H__
#define __BINARY_DECODER_H__

#pragma once

#include <stdbool.h>
#include "common.h"
#include "../../include/data_stream.h"

/**
 * 提取raw_data中的第一个字节，并填充至char型结果中。
 *
 * @param raw_data 原始数据缓存
 * @param res 提取char型结果的指针
 * @return 状态码
 */
parse_state_t decoder_extract_char(struct raw_data_s *raw_data, char *res);

#define BIG_ENDIAN_BYTES_TO_INT_FUNC(INT_TYPE) \
INT_TYPE big_endian_bytes_to_##INT_TYPE(const char *data_stream_buf)

// uint8_t big_endian_bytes_to_int8_t(const char *data_stream_buf)
BIG_ENDIAN_BYTES_TO_INT_FUNC(int8_t);

// uint16_t big_endian_bytes_to_int16_t(const char *data_stream_buf)
BIG_ENDIAN_BYTES_TO_INT_FUNC(int16_t);

// uint16_t big_endian_bytes_to_int32_t(const char *data_stream_buf)
BIG_ENDIAN_BYTES_TO_INT_FUNC(int32_t);

// uint8_t big_endian_bytes_to_uint8_t(const char *data_stream_buf)
BIG_ENDIAN_BYTES_TO_INT_FUNC(uint8_t);

// uint16_t big_endian_bytes_to_uint16_t(const char *data_stream_buf)
BIG_ENDIAN_BYTES_TO_INT_FUNC(uint16_t);

// uint32_t big_endian_bytes_to_uint32_t(const char *data_stream_buf)
BIG_ENDIAN_BYTES_TO_INT_FUNC(uint32_t);

#define DECODER_EXTRACT_INT_FUNC(INT_TYPE) \
parse_state_t decoder_extract_##INT_TYPE(struct raw_data_s *raw_data, INT_TYPE *res)

// parse_state_t decoder_extract_int8_t(raw_data_s *raw_data, int8_t *res)
DECODER_EXTRACT_INT_FUNC(int8_t);

// parse_state_t decoder_extract_int16_t(raw_data_s *raw_data, int16_t *res)
DECODER_EXTRACT_INT_FUNC(int16_t);

// parse_state_t decoder_extract_int32_t(raw_data_s *raw_data, int32_t *res)
DECODER_EXTRACT_INT_FUNC(int32_t);

// parse_state_t decoder_extract_uint8_t(raw_data_s *raw_data, uint8_t *res)
DECODER_EXTRACT_INT_FUNC(uint8_t);

// parse_state_t decoder_extract_uint16_t(raw_data_s *raw_data, uint16_t *res)
DECODER_EXTRACT_INT_FUNC(uint16_t);

// parse_state_t decoder_extract_uint32_t(raw_data_s *raw_data, uint32_t *res)
DECODER_EXTRACT_INT_FUNC(uint32_t);

/**
 * 提取整形数据宏
 *
 * @param int_type 整形类型（int8_t uint8_t int16_t uint16_t int32_t uint32_t）
 * @param raw_data_ptr 字符串缓存结构体raw_data_s指针
 * @param res_ptr 整形数据结果存放指针
 */
#define DECODER_EXTRACT_INT_WITH_INT_TYPE(int_type, raw_data_ptr, res_ptr) \
    decoder_extract_##int_type(raw_data_ptr, res_ptr)

/**
 * 从raw_data中提取decode_len长度子串，置于*res，并偏移raw_data指针。
 * NOTE：入参*res需要在堆上分配内存。
 *
 * @param raw_data 字符串缓存
 * @param decode_len 提取字符串的长度
 * @param data_stream_offset 字符串缓存区偏移量
 * @return bool
 */
bool extract_prefix_bytes_string(struct raw_data_s *raw_data, char **res, size_t decode_len, size_t data_stream_offset);

/**
 * 从raw_data中提取decode_len长度子串，置于**dst_raw_data，并偏移raw_data指针。
 *
 * @param src_raw_data 字符缓存
 * @param decode_len 提取字符串的长度
 * @param dst_raw_data 目的raw_data
 * @return parse_state_t
 */
parse_state_t decoder_extract_raw_data_with_len(struct raw_data_s *src_raw_data, size_t decode_len,
                                                struct raw_data_s **dst_raw_data);

/**
 * 从raw_data中提取decode_len长度子串，置于*res。
 * NOTE：入参*res需要在堆上分配内存。
 *
 * @param raw_data 字符串缓存
 * @param decode_len 提取字符串的长度
 * @return parse_state_t
 */
parse_state_t decoder_extract_string(struct raw_data_s *raw_data, char **res, size_t decode_len);

/**
 * 从字符串缓存起始位置提取子串，直到遇到search_char。如果不存在search_char，则返回NOT_FOUND。
 * NOTE：入参*res需要在堆上分配内存。
 *
 * @param raw_data 字符串缓存
 * @param search_char 停止字符
 * @return parse_state_t
 */
parse_state_t decoder_extract_str_until_char(struct raw_data_s *raw_data, char **res, char search_char);

/**
 * 从字符串缓存起始位置提取子串，直到遇到search_str。如果不存在search_str，则返回NOT_FOUND。
 * NOTE：入参*res需要在堆上分配内存。
 *
 * @param raw_data 字符串缓存
 * @param search_str 停止字符串标识
 * @return parse_state_t
 */
parse_state_t decoder_extract_str_until_str(struct raw_data_s *raw_data, char **res, const char *search_str);

/**
 * 跳过raw_data前prefix_len字节的字符。
 *
 * @param raw_data 字符串缓存
 * @param prefix_len 跳过字节数
 * @return parse_state_t，若raw_data长度不足prefix_len，则返回STATE_NEEDS_MORE_DATA
 */
parse_state_t decoder_extract_prefix_ignore(struct raw_data_s *raw_data, size_t prefix_len);

#endif
