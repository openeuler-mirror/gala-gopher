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
 * Create: 2023-04-15
 * Description:
 ******************************************************************************/

#ifndef __PROTOCOL_COMMON_H__
#define __PROTOCOL_COMMON_H__

#pragma once

#include "data_stream.h"

/**
 * 拷贝raw_data_s。
 *
 * @param raw_data 字符串缓存
 * @return raw_data_s *
 */
struct raw_data_s *parser_copy_raw_data(struct raw_data_s *raw_data);

/**
 * 根据字符串初始化raw_data_s
 *
 * @param str 字符串首地址
 * @param str_len 字符串长度
 * @return struct raw_data_s *
 */
struct raw_data_s *init_raw_data_with_str(char *str, size_t str_len);

/**
 * 偏移字符串缓存raw_data当前首地址
 *
 * @param raw_data 字符串缓存
 * @param offset 偏移量
 */
void parser_raw_data_offset(struct raw_data_s *raw_data, size_t offset);

#endif
