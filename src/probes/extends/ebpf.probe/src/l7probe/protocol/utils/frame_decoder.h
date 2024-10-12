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
 * Author: shiaigang
 * Create: 2023-06-07
 * Description: wrap the common decoder methods.
 *
 ******************************************************************************/


#ifndef __FRAME_DECODER_H__
#define __FRAME_DECODER_H__
#pragma once
#include <stdbool.h>
#include "data_stream.h"

parse_state_t decode_bool(struct raw_data_s *raw_data, bool *res);

parse_state_t decode_int8(struct raw_data_s *raw_data, int8_t *res);

parse_state_t decode_int16(struct raw_data_s *raw_data, int16_t *res);

parse_state_t decode_int32(struct raw_data_s *raw_data, int32_t *res);

parse_state_t decode_int64(struct raw_data_s *raw_data, int64_t *res);

parse_state_t decode_unsigned_int(struct raw_data_s *raw_data, int32_t *res);

parse_state_t decode_bytes_core(struct raw_data_s *raw_data, char **res, int32_t len);

parse_state_t decode_unsigned_int_core(struct raw_data_s *raw_data, int64_t *res, u_int8_t max_length);

parse_state_t decode_string_int16(struct raw_data_s *raw_data, char **res);

#endif