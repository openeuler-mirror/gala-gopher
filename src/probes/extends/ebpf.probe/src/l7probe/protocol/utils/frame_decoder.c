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

#include "binary_decoder.h"
#include "frame_decoder.h"


parse_state_t decode_bool(struct raw_data_s *raw_data, bool *res)
{
    return decoder_extract_bool(raw_data, res);
}

parse_state_t decode_int8(struct raw_data_s *raw_data, int8_t *res)
{
    return decoder_extract_int8_t(raw_data, res);
}

parse_state_t decode_int16(struct raw_data_s *raw_data, int16_t *res)
{
    return decoder_extract_int16_t(raw_data, res);
}

parse_state_t decode_int32(struct raw_data_s *raw_data, int32_t *res)
{
    return decoder_extract_int32_t(raw_data, res);
}

parse_state_t decode_int64(struct raw_data_s *raw_data, int64_t *res)
{
    return decoder_extract_int64_t(raw_data, res);
}


parse_state_t decode_bytes_core(struct raw_data_s *raw_data, char **res, int32_t len)
{
    return decoder_extract_string(raw_data, res, len);
}

parse_state_t decode_unsigned_int_core(struct raw_data_s *raw_data, int64_t *res, u_int8_t max_length)
{
    const u_int8_t kFirstBitMask = 0x80;
    const u_int8_t kLastSevenBitMask = 0x7f;
    const u_int8_t kByteLength = 7;

    int64_t value = 0;
    for (int i = 0; i < max_length; i += kByteLength) {
        char char_res = 0;
        parse_state_t decode_status = decoder_extract_char(raw_data, &char_res);
        if (decode_status == STATE_SUCCESS) {
            u_int64_t b = (u_int64_t) char_res;
            if (!(b & kFirstBitMask)) {
                value |= (b << i);
                *res = value;
                return STATE_SUCCESS;
            }
            value |= ((b & kLastSevenBitMask) << i);
        }
    }
    return STATE_INVALID;
}

parse_state_t decode_unsigned_int(struct raw_data_s *raw_data, int32_t *res)
{
    const u_int8_t varint_max_length = 35;
    int64_t res_64 = 0;
    parse_state_t res_64_status = decode_unsigned_int_core(raw_data, &res_64, varint_max_length);
    if (res_64_status != STATE_SUCCESS) {
        ERROR("Extract Unsigned Varint failure.\n");
        return STATE_INVALID;
    }
    *res = (int32_t) res_64;
    return STATE_SUCCESS;
}

parse_state_t decode_string_int16(struct raw_data_s *raw_data, char **res)
{
    int16_t len;
    parse_state_t decode_status = decoder_extract_int16_t(raw_data, &len);
    if (decode_status != STATE_SUCCESS) {
        return STATE_INVALID;
    }
    return decode_bytes_core(raw_data, res, len);
}
