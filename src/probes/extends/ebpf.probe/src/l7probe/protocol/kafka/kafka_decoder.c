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
 * Description: wrap the common decoder methods for kafka.
 *
 ******************************************************************************/


#include "../utils/frame_decoder.h"
#include "kafka_msg_format.h"

parse_state_t decode_tag_item(struct raw_data_s *data_stream_buf)
{
    int32_t tag;
    parse_state_t decode_status = decode_int32(data_stream_buf, &tag);
    if (decode_status != STATE_SUCCESS) {
        return STATE_INVALID;
    }

    int32_t len;
    decode_status = decode_unsigned_int(data_stream_buf, &len);
    if (decode_status != STATE_SUCCESS) {
        return STATE_INVALID;
    }

    char *res = NULL;
    return decode_bytes_core(data_stream_buf, &res, len);
}

parse_state_t decode_tags(struct raw_data_s *data_stream_buf, enum kafka_api api, int16_t version)
{
    if (!is_flexible(api, version)) {
        return STATE_SUCCESS;
    }

    int32_t tag_section_len;
    parse_state_t decode_status = decode_int32(data_stream_buf, &tag_section_len);
    if (decode_status != STATE_SUCCESS) {
        ERROR("Tag Section len decode failure.\n");
        return STATE_INVALID;
    }
    for (int i = 0; i < tag_section_len; ++i) {
        bool res = decode_tag_item(data_stream_buf);
        if (!res) {
            return STATE_INVALID;
        }
    }
    return STATE_SUCCESS;
}

parse_state_t decode_req_header(struct raw_data_s *data_stream_buf, struct kafka_request_s *req)
{
    int16_t api_key;
    parse_state_t decode_status = decode_int16(data_stream_buf, &api_key);
    if (decode_status != STATE_SUCCESS) {
        ERROR("API Key decode failure.\n");
        return STATE_INVALID;
    }
    req->api = (enum kafka_api) api_key;

    int16_t api_version;
    decode_status = decode_int16(data_stream_buf, &api_version);
    if (decode_status != STATE_SUCCESS) {
        ERROR("API Version decode failure.\n");
        return STATE_INVALID;
    }
    req->api_version = api_version;

    int32_t correlation_id;
    decode_status = decode_int32(data_stream_buf, &correlation_id);
    if (decode_status != STATE_SUCCESS) {
        ERROR("Correlation id decode failure.\n");
        return STATE_INVALID;
    }

    char **client_id = 0;
    decode_status = decode_string_int16(data_stream_buf, client_id);
    if (decode_status != STATE_SUCCESS) {
        ERROR("Client id decode failure.\n");
        return STATE_INVALID;
    }

    return decode_tags(data_stream_buf, req->api, req->api_version);
}

parse_state_t decode_resp_header(struct raw_data_s *data_stream_buf, struct kafka_response_s *resp,
                                 enum kafka_api api, int16_t api_version)
{
    int32_t correlation_id;
    parse_state_t decode_status = decode_int32(data_stream_buf, &correlation_id);
    if (decode_status != STATE_SUCCESS) {
        ERROR("Correlation id decode failure.\n");
        return STATE_INVALID;
    }
    return decode_tags(data_stream_buf, api, api_version);
}
