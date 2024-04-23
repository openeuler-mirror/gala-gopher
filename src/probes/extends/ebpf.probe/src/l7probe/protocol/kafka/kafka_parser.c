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
 * Description:
 *
 ******************************************************************************/

#include <string.h>
#include "../common/protocol_common.h"
#include "../utils/binary_decoder.h"
#include "kafka_parser.h"

// Kafka request/response format: https://kafka.apache.org/protocol.html#protocol_messages
parse_state_t kafka_parse_frame(enum message_type_t msg_type, struct raw_data_s *raw_data, struct frame_data_s **frame)
{
    if (msg_type == MESSAGE_UNKNOW) {
        ERROR("[Kafka] Unknown message type.\n");
        return STATE_IGNORE;
    }

    if (msg_type != MESSAGE_REQUEST && msg_type != MESSAGE_RESPONSE) {
        ERROR("[Kafka] Invalid message type.\n");
        return STATE_INVALID;
    }

    int min_frame_len = msg_type == MESSAGE_REQUEST ? KAFKA_MIN_REQ_FRAME_LENGTH : KAFKA_MIN_RESP_FRAME_LENGTH;

    // 判断raw_data的长度是否小于frame最小长度
    size_t raw_data_len = strlen(raw_data->data);
    if (raw_data_len < min_frame_len) {
        return STATE_NEEDS_MORE_DATA;
    }

    int32_t msg_length;
    parse_state_t decode_status = decoder_extract_int32_t(raw_data, &msg_length);
    if (decode_status != STATE_SUCCESS) {
        return STATE_INVALID;
    }

    // 判断msg_length + KAFKA_PAYLOAD_LENGTH是否小于min_frame_len
    if (msg_length + KAFKA_PAYLOAD_LENGTH < min_frame_len) {
        return STATE_INVALID;
    }

    if (msg_length > KAFKA_MAX_MESSAGE_LEN) {
        ERROR("[Kafka] Message length is too long.\n");
        return STATE_INVALID;
    }

    // 深拷贝一份当前buf（除payload描述之外的完整消息）
    struct raw_data_s *raw_data_copy = (struct raw_data_s *) malloc(sizeof(raw_data) + msg_length);
    if (raw_data_copy == NULL) {
        ERROR("[Kafka] Malloc raw data copy failed.\n");
        return STATE_INVALID;
    }
    memcpy(raw_data_copy->data, raw_data->data, msg_length);
    raw_data_copy->data_len = msg_length;
    raw_data_copy->current_pos = raw_data->current_pos;
    raw_data_copy->timestamp_ns = raw_data->timestamp_ns;

    enum kafka_api api_key;
    int16_t api_version;
    // 当msg_type为MESSAGE_REQUEST时，解析request_api_key和request_api_version
    if (msg_type == MESSAGE_REQUEST) {
        int16_t api_key_int;
        decode_status = decoder_extract_int16_t(raw_data, &api_key_int);
        if (decode_status != STATE_SUCCESS) {
            ERROR("[Kafka] Decode request key failed.\n");
            return STATE_INVALID;
        }
        api_key = (enum kafka_api) api_key_int;

        decode_status = decoder_extract_int16_t(raw_data, &api_version);
        if (decode_status != STATE_SUCCESS) {
            ERROR("[Kafka] Decode request version failed.\n");
            return STATE_INVALID;
        }

        if (!is_api_key_valid(api_key)) {
            ERROR("[Kafka] Decode request key is invalid.\n");
            return STATE_INVALID;
        }

        if (!is_api_version_support(api_key, api_version)) {
            ERROR("[Kafka] Decode request version is invalid.\n");
            return STATE_INVALID;
        }
    }

    // 解析correlation_id
    int32_t correlation_id;
    decode_status = decoder_extract_int32_t(raw_data, &correlation_id);
    if (decode_status != STATE_SUCCESS) {
        ERROR("[Kafka] Decode correlation id failed.\n");
        return STATE_INVALID;
    }

    if (correlation_id < 0) {
        ERROR("[Kafka] Decode correlation id is invalid.\n");
        return STATE_INVALID;
    }

    if (raw_data_len - KAFKA_PAYLOAD_LENGTH < msg_length) {
        INFO("[Kafka] Decode needs more data.\n");
        return STATE_NEEDS_MORE_DATA;
    }

    struct kafka_frame_s *kafka_frame = (struct kafka_frame_s *) malloc(sizeof(struct kafka_frame_s));
    if (kafka_frame == NULL) {
        ERROR("[Kafka] Malloc kafka frame failed.\n");
        return STATE_INVALID;
    }

    (*frame)->msg_type = msg_type;
    (*frame)->frame = kafka_frame;

    kafka_frame->correlation_id = correlation_id;
    kafka_frame->msg = raw_data_copy;
    kafka_frame->msg_len = msg_length;

    return STATE_SUCCESS;
}

size_t kafka_find_frame_boundary(enum message_type_t msg_type, struct raw_data_s *raw_data)
{
    size_t ori_pos = raw_data->current_pos;
    size_t raw_data_len = strlen(raw_data->data);
    size_t min_frame_len = (size_t)(msg_type == MESSAGE_REQUEST ? KAFKA_MIN_REQ_FRAME_LENGTH : KAFKA_MIN_RESP_FRAME_LENGTH);

    if (raw_data_len < min_frame_len) {
        return -1;
    }

    for (size_t i = raw_data->current_pos; i < raw_data_len - min_frame_len; ++i) {
        int32_t message_length;
        parse_state_t decode_status = decoder_extract_int32_t(raw_data, &message_length);
        if (decode_status != STATE_SUCCESS) {
            continue;
        }

        // Check message length
        if (message_length <= 0 || message_length + KAFKA_PAYLOAD_LENGTH > raw_data->data_len - raw_data->current_pos ||
            message_length + KAFKA_PAYLOAD_LENGTH < min_frame_len) {
            continue;
        }

        // Check for valid api_key and api_version in requests.
        if (msg_type == MESSAGE_REQUEST) {
            enum kafka_api api_key;
            int16_t api_key_int;
            int16_t api_version;

            decode_status = decoder_extract_int16_t(raw_data, &api_key_int);
            if (decode_status != STATE_SUCCESS) {
                continue;
            }
            api_key = (enum kafka_api) api_key_int;

            if (!is_api_key_valid(api_key)) {
                continue;
            }

            decode_status = decoder_extract_int16_t(raw_data, &api_version);
            if (decode_status != STATE_SUCCESS) {
                continue;
            }

            if (!is_api_version_support(api_key, api_version)) {
                continue;
            }
        }

        int32_t correlation_id;
        decode_status = decoder_extract_int32_t(raw_data, &correlation_id);
        if (decode_status != STATE_SUCCESS || correlation_id < 0) {
            continue;
        }

        return i;
    }

    // recover pos, pos will be updated on invocation
    raw_data->current_pos = ori_pos;
    return SIZE_MAX;
}
