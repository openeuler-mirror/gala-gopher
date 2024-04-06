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

#include "kafka_matcher.h"
#include "kafka_decoder.h"
#include "../utils/frame_decoder.h"
#include <string.h>

parse_state_t decode_fetch_resp(struct raw_data_s *resp_frame, int16_t api_version, size_t *error_count)
{
    int32_t throttle_time_ms;
    int16_t error_code;
    parse_state_t decode_status;
    if (api_version >= 1) {
        decode_status = decode_int32(resp_frame, &throttle_time_ms);
        if (decode_status != STATE_SUCCESS) {
            return STATE_INVALID;
        }
    }
    if (api_version >= 7) {
        decode_status = decode_int16(resp_frame, &error_code);
        if (decode_status != STATE_SUCCESS) {
            return STATE_INVALID;
        }

        if (error_code != None) {
            (*error_count)++;
        }
    }

    return STATE_SUCCESS;
}

parse_state_t handle_request(struct kafka_frame_s *req_frame, struct kafka_request_s *req)
{
    req->timestamp_ns = req_frame->timestamp_ns;
    req_frame->consumed = true;
    decode_req_header(req_frame->msg, req);

    return STATE_INVALID;
}

parse_state_t handle_response(struct kafka_frame_s *resp_frame, struct kafka_response_s *resp, enum kafka_api api_key,
                              int16_t api_version, size_t *error_count)
{
    resp->timestamp_ns = resp_frame->timestamp_ns;

    resp_frame->consumed = true;
    decode_resp_header(resp_frame->msg, resp, api_key, api_version);

    switch (api_key) {
        case Fetch:
            decode_fetch_resp(resp_frame->msg, api_version, error_count);
        default:
            break;
    }

    return STATE_INVALID;
}

struct kafka_record_s *
match_req_resp(struct kafka_frame_s *req_frame, struct kafka_frame_s *resp_frame, size_t *error_count)
{
    if (req_frame->timestamp_ns > resp_frame->timestamp_ns) {
        ERROR("[Kafka Match] Request frame timestamp is larger than response frame timestamp.\n");
        return NULL;
    }

    struct kafka_record_s *r = (struct kafka_record_s *)calloc(1, sizeof(struct kafka_record_s));
    if (r == NULL) {
        ERROR("[Kafka Match] Malloc kafka record failed.\n");
        return NULL;
    }
    parse_state_t decode_status = handle_request(req_frame, r->req);
    if (decode_status != STATE_SUCCESS) {
        free(r);
        ERROR("[Kafka Match] Failed to decode request frame.\n");
        return NULL;
    }
    decode_status = handle_response(resp_frame, r->resp, r->req->api, r->req->api_version, error_count);
    if (decode_status != STATE_SUCCESS) {
        free(r);
        ERROR("[Kafka Match] Failed to decode response frame.\n");
        return NULL;
    }
    return r;
}

void kafka_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *resp_frames, struct record_buf_s *buf)
{
    if (req_frames->frame_buf_size == 0 || resp_frames->frame_buf_size == 0) {
        return;
    }

    size_t error_count = 0;
    buf->err_count = 0;
    buf->record_buf_size = 0;
    buf->req_count = req_frames->frame_buf_size;
    buf->resp_count = resp_frames->frame_buf_size;

    // kafka 目前的 error_count仅考虑 Fetch 下的错误码，错误率计算采用 record 数量，后续改为 response 数量
    struct kafka_correlation_hash_t *correlation_id_map = NULL;

    // 遍历resp_frames，将correlation_id作为key，resp_frame作为value存入correlation_id_map
    for (int i = resp_frames->current_pos; i < resp_frames->frame_buf_size; i++) {
        struct kafka_frame_s *resp_frame = resp_frames->frames[i]->frame;
        correlation_id_map->correlation_id = resp_frame->correlation_id;
        H_ADD(correlation_id_map, correlation_id, sizeof(int), correlation_id_map);
    }

    // 遍历 req_frames, 从correlation_id_map中找到对应的resp_frame，然后进行匹配
    for (int i = req_frames->current_pos; i < req_frames->frame_buf_size; i++) {
        struct kafka_frame_s *req_frame = req_frames->frames[i]->frame;
        struct kafka_correlation_hash_t *matched_resp_frame = NULL;
        H_FIND_I(correlation_id_map, &req_frame->correlation_id, matched_resp_frame);
        if (matched_resp_frame == NULL) {
            ERROR("[Kafka Match Frames] No matched response frame found.\n");
            continue;
        }
        H_DEL(correlation_id_map, matched_resp_frame);
        struct kafka_record_s *record = match_req_resp(req_frame, matched_resp_frame->frame, &error_count);

        // 将匹配到的record存入record_buf
        if (record != NULL) {
            struct record_data_s *record_data = (struct record_data_s *) malloc(sizeof(struct record_data_s));
            if (record_data == NULL) {
                ERROR("[Kafka Match Frames] malloc record_data failed.\n");
                continue;
            }
            record_data->record = record;
            record_data->latency = record->resp->timestamp_ns - record->req->timestamp_ns;
            buf->records[buf->record_buf_size] = record_data;
            buf->record_buf_size++;
            req_frame->consumed = true;
            matched_resp_frame->frame->consumed = true;
        } else {
            ERROR("[Kafka Match Frames]: kafka match req and resp failed, correlation_id is %s\n",
                  req_frame->correlation_id);
            continue;
        }
    }

    // delete until find unconsumed request, need to avoid list drifting
    for (int pos = 0; pos < req_frames->frame_buf_size; ++pos) {
        struct kafka_frame_s *req_frame = req_frames->frames[pos]->frame;

        if (!req_frame->consumed) {
            req_frames->current_pos = pos;
            break;
        }
    }

    buf->err_count = error_count;
}
