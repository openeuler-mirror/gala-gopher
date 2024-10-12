/*******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Vchanger
 * Create: 2024-10-10
 * Description:
 ******************************************************************************/
#include <arpa/inet.h>
#include "../../include/data_stream.h"
#include "../utils/binary_decoder.h"
#include "crpc_internal.h"
#include "crpc_parser.h"

void free_crpc_msg(void *frame)
{
    struct crpc_message_s *crpc_msg = (struct crpc_message_s *)frame;
    free(crpc_msg);
}

static parse_state_t crpc_validate_tech_header(struct raw_data_s *raw_data, u16 head_len, u32 message_len)
{
    if (head_len >= message_len || raw_data->data_len > message_len) {
        return STATE_INVALID;
    }

    if (raw_data->data_len < message_len) {
        return STATE_NEEDS_MORE_DATA;
    }

    return STATE_SUCCESS;
}

static parse_state_t crpc_parse_tech_header(struct raw_data_s *raw_data, struct crpc_message_s *crpc_msg)
{
    parse_state_t state;
    u32 message_len;
    u16 head_len;

    raw_data->current_pos += CRPC_HEADER_BEGIN_FLAG_LEN;  // skip two bytes of beginFlag
    state = decoder_extract_u_int32_t(raw_data, &message_len);
    if (state != STATE_SUCCESS) {
        return STATE_NEEDS_MORE_DATA;
    }
    message_len += CRPC_HEADER_MSGLEN_OFFSET;

    state = decoder_extract_u_int16_t(raw_data, &head_len);
    if (state != STATE_SUCCESS) {
        return STATE_NEEDS_MORE_DATA;
    }
    head_len += CRPC_HEADER_HEADLEN_OFFSET;

    state = decoder_extract_prefix_ignore(raw_data, CRPC_HEADER_HEADVER_LEN + CRPC_HEADER_PROPERTY_LEN);
    if (state != STATE_SUCCESS) {
        return STATE_NEEDS_MORE_DATA;
    }

    state = decoder_extract_char_array(raw_data, crpc_msg->request_id, sizeof(crpc_msg->request_id));
    if (state != STATE_SUCCESS) {
        return STATE_NEEDS_MORE_DATA;
    }

    state = crpc_validate_tech_header(raw_data, head_len, message_len);
    if (state != STATE_SUCCESS) {
        return state;
    }

    crpc_msg->message_len = message_len;
    crpc_msg->head_len = head_len;
    return STATE_SUCCESS;
}

// TODO: parse repsonse code to get error_count
static parse_state_t crpc_parse_response_code(struct raw_data_s *raw_data, struct crpc_message_s *crpc_msg)
{
    return STATE_SUCCESS;
}

/* See __get_crpc_type() for crpc header fmt */
static parse_state_t __do_crpc_parse_frame(enum message_type_t msg_type, struct raw_data_s *raw_data,
                                           struct crpc_message_s *crpc_msg)
{
    size_t pos = raw_data->current_pos;
    parse_state_t state;

    state = crpc_parse_tech_header(raw_data, crpc_msg);
    if (state != STATE_SUCCESS) {
        goto err;
    }

    if (msg_type == MESSAGE_RESPONSE) {
        state = crpc_parse_response_code(raw_data, crpc_msg);
        if (state != STATE_SUCCESS) {
            goto err;
        }
    }
    crpc_msg->timestamp_ns = raw_data->timestamp_ns;
    raw_data->current_pos = raw_data->data_len;
    return STATE_SUCCESS;

err:
    raw_data->current_pos = pos;
    return state;
}

size_t crpc_find_frame_boundary(struct raw_data_s *raw_data)
{
    if (raw_data->data_len < CRPC_REQUEST_HEADER_MIN_LEN) {
        return PARSER_INVALID_BOUNDARY_INDEX;
    }

    for (size_t i = raw_data->current_pos; i < raw_data->data_len - 1; ++i) {
        if (raw_data->data[i] == CRPC_HEADER_BEGIN_FLAG1 &&
            raw_data->data[i + 1] == CRPC_HEADER_BEGIN_FLAG2) {
            return i;
        }
    }
    return PARSER_INVALID_BOUNDARY_INDEX;
}

parse_state_t crpc_parse_frame(enum message_type_t msg_type, struct raw_data_s *raw_data, struct frame_data_s **frame_data)
{
    parse_state_t state;
    struct crpc_message_s *crpc_msg = (struct crpc_message_s *)calloc(1, sizeof(struct crpc_message_s));
    if (crpc_msg == NULL) {
        CRPC_ERROR("Failed to malloc crpc message.\n");
        return STATE_INVALID;
    }

    state = __do_crpc_parse_frame(msg_type, raw_data, crpc_msg);
    if (state != STATE_SUCCESS) {
        free(crpc_msg);
        return state;
    }

    *frame_data = (struct frame_data_s *)malloc(sizeof(struct frame_data_s));
    if ((*frame_data) == NULL) {
        CRPC_ERROR("Failed to malloc frame data.\n");
        free(crpc_msg);
        return STATE_INVALID;
    }

    (*frame_data)->frame = crpc_msg;
    (*frame_data)->msg_type = msg_type;
    (*frame_data)->timestamp_ns = crpc_msg->timestamp_ns;
    return state;
}


void free_crpc_record(void *record)
{
    struct crpc_record_s *crpc_record = (struct crpc_record_s *)record;
    free(crpc_record);
}


static void crpc_matcher_add_record(struct crpc_record_s *match_record, struct record_buf_s *record_buf)
{
    struct crpc_record_s *record;

    if (match_record->req_msg == NULL || match_record->resp_msg == NULL) {
        CRPC_ERROR("Failed to find matched request of one response\n");
        return;
    }

    if (record_buf->record_buf_size >= RECORD_BUF_SIZE) {
        CRPC_WARN("The record buffer is full.\n");
        return;
    }

    record = (struct crpc_record_s *)malloc(sizeof(struct crpc_record_s));
    if (record == NULL) {
        CRPC_ERROR("Failed to malloc crpc record.\n");
        return;
    }
    record->req_msg = match_record->req_msg;
    record->resp_msg = match_record->resp_msg;

    struct record_data_s *record_data = (struct record_data_s *)malloc(sizeof(struct record_data_s));
    if (record_data == NULL) {
        CRPC_ERROR("Failed to malloc record data.\n");
        free_crpc_record(record);
        return;
    }
    record_data->record = record;
    record_data->latency = record->resp_msg->timestamp_ns - record->req_msg->timestamp_ns;

    // TODO: calculate error count;
    record_buf->records[record_buf->record_buf_size] = record_data;
    record_buf->record_buf_size++;
}

void crpc_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *resp_frames, struct record_buf_s *record_buf)
{
    struct crpc_record_s crpc_record;
    struct crpc_message_s *crpc_req_msg, *crpc_resp_msg;

    // We suppose the amount of req is larger than or equals to the one of resp, so all resp should be matched
    for (size_t i = 0; i < resp_frames->frame_buf_size; ++i) {
        memset(&crpc_record, 0, sizeof(struct crpc_record_s));
        crpc_resp_msg = (struct crpc_message_s *)resp_frames->frames[i]->frame;
        crpc_record.resp_msg = crpc_resp_msg;

        for (size_t j = 0; j < req_frames->frame_buf_size; ++j) {
            crpc_req_msg = (struct crpc_message_s *)req_frames->frames[j]->frame;
            if (crpc_req_msg->matched == 0 &&
                strncpy(crpc_req_msg->request_id, crpc_resp_msg->request_id, sizeof(crpc_req_msg->request_id)) == 0 &&
                crpc_req_msg->timestamp_ns < crpc_resp_msg->timestamp_ns) {
                crpc_record.req_msg = crpc_req_msg;
                crpc_req_msg->matched = 1;
                break;
            }
        }

        crpc_matcher_add_record(&crpc_record, record_buf);
        resp_frames->current_pos++;
    }

    for (size_t i = 0; i < req_frames->frame_buf_size; ++i) {
        crpc_req_msg = (struct crpc_message_s *)req_frames->frames[i]->frame;
        if (crpc_req_msg->matched) {
            req_frames->current_pos = i;
        }
    }

    record_buf->req_count = req_frames->current_pos;
    record_buf->resp_count = resp_frames->current_pos;
}