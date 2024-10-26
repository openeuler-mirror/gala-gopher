/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: eank
 * Create: 2023/6/26
 * Description:
 ******************************************************************************/

#include "protocol_parser.h"
#include "pgsql/pgsql_msg_format.h"
#include "pgsql/pgsql_parser.h"
#include "pgsql/pgsql_matcher.h"
#include "http1.x/parser/http_parser.h"
#include "http1.x/matcher/http_matcher.h"
#include "kafka/kafka_msg_format.h"
#include "kafka/kafka_parser.h"
#include "kafka/kafka_matcher.h"
#include "redis/redis_parser.h"
#include "redis/redis_matcher.h"
#include "crpc/crpc_parser.h"

/**
 * Free record data
 *
 * @param type protocol type
 * @param record
 */
void free_record_data(enum proto_type_t type, struct record_data_s *record_data)
{
    if (record_data == NULL) {
        return;
    }
    if (record_data->record == NULL) {
        free(record_data);
        return;
    }

    switch (type) {
        case PROTO_PGSQL:
            free_pgsql_record((struct pgsql_record_s *) record_data->record);
            break;
        case PROTO_HTTP:
            free_http_record((http_record *) record_data->record);
            break;
            // todo: add protocols:
        case PROTO_HTTP2:
            break;
        case PROTO_REDIS:
            free_redis_record((struct redis_record_s *) record_data->record);
            break;
        case PROTO_KAFKA:
            free_kafka_record((struct kafka_record_s *) record_data->record);
            break;
        case PROTO_CRPC:
            free_crpc_record(record_data->record);
            break;
        case PROTO_MYSQL:
        case PROTO_MONGO:
        case PROTO_DNS:
        case PROTO_NATS:
        case PROTO_CQL:
        default:
            break;
    }
    free(record_data);
}

void free_frame_data_s(enum proto_type_t type, struct frame_data_s *frame)
{
    if (frame == NULL) {
        return;
    }
    if (frame->frame == NULL) {
        free(frame);
        return;
    }

    switch (type) {
        case PROTO_PGSQL:
            free_pgsql_regular_msg((struct pgsql_regular_msg_s *) frame->frame);
            break;
        case PROTO_HTTP:
            free_http_msg((http_message *) frame->frame);
            break;
        // todo: add protocols:
        case PROTO_HTTP2:
            break;
        case PROTO_REDIS:
            free_redis_msg((struct redis_msg_s *) frame->frame);
            break;
        case PROTO_KAFKA:
            free_kafka_frame((struct kafka_frame_s *) frame->frame);
            break;
        case PROTO_CRPC:
            free_crpc_msg(frame->frame);
            break;
        case PROTO_MYSQL:
        case PROTO_MONGO:
        case PROTO_DNS:
        case PROTO_NATS:
        case PROTO_CQL:
        default:
            break;
    }
    free(frame);
}

size_t proto_find_frame_boundary(enum proto_type_t type, enum message_type_t msg_type, struct raw_data_s *raw_data)
{
    size_t ret = 0;
    switch (type) {
        case PROTO_PGSQL:
            ret = pgsql_find_frame_boundary(raw_data);
            break;
        case PROTO_HTTP:
            ret = http_find_frame_boundary(msg_type, raw_data);
            break;
        case PROTO_HTTP2:
            break;
        case PROTO_REDIS:
            ret = redis_find_frame_boundary(raw_data);
            break;
        case PROTO_KAFKA:
//            ret = kafka_find_frame_boundary(msg_type, raw_data);
            break;
        case PROTO_MYSQL:
            break;
        case PROTO_MONGO:
            break;
        case PROTO_DNS:
            break;
        case PROTO_NATS:
            break;
        case PROTO_CQL:
            break;
        case PROTO_CRPC:
            ret = crpc_find_frame_boundary(raw_data);
            break;
        default:
            WARN("[PROTOCOL FIND BOUNDARY] Not Supported Protocol.\n");
            break;
    }
    return ret;
}

parse_state_t proto_parse_frame(enum proto_type_t type, enum message_type_t msg_type, struct raw_data_s *raw_data,
                                struct frame_data_s **frame_data)
{
    parse_state_t state = STATE_UNKNOWN;
    switch (type) {
        case PROTO_PGSQL:
            state = pgsql_parse_frame(raw_data, frame_data);
            break;
        case PROTO_HTTP:
            state = http_parse_frame(msg_type, raw_data, frame_data);
            break;
        case PROTO_HTTP2:
            break;
        case PROTO_REDIS:
            state = redis_parse_frame(msg_type, raw_data, frame_data);
            break;
        case PROTO_KAFKA:
//            state = kafka_parse_frame(msg_type, raw_data, frame_data);
            break;
        case PROTO_MYSQL:
            break;
        case PROTO_MONGO:
            break;
        case PROTO_DNS:
            break;
        case PROTO_NATS:
            break;
        case PROTO_CQL:
            break;
        case PROTO_CRPC:
            state = crpc_parse_frame(msg_type, raw_data, frame_data);
            break;
        default:
            WARN("[PROTOCOL PARSER] Not Supported Protocol.\n");
            break;
    }
    return state;
}

void proto_match_frames(enum proto_type_t type, struct frame_buf_s *req_frame, struct frame_buf_s *resp_frame,
                        struct record_buf_s *record_buf)
{
    if (req_frame == NULL || req_frame->frame_buf_size == 0 || resp_frame == NULL || resp_frame->frame_buf_size == 0) {
        return;
    }

    switch (type) {
        case PROTO_PGSQL:
            pgsql_match_frames(req_frame, resp_frame, record_buf);
            break;
        case PROTO_HTTP:
            http_match_frames(req_frame, resp_frame, record_buf);
            break;
        case PROTO_HTTP2:
            break;
        case PROTO_REDIS:
            redis_match_frames(req_frame, resp_frame, record_buf);
            break;
        case PROTO_KAFKA:
//            kafka_match_frames(req_frame, resp_frame, record_buf);
            break;
        case PROTO_MYSQL:
            break;
        case PROTO_MONGO:
            break;
        case PROTO_DNS:
            break;
        case PROTO_NATS:
            break;
        case PROTO_CQL:
            break;
        case PROTO_CRPC:
            crpc_match_frames(req_frame, resp_frame, record_buf);
            break;
        default:
            break;
    }
}
