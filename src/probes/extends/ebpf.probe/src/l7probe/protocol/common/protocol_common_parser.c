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

#include "protocol_common_parser.h"

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
            free_pgsql_record((struct pgsql_record_s *) record_data);
            break;
            // todo: add protocols:
        case PROTO_HTTP:
        case PROTO_HTTP2:
        case PROTO_REDIS:
        case PROTO_KAFKA:
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
            // todo: add protocols:
        case PROTO_HTTP:
        case PROTO_HTTP2:
        case PROTO_REDIS:
        case PROTO_KAFKA:
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
        case PROTO_HTTP2:
        case PROTO_REDIS:
        case PROTO_KAFKA:
        case PROTO_MYSQL:
        case PROTO_MONGO:
        case PROTO_DNS:
        case PROTO_NATS:
        case PROTO_CQL:
        default:
            break;
    }
    return ret;
}

parse_state_t proto_parse_frame(enum proto_type_t type, enum message_type_t msg_type, struct raw_data_s *raw_data,
                                struct frame_data_s **frame_data)
{
    parse_state_t state;
    switch (type) {
        case PROTO_PGSQL:
            state = pgsql_parse_frame(raw_data, frame_data);
            break;
        case PROTO_HTTP:
        case PROTO_HTTP2:
        case PROTO_REDIS:
        case PROTO_KAFKA:
        case PROTO_MYSQL:
        case PROTO_MONGO:
        case PROTO_DNS:
        case PROTO_NATS:
        case PROTO_CQL:
        default:
            break;
    }
    return state;
}

void proto_match_frames(enum proto_type_t type, struct frame_buf_s *req_frame, struct frame_buf_s *resp_frame,
                        struct record_buf_s **record_buf)
{
    switch (type) {
        case PROTO_PGSQL:
            pgsql_match_frames(req_frame, resp_frame, record_buf);
            break;
        case PROTO_HTTP:
        case PROTO_HTTP2:
        case PROTO_REDIS:
        case PROTO_KAFKA:
        case PROTO_MYSQL:
        case PROTO_MONGO:
        case PROTO_DNS:
        case PROTO_NATS:
        case PROTO_CQL:
        default:
            break;
    }
}