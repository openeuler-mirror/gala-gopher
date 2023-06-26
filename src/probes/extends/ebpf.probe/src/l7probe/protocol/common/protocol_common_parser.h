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
#ifndef GALA_GOPHER_PROTOCOL_COMMON_PARSER_H
#define GALA_GOPHER_PROTOCOL_COMMON_PARSER_H

#include "../../include/l7.h"
#include "../../include/data_stream.h"
#include "../utils/parser_state.h"
#include "../utils/binary_decoder.h"
#include "../pgsql/pgsql_msg_format.h"
#include "../pgsql/pgsql_parser.h"
#include "../pgsql/pgsql_matcher.h"

/**
 * Free record data
 *
 * @param type protocol type
 * @param record_data
 */
void free_record_data(enum proto_type_t type, struct record_data_s *record_data);

/**
 * Free frame data structure
 *
 * @param frame frame data to be freed
 */
void free_frame_data_s(enum proto_type_t type, struct frame_data_s *frame);

/**
 * Find frame boundary for protocols
 *
 * @param type protocol type
 * @param msg_type message type
 * @param raw_data raw data
 * @return
 */
size_t proto_find_frame_boundary(enum proto_type_t type, enum message_type_t msg_type, struct raw_data_s *raw_data);

/**
 * Parse frame for protocols
 *
 * @param type protocol type
 * @param msg_type message type
 * @param raw_data raw data
 * @param frame_data frame data
 * @return
 */
parse_state_t proto_parse_frame(enum proto_type_t type, enum message_type_t msg_type, struct raw_data_s *raw_data,
                                struct frame_data_s **frame_data);

/**
 * Match req & resp frames into record for protocols
 *
 * @param type protocol type
 * @param req_frame req frame
 * @param resp_frame resp frame
 * @param record_buf record
 */
void proto_match_frames(enum proto_type_t type, struct frame_buf_s *req_frame, struct frame_buf_s *resp_frame,
                        struct record_buf_s **record_buf);


#endif // GALA_GOPHER_PROTOCOL_COMMON_PARSER_H
