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
 * Create: 2023-04-20
 * Description:
 ******************************************************************************/
#ifndef GALA_GOPHER_HTTP_PARSER_H
#define GALA_GOPHER_HTTP_PARSER_H

#pragma once

#include "../../common/protocol_common.h"
#include "../model/http_msg_format.h"
#include "../model/multiple_map.h"
#include "../../utils/binary_decoder.h"
#include "../../utils/parser_state.h"

#include <algorithm>
#include <string>

#include "../decoder/http_body_decoder.h"
#include "../matcher/http_matcher.h"
#include "../../utils/message_type.h"
#include "../util/string_utils.h"
#include "../../../include/l7.h"

// const size_t kMaxNumHeaders = 50;
#define K_MAX_NUM_HEADERS 50;

/**
 * HTTP Request
 */
struct http_request {
    const char* method;
    size_t method_len;
    const char* path;
    size_t path_len;
    int minor_version;
    http_headers_map headers[K_MAX_NUM_HEADERS];
    // Set header number to maximum we can accept.
    // Pico will change it to the number of headers parsed for us.
    size_t num_headers;
};

/**
 * HTTP Response
 */
struct http_response {
    const char* msg;
    size_t msg_len;
    int status;
    int minor_version;
    http_headers_map headers[K_MAX_NUM_HEADERS];
    // Set header number to maximum we can accept.
    // Pico will change it to the number of headers parsed for us.
    size_t num_headers;
};

/**
 * Parse Request
 *
 * @param buf
 * @param result
 * @return
 */
int parse_request(struct raw_data_s *raw_data, http_request* result);

/**
 * Parse Response
 *
 * @param buf
 * @param result
 * @return
 */
int parse_response(struct raw_data_s *raw_data, http_response* result);

/**
 * Get HTTP Headers Map
 *
 * @param headers
 * @param num_headers
 * @return
 */
http_headers_map get_http_headers_map(const http_header* headers, size_t num_headers);

/**
 * Parses a single HTTP message from the input string.
 *
 * @param msg_type
 * @param raw_data
 * @param frame_data
 * @return
 */
parse_state_t http_parse_frame(enum message_type_t msg_type, struct raw_data_s *raw_data, struct frame_data_s **frame_data);

/**
 * Find frame boundary for HTTP raw_data
 *
 * @param msg_type
 * @param raw_data
 * @return
 */
size_t http_find_frame_boundary(enum message_type_t msg_type, struct raw_data_s *raw_data);

#endif // GALA_GOPHER_HTTP_PARSER_H
