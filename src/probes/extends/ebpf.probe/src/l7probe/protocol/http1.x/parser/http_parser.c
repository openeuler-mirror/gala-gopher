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

#include "http_parser.h"

int parse_request(struct raw_data_s *raw_data, http_request* result) {
    return -1;
}

int parse_response(struct raw_data_s *raw_data, http_response* result) {
    return -1;
}
http_headers_map *get_http_headers_map(http_headers_map *headers, size_t num_headers) {
    return NULL;
}

parse_state_t http_parse_frame(enum message_type_t msg_type, struct raw_data_s *raw_data, struct frame_data_s **frame_data) {
    return STATE_UNKNOWN;
}

size_t http_find_frame_boundary(enum message_type_t msg_type, struct raw_data_s *raw_data)
{
    return -1;
}