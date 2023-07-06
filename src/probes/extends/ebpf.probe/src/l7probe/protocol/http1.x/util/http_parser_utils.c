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

#include "http_parser_utils.h"

http_parse_req_param *init_http_parse_req_param(void)
{
    return NULL;
}

void free_http_parse_req_param(http_parse_req_param * param)
{
}

int http_parse_request(http_parse_req_param *param)
{
    return -1;
}

int http_parse_response(http_parse_resp_param *param)
{
    return -1;
}

int http_parse_headers(const char *buf_start, size_t len, http_header *headers, size_t *num_headers, size_t last_len)
{
    return -1;
}

ssize_t http_decode_chunked(http_chunked_decoder *decoder, char *buf, size_t *buf_size)
{
    return -1;
}

int http_decode_chunked_is_in_data(struct http_chunked_decoder *decoder)
{
    return -1;
}

http_header_filter *parse_http_header_filters(char *filters) {
    return NULL;
}

bool is_json_content(http_header headers) {
    return false;
}

bool matches_http_headers(http_headers_map http_headers, const http_header_filter filter) {
    return false;
}
