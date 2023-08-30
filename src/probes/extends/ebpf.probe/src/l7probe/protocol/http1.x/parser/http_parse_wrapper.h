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
 * Create: 2023/7/7
 * Description:
 ******************************************************************************/
#ifndef __HTTP_PARSE_WRAPPER_H__
#define __HTTP_PARSE_WRAPPER_H__

#include "../model/http_msg_format.h"
#include "picohttpparser.h"

/**
 * HTTP header
 */
typedef struct http_header_t {
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
} http_header;

http_header *init_http_header();

void free_http_header(http_header* header);

/**
 * HTTP Request
 */
typedef struct http_request {
    const char *method;
    size_t method_len;
    const char *path;
    size_t path_len;
    int minor_version;
    struct phr_header headers[MAX_HEADERS_SIZE];
    size_t num_headers;
} http_request;

/**
 * HTTP Response
 */
typedef struct http_response {
    const char *msg;
    size_t msg_len;
    int status;
    int minor_version;
    struct phr_header headers[MAX_HEADERS_SIZE];
    size_t num_headers;
} http_response;

/**
 * Parse http request header
 *
 * @param raw_data
 * @param req
 * @return
 */
size_t http_parse_request_headers(struct raw_data_s* raw_data, http_request* req);

/**
 * Parse http response header
 *
 * @param raw_data
 * @param resp
 * @return
 */
size_t http_parse_response_headers(struct raw_data_s* raw_data, http_response* resp);

/**
 * parse http headers from req.headers into http_headers_map
 *
 * @param headers
 * @param num_headers
 * @return
 */
http_headers_map *get_http_headers_map(struct phr_header* headers, size_t num_headers);

#endif // __HTTP_PARSE_WRAPPER_H__