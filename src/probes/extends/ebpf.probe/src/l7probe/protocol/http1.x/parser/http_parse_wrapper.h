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

/**
 * HTTP header
 */
typedef struct http_header {
    char *name;
    size_t name_len;
    char *value;
    size_t value_len;
} http_header;

/**
 * HTTP Request
 */
typedef struct http_request {
    char *method;
    size_t method_len;
    char *path;
    size_t path_len;
    int minor_version;
    http_header headers[MAX_HEADERS_SIZE];
    size_t num_headers;
} http_request;

/**
 * HTTP Response
 */
typedef struct http_response {
    char *msg;
    size_t msg_len;
    int status;
    int minor_version;
    http_header headers[MAX_HEADERS_SIZE];
    size_t num_headers;
} http_response;

/**
 * Parse http request header
 *
 * @param raw_data
 * @param req
 * @return
 */
int http_parse_request_headers(struct raw_data_s* raw_data, http_request* req);

/**
 * Parse http response header
 *
 * @param raw_data
 * @param resp
 * @return
 */
int http_parse_response_headers(struct raw_data_s* raw_data, http_response* resp);

/**
 * parse http headers from req.headers, get 1st value by key.
 */
int get_http_header_value_by_key(struct http_header headers[], size_t num_headers, char *key, char *value, int vlen_max);

#endif // __HTTP_PARSE_WRAPPER_H__