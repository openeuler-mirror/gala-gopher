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

#ifndef GALA_GOPHER_HTTP_PARSER_UTILS_H
#define GALA_GOPHER_HTTP_PARSER_UTILS_H

#include <sys/types.h>
#include <uthash.h>
#include <stdbool.h>
#include "hash.h"
#include "../model/http_msg_format.h"
#include "../model/multiple_map.h"

/**
 * htt header structure
 */
typedef struct http_header_t {
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
} http_header_t;

/**
 * http header filters
 * inclusions means the selected http message should matches all of the rules in inclusions
 * exclusions means the selected http message should not match any of the rules in exclusions
 */
struct http_header_filter {
    struct key_values_pair *inclusions;
    struct key_values_pair *exclusions;
};

/**
 * http chunked decoder structure
 */
struct http_chunked_decoder {
    size_t bytes_left_in_chunk; /* number of bytes left in current chunk */
    char consume_trailer;       /* if trailing headers should be consumed */
    char _hex_count;
    char _state;
};

/**
 * http_parse_request parameters
 */
typedef struct http_parse_req_param_t {
    const char *buf;
    size_t len;
    const char **method;
    size_t *method_len;
    const char **path;
    size_t *path_len;
    int *minor_version;
    struct http_header_t *headers;
    size_t *num_headers;
    size_t last_len;
} http_parse_req_param;

http_parse_req_param *init_http_parse_req_param();

void free_http_parse_req_param(http_parse_req_param * param);

/**
 * parse http request
 * returns number of bytes consumed if successful, -2 if request is partial,
 * -1 if failed
 *
 * @return
 */
int http_parse_request(http_parse_req_param *param);

//int http_parse_request(const char *buf, size_t len, const char **method, size_t *method_len, const char **path, size_t *path_len,
//                       int *minor_version, struct http_header_t *headers, size_t *num_headers, size_t last_len);

/**
 * http_parse_response parameters
 */
typedef struct http_parse_resp_param_t {
    const char *_buf;
    size_t len;
    int *minor_version;
    int *status;
    const char **msg;
    size_t *msg_len;
    struct http_header_t *headers;
    size_t *num_headers;
    size_t last_len;
} http_parse_resp_param;

/**
 * parse http response
 * returns number of bytes consumed if successful, -2 if response is partial,
 * -1 if failed
 *
 * @return
 */
int http_parse_response(http_parse_resp_param *param);

//int http_parse_response(const char *_buf, size_t len, int *minor_version, int *status, const char **msg, size_t *msg_len,
//                       struct http_header_t *headers, size_t *num_headers, size_t last_len);

/**
 * parse http headers
 * returns number of bytes consumed if successful, -2 if headers is partial,
 * -1 if failed
 *
 * @param buf
 * @param len
 * @param headers
 * @param num_headers
 * @param last_len
 * @return
 */
int http_parse_headers(const char *buf, size_t len, http_header_t *headers, size_t *num_headers, size_t last_len);

/**
 * decode chunked-encoding headers
 * when returns without an error, buf_size is updated to the length of the decoded data available,
 * when returns -2, application should repeatedly call the function,
 * when returns -1, it means an error.
 * if the end of the chunked-encoded data is found,
 * returns a non-negative number indicating the number of octets left un-decoded
 *
 * @param decoder
 * @param buf
 * @param buf_size
 * @return
 */
ssize_t http_decode_chunked(struct http_chunked_decoder *decoder, char *buf, size_t *buf_size);

/**
 * judge if chunked decoder is in middle of data
 *
 * @param decoder
 * @return
 */
int http_decode_chunked_is_in_data(struct http_chunked_decoder *decoder);

/**
  * parse http header filters
  *
  * @param filters
  * @return
  */
struct http_header_filter parse_http_header_filters(char* filters);

/**
  * judge if the header is matched with the filter
  * returns true if the header matches any filter
  *
  * @param http_headers
  * @param filter
  * @return
  */
bool matches_http_headers(const http_headers_map http_headers, const http_header_filter filter);

/**
 * judge if the content-type of http message is JSON
 *
 * @param message
 * @return
 */
bool is_json_content(http_header_t headers);

#endif // GALA_GOPHER_HTTP_PARSER_UTILS_H
