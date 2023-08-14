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

#include <string.h>
#include "http_parse_wrapper.h"
#include "../model/multiple_map.h"

size_t http_parse_request_headers(struct raw_data_s* raw_data, http_request* req)
{
    DEBUG("[HTTP1.x PARSER WRAPPER] Parse request, data_len: %d, current_pos: %d, data:\n %s\n", raw_data->data_len,
         raw_data->current_pos, raw_data->data);
    memset(req, 0, sizeof(http_request));
    req->num_headers = MAX_HEADERS_SIZE;
    char *buf = &raw_data->data[raw_data->current_pos];
    size_t buf_size = raw_data->data_len;

    size_t ret = phr_parse_request(buf, buf_size, &req->method, &req->method_len, &req->path, &req->path_len,
                                   &req->minor_version, req->headers, &req->num_headers, /*last_len*/ 0);
    return ret;
}

size_t http_parse_response_headers(struct raw_data_s* raw_data, http_response* resp)
{
    DEBUG("[HTTP1.x PARSER WRAPPER] Parse response, data_len: %d, current_pos: %d, data:\n %s\n", raw_data->data_len,
         raw_data->current_pos, raw_data->data);
    memset(resp, 0, sizeof(http_response));
    resp->num_headers = MAX_HEADERS_SIZE;
    char *buf = &raw_data->data[raw_data->current_pos];
    size_t buf_size = raw_data->data_len;

    size_t ret = phr_parse_response(buf, buf_size, &resp->minor_version, &resp->status, &resp->msg,
                                    &resp->msg_len, resp->headers, &resp->num_headers,/*last_len*/ 0);
    return ret;
}

http_headers_map *get_http_headers_map(struct phr_header* headers, size_t num_headers)
{
    DEBUG("[HTTP1.x PARSER WRAPPER][Get Http Headers] Num_headers: %d\n", num_headers);
    http_headers_map *headers_map = NULL;
    for (size_t i = 0; i < num_headers; i++) {
        char name[headers[i].name_len + 1];
        char value[headers[i].value_len + 1];
        strncpy(name, headers[i].name, headers[i].name_len);
        strncpy(value, headers[i].value, headers[i].value_len);
        name[headers[i].name_len] = '\0';
        value[headers[i].value_len] = '\0';
        insert_into_multiple_map(&headers_map, name, value);
    }
    return headers_map;
}

struct phr_header *init_phr_header()
{
    struct phr_header *header = (struct phr_header *) malloc(sizeof(struct phr_header));
    if (header == NULL) {
        ERROR("[HTTP1.x PARSER WRAPPER] Failed to malloc phr_header.\n");
        return NULL;
    }
    memset(header, 0, sizeof(struct phr_header));
    return header;
}

void free_phr_header(struct phr_header* header)
{
    if (header == NULL) {
        return;
    }
    free(header);
}

http_header *init_http_header()
{
    http_header *header = (http_header *) malloc(sizeof(http_header));
    if (header == NULL) {
        ERROR("[HTTP1.x PARSER WRAPPER] Failed to malloc http_header.\n");
        return NULL;
    }
    memset(header, 0, sizeof(http_header));
    return header;
}

void free_http_header(http_header* header)
{
    if (header == NULL) {
        return;
    }
    free(header);
}

http_request *init_http_request(void)
{
    http_request *req = (http_request *) malloc(sizeof(http_request));
    if (req == NULL) {
        ERROR("[HTTP1.x PARSER WRAPPER] Failed to malloc http_request.\n");
        return NULL;
    }
    memset(req, 0, sizeof(http_request));
    req->minor_version = -1;
    req->num_headers = MAX_HEADERS_SIZE;
    return req;
}

void free_http_request(http_request* req)
{
    if (req == NULL) {
        return;
    }
    if (req->headers != NULL) {
        free_phr_header(req->headers);
    }
    free(req);
}

http_response *init_http_response(void)
{
    http_response *resp = (http_response *) malloc(sizeof(http_response));
    if (resp == NULL) {
        ERROR("[HTTP1.x PARSER WRAPPER] Failed to malloc http_response.\n");
        return NULL;
    }
    memset(resp, 0, sizeof(http_response));
    resp->minor_version = -1;
    resp->num_headers = MAX_HEADERS_SIZE;
    return resp;
}

void free_http_response(http_response* resp)
{
    if (resp == NULL) {
        return;
    }
    if (resp->headers != NULL) {
        free_phr_header(resp->headers);
    }
    free(resp);
}
