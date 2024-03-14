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
 * Author: Vchanger
 * Create: 2023-12-05
 * Description: Restful API Server
 ******************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "rest_server.h"
#include "probe_mng.h"

#define PUT_DATA_KEY          "json="
#define ITER_BUFFER_SIZE       512
#define PUT_BUFFER_SIZE        (1024 * 1024)   // max post data size

static void rest_handle_put_request(struct evhttp_request *req, const char *path)
{
    struct evbuffer *evbuf;
    char iter_buf[ITER_BUFFER_SIZE];
    char *put_data;
    char *json_data;
    int offset = 0, read_len;

    evbuf = evhttp_request_get_input_buffer(req);
    if (evbuf == NULL) {
        return http_server_reply_code(req, HTTP_BADREQUEST);
    }

    /* use heap here to prevent stack overflow */
    put_data = calloc(1, PUT_BUFFER_SIZE + 1);
    if (put_data == NULL){
        return http_server_reply_code(req, HTTP_INTERNAL);
    }

    while (evbuffer_get_length(evbuf)) {
        read_len = evbuffer_remove(evbuf, iter_buf, sizeof(iter_buf));
        if (read_len <= 0) {
            break;
        }
        if (offset + read_len > PUT_BUFFER_SIZE) {
            PARSE_ERR("put data size exceeds %d", PUT_BUFFER_SIZE);
            goto err;
        }
        strncpy(put_data + offset, iter_buf, read_len);
        offset += read_len;
        put_data[offset] = 0;
    }

    if (strncmp(put_data, PUT_DATA_KEY, strlen(PUT_DATA_KEY))) {
        PARSE_ERR("put data must start with %s", PUT_DATA_KEY);
        goto err;
    }

    path++;  // skip prefix "/"
    json_data = put_data + strlen(PUT_DATA_KEY);
    if (parse_probe_json(path, json_data) == 0) {
        free(put_data);
        return http_server_reply_message(req, HTTP_OK, "New config takes effect");
    }

err:
    free(put_data);
    return http_server_reply_message(req, HTTP_BADREQUEST, g_parse_json_err);
}

static void rest_handle_get_request(struct evhttp_request *req, const char *path)
{
    int ret;
    char *buf;
    struct evbuffer *evbuffer = NULL;

    path++;   // skip prefix "/"
    buf = get_probe_json(path);
    if (buf == NULL) {
        return http_server_reply_message(req, HTTP_NOTFOUND, HTTP_NOTFOUND_ERR_MSG);
    }

    http_server_reply_buffer(req, buf);
    free(buf);
}

static void rest_server_request_handler(struct evhttp_request *req, void *arg)
{
    enum evhttp_cmd_type method;
    char path[HTTP_URL_PATH_LEN];

    if (http_get_request_uri_path(req, path, HTTP_URL_PATH_LEN)) {
        return http_server_reply_code(req, HTTP_BADREQUEST);
    }

    /* request url path must /xxx */
    if (strlen(path) <= 1) {
        return http_server_reply_message(req, HTTP_NOTFOUND, HTTP_NOTFOUND_ERR_MSG);
    }

    method = evhttp_request_get_command(req);
    if (method == EVHTTP_REQ_GET) {
        return rest_handle_get_request(req, path);
    }

    if (method == EVHTTP_REQ_PUT) {
        return rest_handle_put_request(req, path);
    }

    http_server_reply_message(req, HTTP_BADMETHOD, HTTP_BADMETHOD_ERR_MSG);
}


int init_rest_server_mgr(http_server_mgr_s *rest_server, HttpServerConfig *config)
{
    (void)snprintf(rest_server->name, HTTP_THREAD_NAME_LEN, "%s", "RESTSERVER");
    rest_server->req_handler = rest_server_request_handler;
    rest_server->allow_methods = EVHTTP_REQ_GET | EVHTTP_REQ_PUT;
    return init_http_server_mgr(rest_server, config);
}