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
 * Create: 2023-11-27
 * Description: Lib for rest server and web server, implemented by libevent2
 ******************************************************************************/

#ifndef __GOPHER_HTTP_SERVER_H__
#define __GOPHER_HTTP_SERVER_H__

#include <stdint.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include "base.h"
#include "config.h"

#define HTTP_THREAD_NAME_LEN        16
#define HTTP_URL_PATH_LEN           64
#define HTTP_REPLY_MSG_LEN          128

//http error msg
#define HTTP_NOTFOUND_ERR_MSG       "url not found"
#define HTTP_BADMETHOD_ERR_MSG      "method not allowed"

typedef void (*request_handler_cb)(struct evhttp_request *, void *);

typedef struct {
    char name[HTTP_THREAD_NAME_LEN];
    uint16_t port;
    uint16_t allow_methods;
    request_handler_cb req_handler;
    char bind_addr[IP_STR_LEN];
    SSL_CTX *ssl_ctx;             // Indicate that if we enable https and client auth
    struct event_base *evbase;
    struct evhttp *evhttp;
    pthread_t tid;
} http_server_mgr_s;


void http_server_reply_code(struct evhttp_request *req, int errorno);
void http_server_reply_message(struct evhttp_request *req, int resp_code, const char* message);
void http_server_reply_buffer(struct evhttp_request *req, const char* resp_buf);
int http_get_request_uri_path(struct evhttp_request *req, char *path, int size);
void run_http_server_daemon(http_server_mgr_s *server_mgr);
int init_http_server_mgr(http_server_mgr_s *server_mgr, HttpServerConfig *config);
void destroy_http_server_mgr(http_server_mgr_s *server_mgr);
#endif