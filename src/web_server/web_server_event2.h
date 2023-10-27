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
 * Create: 2023-11-06
 * Description:
 ******************************************************************************/

#ifndef __WEB_SERVER_EVENT2_H__
#define __WEB_SERVER_EVENT2_H__

#include <stdint.h>
#include <pthread.h>

#include <openssl/ssl.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include "config.h"
#include "base.h"

typedef struct {
    uint16_t port;
    char bind_addr[IP_STR_LEN];
    SSL_CTX *ssl_ctx;             // Indicate that if we enable https and client auth
    struct event_base *evbase;
    struct evhttp *evhttp;
    pthread_t tid;
} web_server_mgr_s;

void run_web_server_daemon(web_server_mgr_s *web_server);
int init_web_server_mgr(web_server_mgr_s *web_server, WebServerConfig *config);
void destroy_web_server_mgr(web_server_mgr_s *web_server);
#endif

