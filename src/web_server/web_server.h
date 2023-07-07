/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Hubble_Zhu
 * Create: 2021-04-12
 * Description:
 ******************************************************************************/
#ifndef __WEB_SERVER_H__
#define __WEB_SERVER_H__

#pragma once

#include <stdint.h>
#include <semaphore.h>
#include <microhttpd.h>

#include "imdb.h"
#include "base.h"

typedef struct {
    uint16_t port;

    struct MHD_Daemon *daemon;
} WebServer;

WebServer *WebServerCreate(uint16_t port);
void WebServerDestroy(WebServer *webServer);
int WebServerStartDaemon(WebServer *webServer);

#endif

