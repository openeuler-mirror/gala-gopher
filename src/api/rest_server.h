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
 * Author: Vchanger
 * Create: 2023-04-11
 * Description: Restful API Server
 ******************************************************************************/
#ifndef __REST_SERVER_H__
#define __REST_SERVER_H__

#include <stdint.h>
#include <microhttpd.h>

#include "common.h"

#if MHD_VERSION < 0x00097002
#define MHD_Result   int
#else
#define MHD_Result   enum MHD_Result
#endif

typedef struct {
    uint16_t port;
    char sslAuth;
    struct MHD_Daemon *daemon;
} RestServer;

typedef struct {
    char *post_data;
    struct MHD_PostProcessor *postprocessor;
} RestRequest;

int RestServerStartDaemon(RestServer *restServer);
void RestServerDestroy(RestServer *restServer);
int RestServerSslInit(const char *privKey, const char *pubKey, const char *caFile);
#endif

