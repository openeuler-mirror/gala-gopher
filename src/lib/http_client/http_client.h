/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wo_cow
 * Create: 2024-07-25
 * Description: header file of http_client
 ******************************************************************************/

#ifndef __HTTP_CLIENT_H__
#define __HTTP_CLIENT_H__

#include "config.h"

typedef struct http_client_mgr_s {
    char url[PATH_LEN];
} HttpClientMgr;

HttpClientMgr *InitHttpClientMgr(char *url);
void DestroyHttpClientMgr(HttpClientMgr *mgr);
void HttpClientPost(char post_buf[], long post_len);

#endif