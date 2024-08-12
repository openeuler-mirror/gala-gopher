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
 * Description: post metrics
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include "http_client.h"

HttpClientMgr *g_client_mgr = NULL;
CURL* g_curl = NULL;

HttpClientMgr *InitHttpClientMgr(char *url)
{
    HttpClientMgr *mgr = NULL;

    mgr = (HttpClientMgr *)malloc(sizeof(HttpClientMgr));
    if (mgr == NULL) {
        return NULL;
    }

    (void)memset(mgr, 0, sizeof(HttpClientMgr));
    (void)snprintf(mgr->url, PATH_LEN, "%s", url);

    curl_global_init(CURL_GLOBAL_ALL);
    g_client_mgr = mgr;
    return mgr;
}

void HttpClientPost(char post_buf[], long post_len)
{
    if (g_client_mgr == NULL || post_buf == NULL || post_len == 0) {
        return;
    }

    CURL* handle = curl_easy_init();

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(handle, CURLOPT_URL, g_client_mgr->url);
    curl_easy_setopt(handle, CURLOPT_FORBID_REUSE, 0L);
    curl_easy_setopt(handle, CURLOPT_FRESH_CONNECT, 0L);
    curl_easy_setopt(handle, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(handle, CURLOPT_TCP_KEEPIDLE, 20L);
    curl_easy_setopt(handle, CURLOPT_TCP_KEEPINTVL, 10L);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 3L);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, post_buf);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, post_len);

    CURLcode res = curl_easy_perform(handle);
    if(res != CURLE_OK) {
        ERROR("[CURL]: curl post to %s failed: %s\n", g_client_mgr->url, curl_easy_strerror(res));
    }

    curl_easy_cleanup(handle);
    return;
}

void DestroyHttpClientMgr(HttpClientMgr *mgr)
{
    if (mgr == NULL) {
        return;
    }
    (void)free(mgr);

    curl_global_cleanup();
    return;
}