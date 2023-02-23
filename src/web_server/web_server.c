/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "web_server.h"


#if GALA_GOPHER_INFO("inner func")
static int WebRequestCallback(void *cls,
                              struct MHD_Connection *connection,
                              const char *url,
                              const char *method,
                              const char *version,
                              const char *upload_data,
                              const size_t *upload_data_size,
                              void **ptr);
#endif

static int WebRequestCallback(void *cls,
                              struct MHD_Connection *connection,
                              const char *url,
                              const char *method,
                              const char *version,
                              const char *upload_data,
                              const size_t *upload_data_size,
                              void **ptr)
{
    static int dummy;
    char log_file_name[256];
    struct MHD_Response *response;
    int ret, fd;
    struct stat buf;

    if (strcmp(method, "GET") != 0) {
        return MHD_NO;
    }

    if (*ptr != &dummy) {
        *ptr = &dummy;
        return MHD_YES;
    }
    *ptr = NULL;

    if (*upload_data_size != 0) {
        return MHD_NO;
    }

    if (ReadMetricsLogs(log_file_name) < 0) {
        return MHD_NO;
    }

    fd = open(log_file_name, O_RDONLY);
    if (fd < 0) {
        ERROR("Failed to open '%s': %s\n", log_file_name, strerror(errno));
        return MHD_NO;
    }
    if ((fstat(fd, &buf) == -1) || !S_ISREG(buf.st_mode)) {
        (void)close(fd);
        return MHD_NO;
    }

    response = MHD_create_response_from_fd((u64)buf.st_size, fd);
    if (response == NULL) {
        (void)close(fd);
        return MHD_NO;
    }

    RemoveMetricsLogs(log_file_name);

    ret = MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain");
    if (ret == MHD_NO) {
        MHD_destroy_response(response);
        return MHD_NO;
    }

    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    if (ret != MHD_YES) {
        MHD_destroy_response(response);
        return MHD_NO;
    }

    MHD_destroy_response(response);
    return ret;
}

WebServer *WebServerCreate(uint16_t port)
{
    WebServer *server = NULL;
    server = (WebServer *)malloc(sizeof(WebServer));
    if (server == NULL) {
        return NULL;
    }
    memset(server, 0, sizeof(WebServer));

    server->port = port;
    return server;
}

void WebServerDestroy(WebServer *webServer)
{
    if (webServer == NULL) {
        return;
    }

    if (webServer->daemon != NULL) {
        MHD_stop_daemon(webServer->daemon);
    }

    free(webServer);
    return;
}

int WebServerStartDaemon(WebServer *webServer)
{
#if MHD_VERSION < 0x00095300
    webServer->daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
#else
    webServer->daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD,
#endif
                                         webServer->port,
                                         NULL,
                                         NULL,
                                         &WebRequestCallback,
                                         NULL,
                                         MHD_OPTION_END);
    if (webServer->daemon == NULL) {
        return -1;
    }

    return 0;
}

