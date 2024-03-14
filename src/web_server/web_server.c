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
 * Create: 2023-10-28
 * Description:
 ******************************************************************************/

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

#include "imdb.h"
#include "web_server.h"
#include "http_server.h"


static int is_request_uri_invalid(struct evhttp_request *req)
{
    char path[HTTP_URL_PATH_LEN];

    if (http_get_request_uri_path(req, path, HTTP_URL_PATH_LEN)) {
        return 1;
    }

    if (strcmp(path, "/") && strcmp(path, "/metrics")) {
        return 1;
    }

    return 0;
}

static void web_server_request_handler(struct evhttp_request *req, void *arg)
{
    char log_file_name[256];
    struct evbuffer *evbuffer = NULL;
    struct stat buf;
    int fd;

    // Disallow any input data and any method except GET
    if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
        return http_server_reply_code(req, HTTP_BADMETHOD);
    }

    if (is_request_uri_invalid(req)) {
        return http_server_reply_code(req, HTTP_NOTFOUND);
    }

    // The log file may has not been created if we get here between que_get_next_file() and LOG4CPLUS_DEBUG_FMT()
    if (ReadMetricsLogs(log_file_name) < 0 || access(log_file_name, F_OK) == -1) {
        return http_server_reply_code(req, HTTP_NOCONTENT);
    }

    fd = open(log_file_name, O_RDONLY);
    if (fd < 0) {
        ERROR("[WEBSERVER] Failed to open '%s': %s\n", log_file_name, strerror(errno));
        return http_server_reply_code(req, HTTP_NOCONTENT);
    }

    if ((fstat(fd, &buf) == -1) || !S_ISREG(buf.st_mode)) {
        (void)close(fd);
        return http_server_reply_code(req, HTTP_NOCONTENT);
    }

    evbuffer = evbuffer_new();
    if (evbuffer == NULL) {
        (void)close(fd);
        ERROR("[WEBSERVER] Failed to allocate reply buffer\n");
        return http_server_reply_code(req, HTTP_INTERNAL);
    }

    // evbuffer_add_file() is responsible for closing the fd
    if (evbuffer_add_file(evbuffer, fd, 0, buf.st_size)) {
        evbuffer_free(evbuffer);
        ERROR("[WEBSERVER] Error occurs when accessing metrics\n");
        return http_server_reply_code(req, HTTP_INTERNAL);
    }

    RemoveMetricsLogs(log_file_name);
    (void)evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "text/plain");
    evhttp_send_reply(req, HTTP_OK, NULL, evbuffer);
    evbuffer_free(evbuffer);
}


int init_web_server_mgr(http_server_mgr_s *web_server, HttpServerConfig *config)
{
    (void)snprintf(web_server->name, HTTP_THREAD_NAME_LEN, "%s", "WEBSERVER");
    web_server->req_handler = web_server_request_handler;
    web_server->allow_methods = EVHTTP_REQ_GET;
    return init_http_server_mgr(web_server, config);
}
