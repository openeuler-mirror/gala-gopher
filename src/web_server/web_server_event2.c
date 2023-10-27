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

#include <event2/bufferevent_ssl.h>

#include "imdb.h"
#include "web_server_event2.h"

static int is_request_uri_invalid(struct evhttp_request *req)
{
    const char *uri;
    const char *path;
    struct evhttp_uri *decoded;

    uri = evhttp_request_get_uri(req);
    decoded = evhttp_uri_parse(uri);
    if (decoded == NULL) {
        return 1;
    }

    path = evhttp_uri_get_path(decoded);
    if (path == NULL || (strcmp(path, "/") && strcmp(path, "/metrics"))) {
        evhttp_uri_free(decoded);
        return 1;
    }

    evhttp_uri_free(decoded);
    return 0;
}


#if 0
static int is_bindaddr_invalid(const char *bind_addr)
{
    struct in_addr in_addr;
    int ret;

    if (bind_addr == NULL || strlen(bind_addr) == 0) {
        return 1;
    }

    ret = inet_aton(bind_addr, &in_addr);
    if (ret == 0 || in_addr.s_addr == INADDR_ANY) {
        return 1;
    }

    return 0;
}
#endif

static void web_server_reply_empty_metric(struct evhttp_request *req)
{
    evhttp_send_reply(req, HTTP_NOCONTENT, NULL, NULL);
}

static void web_server_reply_error(struct evhttp_request *req, int errorno)
{
    evhttp_send_reply(req, errorno, NULL, NULL);
}

static void web_server_request_handler(struct evhttp_request *req, void *arg)
{
    char log_file_name[256];
    struct evbuffer *evbuffer = NULL;
    struct stat buf;
    int fd;

    // Disallow any input data and any method except GET
    if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
        return web_server_reply_error(req, HTTP_BADREQUEST);
    }

    if (is_request_uri_invalid(req)) {
        return web_server_reply_error(req, HTTP_BADREQUEST);
    }

    // The log file may has not been created if we get here between que_get_next_file() and LOG4CPLUS_DEBUG_FMT()
    if (ReadMetricsLogs(log_file_name) < 0 || access(log_file_name, F_OK) == -1) {
        return web_server_reply_empty_metric(req);
    }

    fd = open(log_file_name, O_RDONLY);
    if (fd < 0) {
        ERROR("[WEBSERVER] Failed to open '%s': %s\n", log_file_name, strerror(errno));
        return web_server_reply_empty_metric(req);
    }

    if ((fstat(fd, &buf) == -1) || !S_ISREG(buf.st_mode)) {
        (void)close(fd);
        return web_server_reply_empty_metric(req);
    }

    evbuffer = evbuffer_new();
    if (evbuffer == NULL) {
        (void)close(fd);
        ERROR("[WEBSERVER] Failed to allocate reply buffer\n");
        return web_server_reply_error(req, HTTP_INTERNAL);
    }

    // evbuffer_add_file() is responsible for closing the fd
    if (evbuffer_add_file(evbuffer, fd, 0, buf.st_size)) {
        evbuffer_free(evbuffer);
        ERROR("[WEBSERVER] Error occurs when accessing metrics\n");
        return web_server_reply_error(req, HTTP_INTERNAL);
    }

    RemoveMetricsLogs(log_file_name);
    (void)evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "text/plain");
    evhttp_send_reply(req, HTTP_OK, NULL, evbuffer);
    evbuffer_free(evbuffer);
}

static struct bufferevent* web_server_bevcb_ssl(struct event_base *evbase, void *arg)
{
    SSL_CTX *ssl_ctx = (SSL_CTX *)arg;
    if (ssl_ctx == NULL) {
        return NULL;
    }

    return bufferevent_openssl_socket_new(evbase, -1, SSL_new(ssl_ctx),
                                          BUFFEREVENT_SSL_ACCEPTING,
                                          BEV_OPT_CLOSE_ON_FREE);
}

static struct bufferevent* web_server_bevcb_nossl(struct event_base *evbase, void *arg)
{
    return bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE);
}

void run_web_server_daemon(web_server_mgr_s *web_server)
{
    struct evhttp_bound_socket *handle;

    handle = evhttp_bind_socket_with_handle(web_server->evhttp, web_server->bind_addr, web_server->port);
    if (handle == NULL) {
        ERROR("[WEBSERVER] Failed to bind to addr %s, port %d", web_server->bind_addr, web_server->port);
        return;
    }

    DEBUG("[WEBSERVER] start running, listening on %s:%d", web_server->bind_addr, web_server->port);
    // handling request here in a loop
    event_base_dispatch(web_server->evbase);
}


#if 0
/* Create SSL_CTX. */
static SSL_CTX *web_server_init_ssl_ctx(const char *key_file, const char *cert_file) {
    SSL_CTX *ssl_ctx;

    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        ERROR("Could not create SSL/TLS context");
        return NULL;
    }
    SSL_CTX_set_options(ssl_ctx,
                        SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                        SSL_OP_NO_COMPRESSION |
                        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    EC_KEY *ecdh;
    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh) {
        errx(1, "EC_KEY_new_by_curv_name failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
    EC_KEY_free(ecdh);

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        errx(1, "Could not read private key file %s", key_file);
    }
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
        errx(1, "Could not read certificate file %s", cert_file);
    }

    return ssl_ctx;
}
#endif

int init_web_server_mgr(web_server_mgr_s *web_server, WebServerConfig *config)
{
    web_server->port = config->port;
    (void)snprintf(web_server->bind_addr, sizeof(web_server->bind_addr), "%s", config->bindAddr);
    web_server->evbase = event_base_new();
    if (web_server->evbase == NULL) {
        ERROR("[WEBSERVER] Failed to create base event mgr\n");
        return -1;
    }

    /* Note: do free in destroy_web_server_mgr() if error happens */
    web_server->evhttp = evhttp_new(web_server->evbase);
    if (web_server->evhttp == NULL) {
        ERROR("[WEBSERVER] Failed to create http event mgr\n");
        return -1;
    }

#if 0
    web_server->ssl_ctx = web_server_init_ssl_ctx(key_file, cert_file);
    if (web_server->evhttp == NULL) {
        ERROR("xxx");
        return NULL;
    }
#endif

    if (web_server->ssl_ctx) {
        evhttp_set_bevcb(web_server->evhttp, web_server_bevcb_ssl, web_server->ssl_ctx);
    } else {
        evhttp_set_bevcb(web_server->evhttp, web_server_bevcb_nossl, NULL);
    }

    evhttp_set_gencb(web_server->evhttp, web_server_request_handler, NULL);
    evhttp_set_allowed_methods(web_server->evhttp, EVHTTP_REQ_GET);
    return 0;
}


void destroy_web_server_mgr(web_server_mgr_s *web_server)
{
    if (web_server == NULL) {
        return;
    }

    if (web_server->evbase) {
        event_base_free(web_server->evbase);
    }

    if (web_server->ssl_ctx) {
        SSL_CTX_free(web_server->ssl_ctx);
    }

    if (web_server->evhttp) {
        evhttp_free(web_server->evhttp);
    }
    free(web_server);
}
