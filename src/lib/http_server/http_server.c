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
#include <string.h>
#include <limits.h>

#include "http_server.h"

static struct bufferevent* http_server_bevcb_ssl(struct event_base *evbase, void *arg)
{
    SSL_CTX *ssl_ctx = (SSL_CTX *)arg;
    if (ssl_ctx == NULL) {
        return NULL;
    }

    SSL *ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        return NULL;
    }

    return bufferevent_openssl_socket_new(evbase, -1, ssl,
                                          BUFFEREVENT_SSL_ACCEPTING,
                                          BEV_OPT_CLOSE_ON_FREE);
}

static struct bufferevent* http_server_bevcb_nossl(struct event_base *evbase, void *arg)
{
    return bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE);
}

void http_server_reply_code(struct evhttp_request *req, int errorno)
{
    evhttp_send_reply(req, errorno, NULL, NULL);
}

void http_server_reply_message(struct evhttp_request *req, int resp_code, const char* message)
{
    struct evbuffer *evbuffer;
    char buf[HTTP_REPLY_MSG_LEN] = {0};


    if (resp_code == HTTP_OK) {
        (void)snprintf(buf, sizeof(buf), "{ \"result\": \"success\", \"message\":\"%s\" }\n", message);
    } else {
        (void)snprintf(buf, sizeof(buf), "{ \"result\": \"failed\", \"message\":\"%s\" }\n", message);
    }

    evbuffer = evbuffer_new();
    if (evbuffer == NULL) {
        return http_server_reply_code(req, HTTP_INTERNAL);
    }

    (void)evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    (void)evbuffer_add_printf(evbuffer, "%s", buf);
    evhttp_send_reply(req, resp_code, NULL, evbuffer);
    evbuffer_free(evbuffer);
}

void http_server_reply_buffer(struct evhttp_request *req, const char* resp_buf)
{
    struct evbuffer *evbuffer;

    evbuffer = evbuffer_new();
    if (evbuffer == NULL) {
        return http_server_reply_code(req, HTTP_INTERNAL);
    }

    (void)evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    (void)evbuffer_add_printf(evbuffer, "%s", resp_buf);
    evhttp_send_reply(req, HTTP_OK, NULL, evbuffer);
    evbuffer_free(evbuffer);
}

int http_get_request_uri_path(struct evhttp_request *req, char *path, int size)
{
    const char *uri = evhttp_request_get_uri(req);
    struct evhttp_uri *decoded = evhttp_uri_parse(uri);

    if (decoded == NULL) {
        return -1;
    }

    if (evhttp_uri_get_path(decoded) == NULL) {
        evhttp_uri_free(decoded);
        return -1;
    }

    path[0] = 0;
    snprintf(path, size, "%s", evhttp_uri_get_path(decoded));
    evhttp_uri_free(decoded);
    return 0;
}

void run_http_server_daemon(http_server_mgr_s *server_mgr)
{
    DEBUG("[%s] Start running, listening on %s:%d\n", server_mgr->name, server_mgr->bind_addr, server_mgr->port);
    // handling request here in a loop
    event_base_dispatch(server_mgr->evbase);
}

static void init_ssl_lib(void)
{
    (void)SSL_library_init();
    (void)OpenSSL_add_all_algorithms();
    (void)SSL_load_error_strings();
}

static int load_private_key(SSL_CTX *ctx, const char *name, const char *key_file)
{
    // If private key and encrypted key were both set, private key takes advance
    if (strlen(key_file)) {
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
            ERROR("[%s] Could not load private key, errno = %d\n", name, errno);
            return -1;
        }
        return 0;
    }

    return -1;
}

static int init_http_ssl_ctx(http_server_mgr_s *server_mgr,
                             const char *key_file,
                             const char *cert_file, const char *ca_file)
{
    SSL_CTX *ssl_ctx = NULL;

    init_ssl_lib();
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        ERROR("[%s] Could not create TLS context\n", server_mgr->name);
        return -1;
    }

    SSL_CTX_set_options(ssl_ctx,
                        SSL_OP_ALL | SSL_OP_NO_SSL_MASK |
                        SSL_OP_NO_COMPRESSION |
                        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TLSv1_3);

    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERROR("[%s] Could not read certificate file: %s\n", server_mgr->name, cert_file);
        goto err;
    }

    if (load_private_key(ssl_ctx, server_mgr->name, key_file) != 0) {
        goto err;
    }

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        ERROR("[%s] Could not verify private key file\n", server_mgr->name);
        goto err;
    }

    if (strlen(ca_file)) {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        if (SSL_CTX_load_verify_locations(ssl_ctx, ca_file, NULL) != 1) {
            ERROR("[%s] could not load ca file.\n", server_mgr->name);
            goto err;
        }
    }

    server_mgr->ssl_ctx = ssl_ctx;
    return 0;

err:
    if (ssl_ctx) {
        // clear private key from memory
        SSL_CTX_use_PrivateKey(ssl_ctx, NULL);

        SSL_CTX_free(ssl_ctx);
    }
    return -1;
}

static int check_http_server_realpath(char *path, size_t path_len)
{
    int ret;
    char real_path[PATH_MAX + 1];

    if (realpath(path, real_path) == NULL) {
        return -1;
    }

    ret = snprintf(path, path_len, "%s", real_path);
    if (ret < 0 || ret >= path_len) {
        return -1;
    }

    if (access(path, F_OK) == -1) {
        return -1;
    }
    return 0;
}


static int check_http_server_config(HttpServerConfig *config, const char *server_name)
{
    int port = config->port;

    if (port < GOPHER_MIN_PORT || port > GOPHER_MAX_PORT) {
        ERROR("[%s] port of server is out of range [%d, %d].\n", server_name, GOPHER_MIN_PORT, GOPHER_MAX_PORT);
        return -1;
    }

    if (config->sslAuth) {
        if (strlen(config->privateKey)) {
            if (check_http_server_realpath(config->privateKey, sizeof(config->privateKey))) {
                ERROR("[%s] failed to access private key file, err: %s\n", server_name, strerror(errno));
                return -1;
            }
        }

        if (strlen(config->privateKey) == 0) {
            ERROR("[%s] private key must not be empty\n", server_name);
            return -1;
        }

        if (strlen(config->certFile) == 0) {
            ERROR("[%s] certificate file must not be empty\n", server_name);
            return -1;
        }

        if (check_http_server_realpath(config->certFile, sizeof(config->certFile))) {
            ERROR("[%s] Can not access certificate file, err: %s\n", server_name, strerror(errno));
            return -1;
        }

        if (strlen(config->caFile) && check_http_server_realpath(config->certFile, sizeof(config->certFile))) {
            ERROR("[%s] Can not access CA file, err: %s\n", server_name, strerror(errno));
            return -1;
        }
    }

    return 0;
}


int init_http_server_mgr(http_server_mgr_s *server_mgr, HttpServerConfig *config)
{
    struct evhttp_bound_socket *handle;

    if (check_http_server_config(config, server_mgr->name)) {
        return -1;
    }

    server_mgr->port = config->port;
    (void)snprintf(server_mgr->bind_addr, sizeof(server_mgr->bind_addr), "%s", config->bindAddr);
    server_mgr->evbase = event_base_new();
    if (server_mgr->evbase == NULL) {
        ERROR("[%s] Failed to create base event mgr\n", server_mgr->name);
        return -1;
    }

    /* Note: do free in destroy_web_server_mgr() if error happens */
    server_mgr->evhttp = evhttp_new(server_mgr->evbase);
    if (server_mgr->evhttp == NULL) {
        ERROR("[%s] Failed to create http event mgr\n", server_mgr->name);
        return -1;
    }

    if (config->sslAuth) {
        if (init_http_ssl_ctx(server_mgr, config->privateKey,
                              config->certFile, config->caFile) == -1) {
            return -1;
        }
    }

    if (server_mgr->ssl_ctx) {
        evhttp_set_bevcb(server_mgr->evhttp, http_server_bevcb_ssl, server_mgr->ssl_ctx);
    } else {
        evhttp_set_bevcb(server_mgr->evhttp, http_server_bevcb_nossl, NULL);
    }

    evhttp_set_gencb(server_mgr->evhttp, server_mgr->req_handler, NULL);
    evhttp_set_allowed_methods(server_mgr->evhttp, server_mgr->allow_methods);

    handle = evhttp_bind_socket_with_handle(server_mgr->evhttp, server_mgr->bind_addr, server_mgr->port);
    if (handle == NULL) {
        ERROR("[%s] Failed to bind to addr %s, port %d, err=%s\n", server_mgr->name,
              server_mgr->bind_addr, server_mgr->port, strerror(errno));
        return - 1;
    }
    return 0;
}

void destroy_http_server_mgr(http_server_mgr_s *server_mgr)
{
    if (server_mgr == NULL) {
        return;
    }

    if (server_mgr->evbase) {
        event_base_free(server_mgr->evbase);
    }

    if (server_mgr->ssl_ctx) {
        // clear private key from memory
        SSL_CTX_use_PrivateKey(server_mgr->ssl_ctx, NULL);

        SSL_CTX_free(server_mgr->ssl_ctx);
        server_mgr->ssl_ctx = NULL;
    }

    if (server_mgr->evhttp) {
        evhttp_free(server_mgr->evhttp);
    }

    free(server_mgr);
}
