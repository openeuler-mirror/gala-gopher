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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "rest_server.h"
#include "probe_mng.h"

#define REST_RESPONSE_LEN_MAX 128
#define POST_BUFFER_SIZE 2048

static char *keyPem;
static char *certPem;
static char *rootCaPem;

static MHD_Result RestResponseMessage(struct MHD_Connection *connection,
                                    int status_code,
                                    const char * message)
{
    int ret;
    struct MHD_Response *response;
    char buf[REST_RESPONSE_LEN_MAX] = {0};

    if (status_code == MHD_HTTP_OK) {
        (void)snprintf(buf, sizeof(buf), "{ \"result\": \"success\", \"message\":\"%s\" }", message);
    } else {
        (void)snprintf(buf, sizeof(buf), "{ \"result\": \"failed\", \"message\":\"%s\" }", message);
    }

    response = MHD_create_response_from_buffer(strlen(buf), (void *)buf,
                                               MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "applicaton/json");
    ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);

    return ret;
}

static int LoadPemFromFile(char **pem, const char *file)
{
    int ret;
    gnutls_datum_t data;

    ret = gnutls_load_file(file, &data);
    if (ret < 0) {
        ERROR("[RESTSERVER] Fail to load %s: %s\n", file, gnutls_strerror(ret));
        return -1;
    }
    *pem = malloc(data.size + 1);
    if (*pem == NULL) {
        ERROR("[RESTSERVER] Fail to alloc memory for ssl_auth\n");
        gnutls_free(data.data);
        return -1;
    }

    snprintf(*pem, data.size, "%s", data.data);
    gnutls_free(data.data);
    return 0;
}

static int GetClientCertificate(struct MHD_Connection *connection, gnutls_x509_crt_t *client_cert)
{
    unsigned int list_size;
    const gnutls_datum_t *pcert;
    gnutls_certificate_status_t client_cert_status;
    gnutls_session_t tls_session;
    const union MHD_ConnectionInfo *conn_info;

    conn_info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_GNUTLS_SESSION);
    tls_session = conn_info->tls_session;
    if (tls_session == NULL) {
        return -1;
    }

    if (gnutls_certificate_verify_peers2(tls_session, &client_cert_status)) {
        return -1;
    }

    pcert = gnutls_certificate_get_peers(tls_session, &list_size);
    if (pcert == NULL || list_size == 0) {
        return -1;
    }

    if (gnutls_x509_crt_import(*client_cert, &pcert[0], GNUTLS_X509_FMT_DER)) {
        return -1;
    }

    return 0;
}


void RestServerSslDestroy()
{
    if (keyPem != NULL) {
        free(keyPem);
    }

    if (certPem != NULL) {
        free(certPem);
    }

    if (rootCaPem != NULL) {
        free(rootCaPem);
    }

    keyPem = NULL;
    certPem = NULL;
    rootCaPem = NULL;
}

int RestServerSslInit(const char *privKey, const char *certFile, const char *caFile)
{
    if (privKey == NULL || certFile == NULL || caFile == NULL) {
        return -1;
    }

    if (strlen(privKey) == 0 || strlen(certFile) == 0 || strlen(caFile) == 0) {
        ERROR("[RESTSERVER] private_key/cert_file/ca_file must be specified when ssl_auth enabled\n");
        return -1;
    }

    // TODO: To add checking the format of pem
    if (LoadPemFromFile(&keyPem, privKey) < 0 || LoadPemFromFile(&certPem, certFile) < 0 ||
        LoadPemFromFile(&rootCaPem, caFile) < 0) {
        return -1;
    }

    return 0;
}

int RestServerClientAuth(struct MHD_Connection *connection)
{
    int ret = 0;
    unsigned int verify_status;
    gnutls_x509_crt_t client_cert;
    gnutls_x509_crt_t rootCA_cert;
    const gnutls_datum_t ca_data = {rootCaPem, strlen(rootCaPem) - 1};

    /* Import client certificate */
    if (gnutls_x509_crt_init(&client_cert)) {
        ERROR("[RESTSERVER] Failed to initialize client certificate\n");
        return -1;
    }

    ret = GetClientCertificate(connection, &client_cert);
    if (ret == -1) {
        ERROR("[RESTSERVER] Failed to import client certificate\n");
        gnutls_x509_crt_deinit(client_cert);
        return -1;
    }

    /* Import rootCA certificate */
    if (gnutls_x509_crt_init(&rootCA_cert)) {
        ERROR("[RESTSERVER] Failed to initialize rootCA certificate\n");
        gnutls_x509_crt_deinit(client_cert);
        return -1;
    }

    if (gnutls_x509_crt_import(rootCA_cert, &ca_data, GNUTLS_X509_FMT_PEM)) {
        ERROR("[RESTSERVER] Failed to import rootCA certificate\n");
        gnutls_x509_crt_deinit(rootCA_cert);
        gnutls_x509_crt_deinit(client_cert);
        return -1;
    }

    ret = gnutls_x509_crt_verify(client_cert, &rootCA_cert, 1, 0, &verify_status);
    if (ret < 0 || verify_status != 0) {
        ERROR("[RESTSERVETR] Client Certificate verification failed\n");
    }

    gnutls_x509_crt_deinit(rootCA_cert);
    gnutls_x509_crt_deinit(client_cert);
    return ret;
}

void RestServerDestroy(RestServer *restServer)
{
    if (restServer == NULL) {
        return;
    }

    if (restServer->daemon != NULL) {
        MHD_stop_daemon(restServer->daemon);
    }

    free(restServer);
    RestServerSslDestroy();
}

static MHD_Result RestPostIterator(void *cls, enum MHD_ValueKind kind, const char *key,
                        const char *filename, const char *content_type,
                        const char *transfer_encoding, const char *data, uint64_t off,
                        size_t size)
{
    RestRequest *request = cls;
    char *post_data;

    /*
     * libmicrohttpd now not support application/json post request, use application/x-www-form-urlencoded
     * instead, curl command example: curl -X POST -d json='{"XYZ":"ABC"}' http://ip:port/url
     */
    if (strcmp(key,"json") == 0) {
        if((size > 0) && (size <= POST_BUFFER_SIZE - 1)) {
            post_data = malloc(POST_BUFFER_SIZE);
            if (!post_data){
                return MHD_NO;
            }

            snprintf(post_data, POST_BUFFER_SIZE - 1, "%s", data);
            request->post_data = post_data;
        } else {
            WARN("[RESTSERVER] Post data size exceeds %d, ignore\n", POST_BUFFER_SIZE);
            request->post_data = NULL;
            return MHD_NO;
        }
    }
    return MHD_NO;
}

static MHD_Result RestHandlePostRequest(struct MHD_Connection *connection,
                                const char *url,
                                const char *upload_data,
                                size_t *upload_data_size,
                                void **con_cls)
{
    RestRequest *request = *con_cls;
    struct MHD_Response *response;
    struct json_object *data_json = NULL;

    MHD_post_process(request->postprocessor, upload_data, *upload_data_size);
    if (*upload_data_size != 0 ) {
        *upload_data_size = 0;
        return MHD_YES;
    }

    if (request->post_data != NULL && strlen(request->post_data) != 0) {
        if (parse_probe_json(url, request->post_data) == 0) {
            return RestResponseMessage(connection, MHD_HTTP_OK, "New config takes effect");
        }
    }

    return RestResponseMessage(connection, MHD_HTTP_BAD_REQUEST, "Bad request");
}

static MHD_Result RestHandleGetRequest(struct MHD_Connection *connection,
                                            const char *url)
{
    int ret;
    struct MHD_Response *response;
    char *buf = get_probe_json(url);

    if (buf) {
        response = MHD_create_response_from_buffer(strlen(buf), (void *)buf,
                                                MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "applicaton/json");
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        free(buf);
        return ret;
    }

    return RestResponseMessage(connection, MHD_HTTP_NOT_FOUND, "Url not found");
}

static MHD_Result RestRequestCallback(void *cls,
                              struct MHD_Connection *connection,
                              const char *url,
                              const char *method,
                              const char *version,
                              const char *upload_data,
                              size_t *upload_data_size,
                              void **ptr)
{
    RestRequest *request = *ptr;
    struct MHD_Response *response;

    /* it is the first iteration of a new request */
    if (request == NULL) {
        request = malloc(sizeof(RestRequest));
        if (request == NULL) {
            ERROR("[RESTSERVER] failed to malloc request\n");
            return MHD_NO;
        }
        (void)memset(request, 0, sizeof(RestRequest));

        *ptr = request;
        if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
            request->postprocessor = MHD_create_post_processor(connection, POST_BUFFER_SIZE,
                                                &RestPostIterator, request);
            if (request->postprocessor == NULL) {
                ERROR("[RESTSERVER] Failed to setup post processor\n");
                return MHD_NO;
            }
        }
        return MHD_YES;
    }

    /* url must be /xxxx */
    if (strlen(url) <= 1) {
        return RestResponseMessage(connection, MHD_HTTP_NOT_FOUND, "Url not found");
    }

    /* Client Authentication */
    if ((rootCaPem != NULL) && RestServerClientAuth(connection) < 0) {
        return RestResponseMessage(connection, MHD_HTTP_UNAUTHORIZED, "Client unauthorized");
    }

    url++;
    if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
        return RestHandlePostRequest(connection, url, upload_data, upload_data_size, ptr);
    }

    if (strcmp(method, MHD_HTTP_METHOD_GET) == 0) {
        return RestHandleGetRequest(connection, url);
    }

    return RestResponseMessage(connection, MHD_HTTP_METHOD_NOT_ALLOWED, "Method not allowed");
}

static void RestRequestCompleted(void *cls, struct MHD_Connection *connection,
                                 void **con_cls, enum MHD_RequestTerminationCode toe)
{
    RestRequest *request = *con_cls;

    if (request == NULL) {
        return;
    }

    if (request->post_data) {
        free(request->post_data);
    }
    if (request->postprocessor) {
        MHD_destroy_post_processor(request->postprocessor);
    }
    free(request);
    *con_cls = NULL;
}


int RestServerStartDaemon(RestServer *restServer)
{
#if MHD_VERSION < 0x00095300
    unsigned int mhdFlag = restServer->sslAuth ? MHD_USE_SSL : 0;
    mhdFlag |= MHD_USE_SELECT_INTERNALLY;
#else
    unsigned int mhdFlag = restServer->sslAuth ? MHD_USE_TLS : 0;
    mhdFlag |= MHD_USE_INTERNAL_POLLING_THREAD;
#endif
    if (restServer->sslAuth) {
        restServer->daemon = MHD_start_daemon(mhdFlag, restServer->port, NULL, NULL,
                                &RestRequestCallback, NULL,
                                MHD_OPTION_NOTIFY_COMPLETED, &RestRequestCompleted, NULL,
                                MHD_OPTION_HTTPS_MEM_KEY, keyPem,
                                MHD_OPTION_HTTPS_MEM_CERT, certPem,
                                MHD_OPTION_HTTPS_MEM_TRUST, rootCaPem,
                                MHD_OPTION_END);
    } else {
        restServer->daemon = MHD_start_daemon(mhdFlag, restServer->port, NULL, NULL,
                                &RestRequestCallback, NULL,
                                MHD_OPTION_NOTIFY_COMPLETED, &RestRequestCompleted, NULL,
                                MHD_OPTION_END);
    }

    if (restServer->daemon == NULL) {
        return -1;
    }

    return 0;
}