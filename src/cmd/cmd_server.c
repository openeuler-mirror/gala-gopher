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
 * Author: algorithmofdish
 * Create: 2024-05-15
 * Description: provide gala-gopher cmd
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/sendfile.h>

#include "common.h"
#include "probe_mng.h"
#include "imdb.h"
#include "cmd_server.h"

static int setRunDir(void)
{
    int ret;

    if (access(GALA_GOPHER_RUN_DIR, F_OK) != 0) {
        ret = mkdir(GALA_GOPHER_RUN_DIR, GALA_GOPHER_RUN_DIR_MODE);
        if (ret != 0) {
            ERROR("Failed to set gopher running dir, err=%s\n", strerror(errno));
            return GOPHER_ERR;
        }
    }

    return GOPHER_OK;
}

int cmdServerCreate(const char *path, int *fd)
{
    int ret;
    int server_fd;
    struct sockaddr_un addr;

    if (access(path, 0) == 0) {
        ret = unlink(path);
        if (ret < 0) {
            ERROR("Failed to unlink %s, err=%s\n", path, strerror(errno));
            return GOPHER_ERR;
        }
    }

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        ERROR("Failed to create cmd server socket, err=%s\n", strerror(errno));
        return GOPHER_ERR;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    ret = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (ret < 0 || ret >= sizeof(addr.sun_path)) {
        ERROR("The socket path(%s) is too long\n", path);
        goto err;
    }

    ret = bind(server_fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    if (ret < 0) {
        ERROR("Failed to bind unix socket on %s, err=%s\n", path, strerror(errno));
        goto err;
    }

    if (chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) < 0) {
        ERROR("Failed to chmod unix socket on %s\n", path);
        goto err;
    }

    ret = listen(server_fd, GALA_GOPHER_LISTEN_LEN);
    if (ret < 0) {
        ERROR("Failed to listen the unix socket, err=%s\n", strerror(errno));
        goto err;
    }

    *fd = server_fd;
    return GOPHER_OK;
err:
    close(server_fd);
    return GOPHER_ERR;
}

static int sendProbeResult(int fd, char *buf, int len)
{
    if (SendSizeHeader(fd, len) != GOPHER_OK) {
        return GOPHER_ERR;
    }
    return SendAll(fd, buf, len);
}

static int sendMetricResult(int outFd, int inFd, int len)
{
    ssize_t send_sz;
    ssize_t left_sz = len;
    off_t offset = 0;

    if (SendSizeHeader(outFd, len) != GOPHER_OK) {
        return GOPHER_ERR;
    }

    while (left_sz > 0) {
        send_sz = sendfile(outFd, inFd, &offset, left_sz);
        if (send_sz < 0) {
            return GOPHER_ERR;
        }
        left_sz -= send_sz;
    }

    return GOPHER_OK;
}

static void setRespMessage(char *buf, int buf_sz, bool success, const char *message)
{
    const char *status = success ? "success" : "failed";

    (void)snprintf(buf, buf_sz,
        "{ \"result\": \"%s\", \"message\":\"%s\" }\n", status, message);
}

int processProbeGetRequest(GopherCmdRequest *rcvRequest, int client_fd)
{
    char err_buf[128];
    char *buf;
    int ret;

    buf = get_probe_json(rcvRequest->probeName);
    if (buf == NULL) {
        err_buf[0] = '\0';
        setRespMessage(err_buf, sizeof(err_buf), false, "Failed to get probe config");
        (void)sendProbeResult(client_fd, err_buf, strlen(err_buf) + 1);
        return GOPHER_ERR;
    }
    ret = sendProbeResult(client_fd, buf, strlen(buf) + 1);
    if (ret != GOPHER_OK) {
        free(buf);
        return GOPHER_ERR;
    }

    free(buf);
    return GOPHER_OK;
}

int processProbeSetRequest(GopherCmdRequest *rcvRequest, int client_fd)
{
    char buf[128];
    int ret;

    buf[0] = 0;
    ret = parse_probe_json(rcvRequest->probeName, rcvRequest->probeConf);
    if (ret != 0) {
        setRespMessage(buf, sizeof(buf), false, g_parse_json_err);
    } else {
        setRespMessage(buf, sizeof(buf), true, "New config takes effect");
    }

    ret = sendProbeResult(client_fd, buf, strlen(buf) + 1);
    if (ret != GOPHER_OK) {
        return GOPHER_ERR;
    }

    return GOPHER_OK;
}

static int processProbeRequest(GopherCmdRequest *rcvRequest, int client_fd)
{
    switch (rcvRequest->probeOp) {
        case GOPHER_PROBE_OP_SET:
            return processProbeSetRequest(rcvRequest, client_fd);
        case GOPHER_PROBE_OP_GET:
            return processProbeGetRequest(rcvRequest, client_fd);
        default:
            return GOPHER_ERR;
    }
}

int processMetricRequest(GopherCmdRequest *rcvRequest, int client_fd)
{
    char log_file_name[256];
    struct stat buf;
    int fd;
    int ret;

    // The log file may has not been created if we get here between que_get_next_file() and LOG4CPLUS_DEBUG_FMT()
    if (ReadMetricsLogs(log_file_name) < 0 || access(log_file_name, F_OK) == -1) {
        (void)SendSizeHeader(client_fd, 0);
        return GOPHER_ERR;
    }

    fd = open(log_file_name, O_RDONLY);
    if (fd < 0) {
        ERROR("Failed to open '%s': %s\n", log_file_name, strerror(errno));
        (void)SendSizeHeader(client_fd, 0);
        return GOPHER_ERR;
    }

    if ((fstat(fd, &buf) == -1) || !S_ISREG(buf.st_mode)) {
        (void)close(fd);
        (void)SendSizeHeader(client_fd, 0);
        return GOPHER_ERR;
    }

    ret = sendMetricResult(client_fd, fd, buf.st_size);
    if (ret != GOPHER_OK) {
        DEBUG("Failed to send metrics\n");
        (void)close(fd);
        return GOPHER_ERR;
    }

    close(fd);
    RemoveMetricsLogs(log_file_name);
    return GOPHER_OK;
}

static int processRequest(GopherCmdRequest *rcvRequest, int client_fd)
{
    switch (rcvRequest->cmdType) {
        case GOPHER_CMD_TYPE_PROBE:
            return processProbeRequest(rcvRequest, client_fd);
        case GOPHER_CMD_TYPE_METRIC:
            return processMetricRequest(rcvRequest, client_fd);
        default:
            WARN("Unknown request type\n");
            return GOPHER_ERR;
    }
}

void *CmdServer(void *arg)
{
    int ret = 0;
    int server_fd;
    int client_fd;

    struct sockaddr_un client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    ssize_t receive_num;

    ret = setRunDir();
    if (ret != GOPHER_OK) {
        ERROR("dir not exist and create fail. ret=%d.\n", ret);
        return NULL;
    }

    ret = cmdServerCreate(GALA_GOPHER_CMD_SOCK_PATH, &server_fd);
    if (ret != GOPHER_OK) {
        ERROR("Error: cmdServerCreate failed. ret=%d.\n", ret);
        return NULL;
    }

    GopherCmdRequest *rcvRequest = calloc(1, sizeof(GopherCmdRequest));
    if (rcvRequest == NULL) {
        return NULL;
    }

    while(1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            DEBUG("Failed to accept socket\n");
            continue;
        }

        ret = SetSockTimeout(client_fd);
        if (ret < 0) {
            DEBUG("Failed to set socket timeout, err=%s\n", strerror(errno));
            close(client_fd);
            continue;
        }

        ret = RecvAll(client_fd, (char *)rcvRequest, sizeof(GopherCmdRequest));
        if (ret < 0) {
            DEBUG("Failed to get request\n");
            close(client_fd);
            continue;
        }
        (void)processRequest(rcvRequest, client_fd);
        close(client_fd);
    }

    close(server_fd);
    free(rcvRequest);
    return NULL;
}
