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
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "cmd_common.h"

#define OUTPUT_BUF_SIZE 4096

static void showUsage(void)
{
    (void)printf(
        "Usage:\n"
        "   gopher-ctl probe get <probe_name>\n"
        "   gopher-ctl probe set <probe_name> <probe_config>\n"
        "   gopher-ctl metric\n"
    );
}

static GopherCmdType getGopherCmdType(const char *cmdTypeName)
{
    if (strcmp(cmdTypeName, GOPHER_CMD_TYPE_PROBE_VAL) == 0) {
        return GOPHER_CMD_TYPE_PROBE;
    } else if (strcmp(cmdTypeName, GOPHER_CMD_TYPE_METRIC_VAL) == 0) {
        return GOPHER_CMD_TYPE_METRIC;
    }

    return GOPHER_CMD_TYPE_UNKNOWN;
}

static GopherProbeOp getGopherProbeOp(const char *probeOpName) {
    if (strcmp(probeOpName, GOPHER_PROBE_OP_GET_VAL) == 0) {
        return GOPHER_PROBE_OP_GET;
    } else if (strcmp(probeOpName, GOPHER_PROBE_OP_SET_VAL) == 0) {
        return GOPHER_PROBE_OP_SET;
    }

    return GOPHER_PROBE_OP_UNKNOWN;
}

int cmdRequestParseProbe(int argc, char *argv[], GopherCmdRequest *cmdRequest)
{
    int ret;

    if (argc < 1) {
        (void)printf("Please specify the probe operation\n");
        return GOPHER_ERR;
    }
    cmdRequest->probeOp = getGopherProbeOp(argv[0]);
    if (cmdRequest->probeOp == GOPHER_PROBE_OP_UNKNOWN) {
        (void)printf("Unknown probe operation: %s\n", argv[0]);
        return GOPHER_ERR;
    }

    if (argc < 2) {
        (void)printf("Please specify the probe name\n");
        return GOPHER_ERR;
    }
    ret = snprintf(cmdRequest->probeName, sizeof(cmdRequest->probeName), "%s", argv[1]);
    if (ret < 0 || ret >= sizeof(cmdRequest->probeName)) {
        (void)printf("The probe name(%s) is too long\n", argv[1]);
        return GOPHER_ERR;
    }

    if (cmdRequest->probeOp == GOPHER_PROBE_OP_SET) {
        if (argc < 3) {
            (void)printf("Please specify the probe config\n");
            return GOPHER_ERR;
        }
        ret = snprintf(cmdRequest->probeConf, sizeof(cmdRequest->probeConf), "%s", argv[2]);
        if (ret < 0 || ret >= sizeof(cmdRequest->probeConf)) {
            (void)printf("The probe config(%s) is too long\n", argv[2]);
            return GOPHER_ERR;
        }
    }

    return GOPHER_OK;
}

int cmdRequestParse(int argc, char *argv[], GopherCmdRequest *cmdRequest)
{
    if (argc < 2) {
        (void)printf("Please specify the request type\n");
        return GOPHER_ERR;
    }
    cmdRequest->cmdType = getGopherCmdType(argv[1]);
    if (cmdRequest->cmdType == GOPHER_CMD_TYPE_UNKNOWN) {
        (void)printf("Unknown request type: %s\n", argv[1]);
        return GOPHER_ERR;
    }
    if (cmdRequest->cmdType == GOPHER_CMD_TYPE_PROBE) {
        return cmdRequestParseProbe(argc - 2, argv + 2, cmdRequest);
    }

    return GOPHER_OK;
}

int connectToGopherServer(const char *path, int *fd)
{
    struct sockaddr_un addr;
    int client_fd;
    int ret;

    client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_fd < 0) {
        (void)printf("Failed to create socket.\n");
        return GOPHER_ERR;
    }

    (void)memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    ret = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (ret < 0 || ret >= sizeof(addr.sun_path)) {
        (void)printf("The socket path(%s) is too long\n", path);
        close(client_fd);
        return GOPHER_ERR;
    }

    ret = connect(client_fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    if (ret < 0) {
        (void)printf("Failed to connect to gopher cmd server, err=%s\n", strerror(errno));
        close(client_fd);
        return GOPHER_ERR;
    }

    *fd = client_fd;
    return GOPHER_OK;
}

int outputResult(int fd)
{
    char buf[OUTPUT_BUF_SIZE];
    int data_sz = 0;
    int recv_sz = 0;
    ssize_t recv_cnt;
    int ret;

    buf[0] = '\0';
    ret = RecvSizeHeader(fd, buf, sizeof(buf) - 1, &data_sz, &recv_sz);
    if (ret != GOPHER_OK) {
        (void)printf("Failed to get response size\n");
        return GOPHER_ERR;
    }

    buf[recv_sz] = '\0';
    (void)printf("%s", buf);
    data_sz -= recv_sz;

    while (data_sz > 0) {
        recv_cnt = read(fd, buf, sizeof(buf) - 1);
        if (recv_cnt < 0) {
            (void)printf("Failed to read response data, err=%s\n", strerror(errno));
            return GOPHER_ERR;
        }
        buf[recv_cnt] = '\0';
        (void)printf("%s", buf);
        data_sz -= recv_cnt;
    }

    return GOPHER_OK;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int client_fd;
    GopherCmdRequest *cmdRequest = calloc(1, sizeof(GopherCmdRequest));
    if (cmdRequest == NULL) {
        return GOPHER_ERR;
    }

    ret = cmdRequestParse(argc, argv, cmdRequest);
    if (ret != GOPHER_OK) {
        showUsage();
        goto err;
    }

    ret = connectToGopherServer(GALA_GOPHER_CMD_SOCK_PATH, &client_fd);
    if (ret != GOPHER_OK) {
        goto err;
    }

    ret = SendAll(client_fd, (char *)cmdRequest, sizeof(GopherCmdRequest));
    if (ret != GOPHER_OK) {
        close(client_fd);
        goto err;
    }

    ret = outputResult(client_fd);
    if (ret != GOPHER_OK) {
        close(client_fd);
        goto err;
    }

    close(client_fd);
    (void)fflush(stdout);
    free(cmdRequest);
    return GOPHER_OK;
err:
    (void)fflush(stdout);
    free(cmdRequest);
    return GOPHER_ERR;
}
