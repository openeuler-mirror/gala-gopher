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
 * Author: njlzk
 * Create: 2021-10-12
 * Description: provide gala-gopher cmd
 ******************************************************************************/
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "base_info.h"

extern char *g_galaConfPath;


static int SetRunDir(void)
{
    int ret = 0;

    if (access(GALA_GOPHER_RUN_DIR, F_OK) != 0) {
        ret = mkdir(GALA_GOPHER_RUN_DIR, GALA_GOPHER_FILE_PERMISSION);
    }

    return ret;
}

static int CmdServerCreate(const char *path, int *fd)
{
    int ret;
    int server_fd;
    struct sockaddr_un addr;

    if (access(path, 0) == 0) {
        ret = unlink(path);
        if (ret < 0) {
            printf("Error: unlink %s failed. %s\n", path, strerror(errno));
            return GOPHER_ERR;
        }
    }

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("Error: create socket failed.\n");
        return GOPHER_ERR;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    (void)snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    ret = bind(server_fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    if (ret < 0) {
        printf("Error: bind unix socket failed on %s. ret=%d\n", path, ret);
        goto ERROR;
    }

    ret = listen(server_fd, GALA_GOPHER_LISTEN_LEN);
    if (ret < 0) {
        printf("Error: listen unix socket failed on %s. ret=%d\n", GALA_GOPHER_CMD_SOCK_PATH_NAME, ret);
        goto ERROR;
    }

    *fd = server_fd;
    return GOPHER_OK;

ERROR:
    close(server_fd);
    return GOPHER_ERR;
}


static int getRequest(int fd, char *buf, int len)
{
    ssize_t ret;

    ret = (ssize_t)read(fd, buf, len);
    if (ret <= 0) {
        printf("Error: read msg from fd[%d] failed. %s(%d).\n", fd, strerror(errno), errno);
        return GOPHER_ERR;
    }

    return GOPHER_OK;
}


static int GetConfig(struct GopherCmdRequest *rcvRequest, char *buf)
{
    int ret = 0;

    if (strcmp(rcvRequest->cmdKey, GOPHER_CMD_KEY1) == 0) {
        if (strcmp(rcvRequest->cmdValue, GOPHER_CMD_KEY1_VALUE1) == 0) {
            memcpy(buf, g_galaConfPath, strlen(g_galaConfPath));
        } else {
            ret = -1;
        }
    } else {
        ret = -1;
    }

    return ret;
}


static int RequestProcess(struct GopherCmdRequest *rcvRequest, char *result)
{
    int ret = 0;
    enum GopherCmdType cmdType = rcvRequest->cmdType;
    
    switch (cmdType) {
        case GOPHER_GET_CONFIG_PATH:
            ret = GetConfig(rcvRequest, result);
            break;
        default:
            return GOPHER_ERR;
    }

    return ret;
}


static int SendResult(int fd, char *buf, int len)
{
    ssize_t ret;

    ret = write(fd, buf, len);
    if (ret < 0) {
        printf("write msg to fd %d failed. %s.\n", fd, strerror(errno));
        return GOPHER_ERR;
    }

    return GOPHER_OK;
}


void CmdServer(void *arg)
{
    int ret = 0;
    int server_fd;
    int client_fd;
    
    struct sockaddr_un client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    ssize_t receive_num;

    struct GopherCmdRequest rcvRequest;
    
    ret = SetRunDir();
    if (ret != GOPHER_OK) {
        printf("dir not exist and create fail. ret=%d.\n", ret);
        goto ERROR2;
    }

    ret = CmdServerCreate(GALA_GOPHER_CMD_SOCK_PATH_NAME, &server_fd);
    if (ret != GOPHER_OK) {
        printf("Error: CmdServerCreate failed. ret=%d.\n", ret);
        goto ERROR2;
    }

    char *result;
    result = (char *)malloc(RESULT_INFO_LEN_MAX);
    if (result == NULL) {
        printf("Error: result malloc failed.\n");
        goto ERROR1;
    }

    while(1) {
        memset(result, 0, RESULT_INFO_LEN_MAX);

        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            free(result);
            continue;
        }

        ret = getRequest(client_fd, (char *)(&rcvRequest), sizeof(struct GopherCmdRequest));
        if (ret < 0) {
            memcpy(result, GOPHER_CMD_REQUEST_STATUS_FAILED1, strlen(GOPHER_CMD_REQUEST_STATUS_FAILED1));
        } else {
            ret = RequestProcess(&rcvRequest, result);
            if (ret < 0) {
                printf("Error: RequestProcess failed.\n");
                memcpy(result, GOPHER_CMD_REQUEST_STATUS_FAILED2, strlen(GOPHER_CMD_REQUEST_STATUS_FAILED2));
            }
        }

        ret = SendResult(client_fd, result, strlen(result) + 1);
        if (ret < 0) {
            printf("Error: SendResult failed.\n");
            goto ERROR1;
        } else {
            free(result);
            continue;
        }

ERROR1:
    if (result != NULL) {
        free(result);
    }
    close(server_fd);
ERROR2:
    return;
    }
}
