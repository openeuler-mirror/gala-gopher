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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include "common.h"
#include "cmd_common.h"

#define MAX_HEADER_SIZE 32

int SendAll(int fd, char *buf, int len)
{
    char *pos = buf;
    ssize_t send_sz;
    ssize_t left_sz = len;

    while (left_sz > 0) {
        send_sz = write(fd, pos, left_sz);
        if (send_sz < 0) {
            WARN("Failed to send data: %s\n", strerror(errno));
            return GOPHER_ERR;
        }
        left_sz -= send_sz;
        pos += send_sz;
    }

    return GOPHER_OK;
}

int RecvAll(int fd, char *buf, int len)
{
    char *pos = buf;
    ssize_t recv_sz;
    ssize_t left_sz = len;

    while (left_sz > 0) {
        recv_sz = read(fd, pos, left_sz);
        if (recv_sz < 0) {
            WARN("Failed to receive data: %s\n", strerror(errno));
            return GOPHER_ERR;
        }
        left_sz -= recv_sz;
        pos += recv_sz;
    }

    return GOPHER_OK;
}

int SendSizeHeader(int fd, int data_sz)
{
    char buf[MAX_HEADER_SIZE];

    buf[0] = '\0';
    (void)snprintf(buf, sizeof(buf), "%d\n", data_sz);
    return SendAll(fd, buf, strlen(buf));
}

int RecvSizeHeader(int fd, char *buf, int len, int *data_sz, int *buf_sz)
{
    char header_buf[MAX_HEADER_SIZE] = {0};
    char *cur_pos = header_buf;
    char *end_pos = NULL;
    ssize_t recv_sz = 0;
    ssize_t recv_cnt;
    ssize_t left_sz = sizeof(header_buf) - 1;

    if (sizeof(header_buf) - 1 > len) {
        WARN("Failed to read data size: no enough buffer\n");
        return GOPHER_OK;
    }

    while ((end_pos = strchr(header_buf, '\n')) == NULL) {
        if (left_sz <= 0) {
            break;
        }
        recv_cnt = read(fd, cur_pos, left_sz);
        if (recv_cnt < 0) {
            WARN("Failed to read data size: %s\n", strerror(errno));
            return GOPHER_ERR;
        }
        recv_sz += recv_cnt;
        left_sz -= recv_cnt;
        cur_pos += recv_cnt;
    }

    if (end_pos != NULL) {
        *end_pos = '\0';
        *data_sz = strtol(header_buf, NULL, 10);
        if (*data_sz == 0 && strcmp(header_buf, "0") != 0) {
            WARN("Failed to read data size: invalid format %s\n", header_buf);
            return GOPHER_ERR;
        }
        *buf_sz = recv_sz - (int)(end_pos - header_buf + 1);
        memcpy(buf, end_pos + 1, *buf_sz);
        return GOPHER_OK;
    }

    return GOPHER_ERR;
}