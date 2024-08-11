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
#ifndef __CMD_COMMON_H__
#define __CMD_COMMON_H__
#include "base.h"
#ifdef IS_GOPHER_CMD_CLIENT
#define DEBUG (void)printf
#else
#include "common.h"
#endif

#define GOPHER_OK       0
#define GOPHER_ERR      (-1)

#define GALA_GOPHER_LISTEN_LEN      5

#define SOCK_TIMEOUT_SEC 60

#define MAX_PROBE_CONF_SIZE (1024 * 1024)

#define GOPHER_CMD_TYPE_PROBE_VAL   "probe"
#define GOPHER_CMD_TYPE_METRIC_VAL  "metric"

#define GOPHER_PROBE_OP_GET_VAL     "get"
#define GOPHER_PROBE_OP_SET_VAL     "set"

typedef enum {
    GOPHER_CMD_TYPE_UNKNOWN,
    GOPHER_CMD_TYPE_PROBE,
    GOPHER_CMD_TYPE_METRIC
} GopherCmdType;

typedef enum {
    GOPHER_PROBE_OP_UNKNOWN,
    GOPHER_PROBE_OP_GET,
    GOPHER_PROBE_OP_SET,
} GopherProbeOp;

typedef struct {
    GopherCmdType cmdType;
    GopherProbeOp probeOp;
    char probeName[MAX_PROBE_NAME_LEN];
    char probeConf[MAX_PROBE_CONF_SIZE];
} GopherCmdRequest;

int SendAll(int fd, char *buf, int len);
int RecvAll(int fd, char *buf, int len);
int SendSizeHeader(int fd, int data_sz);
int RecvSizeHeader(int fd, char *buf, int len, int *data_sz, int *buf_sz);
int SetSockTimeout(int sockfd);

#endif
