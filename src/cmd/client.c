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
#include <getopt.h>
#include <errno.h>
#include "base_info.h"


static void ShowUsage(void)
{
    (void)printf("Usage:\n"
                 "   gopher-ctl [-h | --help]\n"
                 "   gopher-ctl [-s | --show]     [config_path]\n"
    );
}

static int CheckShowItem(char *showItem)
{
    int ret = -1;

    for(int i = 0; i < sizeof(g_cmdShowItemTbl) / sizeof(g_cmdShowItemTbl[0]); i++) {
        if (strcmp(showItem, g_cmdShowItemTbl[i]) != 0) {
            continue;
        } else {
            ret = 0;
            break;
        }
    }

    return ret;
}

static int CmdRequestParse(int argc, char *argv[], struct GopherCmdRequest *cmdRequest)
{
    int cmd;
    static struct option long_options[] = {
        {"help",    no_argument,       0, 'h'},
        {"show",    required_argument, 0, 's'},
    };

    char short_options[] = {
        "h"
        "s:"
    };

    if ((argc < GOPHER_CMD_LINE_MIN) \
            || (argc > GOPHER_CMD_LINE_MAX) \
            || ((argc == GOPHER_CMD_LINE_MIN) && (strcmp(argv[1], "-h") != 0) && (strcmp(argv[1], "--help") != 0))) {
        printf("The command you entered is incorrect.\n");
        return GOPHER_ERR;
    }


    while (1) {
        int option_index = 0;
        cmd = getopt_long(argc, argv, short_options, long_options, &option_index);
        if (cmd == -1)
            break;

        switch (cmd) {
            case 'h':
                return GOPHER_ERR;
            case 's':
                cmdRequest->cmdType = GOPHER_GET_CONFIG_PATH;
                memcpy(cmdRequest->cmdKey, GOPHER_CMD_KEY1, strlen(GOPHER_CMD_KEY1));
                if (CheckShowItem(optarg) == 0) {
                    memcpy(cmdRequest->cmdValue, optarg, strlen(optarg));
                    break;
                } else {
                    return GOPHER_ERR;
                }
            default:
                return GOPHER_ERR;
        }
    }

    return GOPHER_OK;
}

static int ConnectToGopher(const char *path, int* fd)
{
    int ret;
    int client_fd;
    struct sockaddr_un addr;

    // 1. new socket
    client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_fd < 0) {
        printf("create socket failed.\n");
        return GOPHER_ERR;
    }

    // 2. addr path
    (void)memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    (void)snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    // 3. connect with server
    ret = connect(client_fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    if (ret < 0) {
        printf("connect to gala-gopher failed. %s\n", strerror(errno));
        return GOPHER_ERR;
    }

    *fd = client_fd;

    return 0;
}

static int SendRequest(int fd, char *buf, int len)
{
    ssize_t ret;

    ret = (ssize_t)write(fd, buf, len);
    if (ret <= 0) {
        printf("write msg to fd %d failed, errno %d.\n", fd, errno);
        return GOPHER_ERR;
    }

    return GOPHER_OK;
}


static int GetResult(int fd, char *buf, int len)
{
    ssize_t ret;
    ret = (ssize_t)read(fd, buf, len);
    if (ret <= 0) {
        printf("read msg from server failed, errno %d.\n", errno);
        return GOPHER_ERR;
    }

    return GOPHER_OK;
}


int main(int argc, char *argv[])
{
    int ret = 0;
    int client_fd;
    char *resultInfo = NULL;
    struct GopherCmdRequest *cmdRequest;

    cmdRequest = (struct GopherCmdRequest *)malloc(sizeof(struct GopherCmdRequest));
    if (cmdRequest == NULL) {
        printf("Error: cmdRequest malloc failed!\n");
        goto END2;
    }
    ret = CmdRequestParse(argc, argv, cmdRequest);
    if (ret < 0) {
        ShowUsage();
        goto END2;
    }

    ret = ConnectToGopher(GALA_GOPHER_CMD_SOCK_PATH_NAME, &client_fd);
    if (ret < 0) {
        goto END2;
    }

    ret = SendRequest(client_fd, (char *)cmdRequest, sizeof(struct GopherCmdRequest));
    if (ret < 0) {
        goto END1;
    }
    
    resultInfo = (char *)malloc(RESULT_INFO_LEN_MAX + 1);
    if (resultInfo == NULL){
        printf("Error: cmdRequest malloc failed!\n");
        goto END1;
    }
    memset(resultInfo, 0, RESULT_INFO_LEN_MAX + 1);
    ret = GetResult(client_fd, resultInfo, RESULT_INFO_LEN_MAX);
    if (ret < 0) {
        goto END1;
    }

    printf("%s\n", resultInfo);
    goto END1;

END1:
    close(client_fd);
END2:
    if (resultInfo != NULL) {
        free(resultInfo);
    }
    if (cmdRequest != NULL) {
        free(cmdRequest);
    }
    return 0;
}
