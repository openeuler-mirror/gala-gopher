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
 * Create: 2021-09-28
 * Description: provide gala-gopher main functions
 ******************************************************************************/
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include "daemon.h"
#include "base.h"

#define GOPHER_CMD_MAX                    3
#define GOPHER_CMD_MIN                    1

char *g_galaConfPath;

static void ShowUsage(void)
{
    (void)printf("Usage:\n"
                 "    gala-gopher [options]\n\n"

                 "General gala-gopher options:\n"
                 "    -c [config path], --config_path [config path]\n"
                 "                                config file location\n"
                 "    -h, --help                  show command help\n"
    );
}

static int ParseConfigPath(const char *path)
{
    if (access(path, 0) < 0) {
        printf("config path error:%s.(errno:%d, %s)\n",
            path, errno, strerror(errno));
        return -1;
    } else {
        g_galaConfPath = (char *)malloc(strlen(path) + 1);
        if (g_galaConfPath == NULL) {
            printf("g_galaConfPath: malloc failed!\n");
            return -1;
        }

        memset(g_galaConfPath, 0, strlen(path) + 1);
        memcpy(g_galaConfPath, path, strlen(path));
    }

    return 0;
}

static int CmdProcessing(int argc, char *argv[])
{
    int cmd;
    int ret = 0;

    static struct option long_options[] = {
        {"help",        no_argument,       0, 'h'},
        {"config_path", required_argument, 0, 'c'},
        {NULL,          0,                 0, NULL}
    };

    char short_options[] = {
        "h"
        "c:"
    };

    if (argc > GOPHER_CMD_MAX) {
        printf("The command you entered is incorrect.\n");
        return -1;
    }

    if (argc == GOPHER_CMD_MIN) {
        ret = ParseConfigPath(GALA_CONF_PATH_DEFAULT);
        return ret;
    }
 
    while(1) {
        int option_index = 0;
        cmd = getopt_long(argc, argv, short_options, long_options, &option_index);
        if (cmd == -1)
            return -1;

        switch (cmd) {
            case 'h':
                // print usage later
                return -1;
            case 'c':
                ret = ParseConfigPath(optarg);
                break;
            default:
                printf("command error!\n");
                return -1;
        }
    }

    return ret;
}


int main(int argc, char *argv[])
{
    int ret = 0;
    ResourceMgr *resourceMgr = NULL;

    ret = CmdProcessing(argc, argv);
    if (ret != 0) {
        ShowUsage();
        return 0;
    }

    resourceMgr = ResourceMgrCreate();
    if (resourceMgr == NULL) {
        ERROR("[MAIN] create resource manager failed.\n");
        return 0;
    }

    ret = ResourceMgrInit(resourceMgr);
    if (ret != 0) {
        ERROR("[MAIN] ResourceMgrInit failed.\n");
        return 0;
    }

    ret = DaemonRun(resourceMgr);
    if (ret != 0) {
        ERROR("[MAIN] daemon run failed.\n");
        return 0;
    }

    ret = DaemonWaitDone(resourceMgr);
    if (ret != 0) {
        ERROR("[MAIN] daemon wait done failed.\n");
        return 0;
    }

    ResourceMgrDeinit(resourceMgr);
    ResourceMgrDestroy(resourceMgr);
    return 0;
}

