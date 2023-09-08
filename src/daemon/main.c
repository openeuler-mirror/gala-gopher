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
#include <signal.h>
#include "daemon.h"
#include "base.h"
#include "ipc.h"

#define GOPHER_CMD_MAX                    3
#define GOPHER_CMD_MIN                    1

#ifndef GOPHER_COMMIT_SHA1
#define GOPHER_COMMIT_SHA1             "unknown"
#endif

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

static void PrintVersion(void)
{
    (void)printf("COMMIT_SHA1=%s\n", GOPHER_COMMIT_SHA1);
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
        {"version",     no_argument,       0, 'v'},
        {0,             0,                 0, 0}
    };

    char short_options[] = {
        "h"
        "c:"
        "v"
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
                ShowUsage();
                return -1;
            case 'c':
                ret = ParseConfigPath(optarg);
                return ret;
            case 'v':
                PrintVersion();
                return -1;
            default:
                printf("command error!\n");
                ShowUsage();
                return -1;
        }
    }

    return ret;
}

static int g_probe_mng_ipc_msgid = -1;
static ResourceMgr *g_resourceMgr;

static void quit_handler(int signo)
{
    destroy_probe_threads();
    destroy_daemon_threads(g_resourceMgr);
    // probe_mng创建的ipc消息队列是跟随内核的，进程结束消息队列还会存在，需要显示调用函数销毁
    destroy_ipc_msg_queue(g_probe_mng_ipc_msgid);

    exit(EXIT_SUCCESS);
}

static void sig_setup(void)
{
    struct sigaction quit_action;

    (void)memset(&quit_action, 0, sizeof(struct sigaction));
    quit_action.sa_handler = quit_handler;

    (void)sigaction(SIGINT, &quit_action, NULL);
    (void)sigaction(SIGTERM, &quit_action, NULL);
}

int main(int argc, char *argv[])
{
    int ret = 0;

    sig_setup();

    ret = CmdProcessing(argc, argv);
    if (ret != 0) {
        goto err;
    }

    g_resourceMgr = ResourceMgrCreate();
    if (g_resourceMgr == NULL) {
        ERROR("[MAIN] create resource manager failed.\n");
        goto err;
    }

    ret = ResourceMgrInit(g_resourceMgr);
    if (ret != 0) {
        ERROR("[MAIN] ResourceMgrInit failed.\n");
        goto err;
    }
    g_probe_mng_ipc_msgid = g_resourceMgr->probe_mng->msq_id;

    ret = DaemonRun(g_resourceMgr);
    if (ret != 0) {
        ERROR("[MAIN] daemon run failed.\n");
        goto err;
    }

    ret = DaemonWaitDone(g_resourceMgr);
    if (ret != 0) {
        ERROR("[MAIN] daemon wait done failed.\n");
        goto err;
    }
err:
    ResourceMgrDeinit(g_resourceMgr);
    ResourceMgrDestroy(g_resourceMgr);
    exit(EXIT_FAILURE);
}

