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
#include <unistd.h>
#include <limits.h>
#include <sys/file.h>
#include <sys/stat.h>
#include "daemon.h"
#include "base.h"
#include "ipc.h"

#define GOPHER_CMD_MAX                    3
#define GOPHER_CMD_MIN                    1
#define MAX_TEMPSTR                       200
#define PIDFILE_MODE                      0640
#define PIDFILE                           "/var/run/gala-gopher/gala-gopher.pid"

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
    (void)unlink(PIDFILE);

    exit(EXIT_SUCCESS);
}

static int write_pid_to_file(pid_t pid, const char *pidfile, int fd)
{
    char buf[MAX_TEMPSTR] = {0};
    int ret;
    ssize_t num;

    ret = snprintf(buf, sizeof(buf) - 1, "%ld\n", (long)pid);
    if (ret == -1) {
        ERROR("[MAIN] snprintf buf failed.\n");
        return 1;
    }

    (void)lseek(fd, (off_t)0, SEEK_SET);
    num = write(fd, buf, strlen(buf));
    if (num < 0) {
        ERROR("[MAIN] write %s error, %s.\n", pidfile, strerror(errno));
        return 1;
    }

    if (ftruncate(fd, num)) {
        ERROR("[MAIN] ftruncate error, %s.\n", strerror(errno));
        return 1;
    }

    return 0;
}

static void handle_lock_pidfile_failed(const char *pidfile, int error_no, int fd)
{
    char buf[MAX_TEMPSTR] = {0};
    char *ep = NULL;
    long other_pid;
    ssize_t num;

    num = read(fd, buf, sizeof(buf) - 1);
    if (num > 0) {
        other_pid = strtol(buf, &ep, 0);
        if (other_pid > 0 && ep != buf && *ep == '\n' && other_pid != LONG_MAX) {
            ERROR("[MAIN] can't lock %s, other pid may be %ld.\n", pidfile, other_pid);
        }
    } else {
        ERROR("[MAIN] can't lock %s, other pid unknown, %s.\n", pidfile, strerror(errno));
    }
}

static int acquire_daemonlock(const char *pidfile, pid_t pid)
{
    int ret = 0;
    int fd = -1;

    // Initial mode is 0600 to prevent flock() race/DoS.
    fd = open(pidfile, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd == -1) {
        ERROR("[MAIN] can't open or create %s, %s.\n", pidfile, strerror(errno));
        return 1;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        handle_lock_pidfile_failed(pidfile, errno, fd);
        (void)close(fd);
        fd = -1;
        return 1;
    }

    (void)fchmod(fd, PIDFILE_MODE);
    (void)fcntl(fd, F_SETFD, 1);

    ret = write_pid_to_file(pid, pidfile, fd);
    if (ret != 0) {
        (void)close(fd);
        fd = -1;
        (void)unlink(pidfile);
        return 1;
    }

    return 0;
}

/*
 * Ensure gala-gopher has a only one instance
 */
static int is_singleton(void)
{
    int ret = 0;

    ret = acquire_daemonlock(PIDFILE, getpid());
    if (ret != 0) {
        ERROR("[MAIN] acquire daemonlock failed.\n");
        return 1;
    }

    return 0;
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
    int delete_pid_file = 0;

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

    ret = is_singleton();
    if (ret != 0) {
        goto err;
    }

    delete_pid_file = 1;

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
    if (delete_pid_file == 1) {
        (void)unlink(PIDFILE);
    }
    exit(EXIT_FAILURE);
}

