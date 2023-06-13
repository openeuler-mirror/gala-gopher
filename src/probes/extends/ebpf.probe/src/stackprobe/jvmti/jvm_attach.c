/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wo_cow
 * Create: 2022-12-09
 * Description: JVMTI attach tool
 ******************************************************************************/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include "common.h"

#define setns(FD, NSTYPE) syscall(__NR_setns, (int)(FD), (int)(NSTYPE))
#define MAX_PATH_LEN 512
char tmp_path[MAX_PATH_LEN];

int get_tmp_path_r(int cur_pid, char* buf, size_t bufsize) {
    if (snprintf(buf, bufsize, "/proc/%d/root/tmp", cur_pid) >= bufsize) {
        return -1;
    }

    // Check if the remote /tmp can be accessed via /proc/[pid]/root
    struct stat stats;
    return stat(buf, &stats);
}

static int get_netns_fd(pid_t pid, const char* type)
{
    char path[PATH_LEN] = {0};
    (void)snprintf(path, PATH_LEN, "/proc/%d/ns/%s", pid, type);
    return open(path, O_RDONLY);
}

static int __ns_enter(int pid, int nspid, const char* type, int *cur_pid)
{
    int fd = -1;

    char path[64], selfpath[64];
    snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, type);
    snprintf(selfpath, sizeof(selfpath), "/proc/self/ns/%s", type);

    struct stat oldns_stat, newns_stat;
    if (stat(selfpath, &oldns_stat) == 0 && stat(path, &newns_stat) == 0) {
        // Don't try to call setns() if we're in the same namespace already
        if (oldns_stat.st_ino != newns_stat.st_ino) {
            fd = get_netns_fd(pid, "mnt");
            if (fd == -1) {
                fprintf(stderr, "[JVM_ATTACH] get tgid(%d)'s ns fd failed.\n", pid);
                return -1;
            }

            int result = setns(fd, 0);
            close(fd);
            if (result < 0) {
                return result;
            }

            *cur_pid = nspid;
        }
    }

    return 0;
}

static int __check_attach_listener(int nspid) {
    char path[PATH_LEN] = {0};
    snprintf(path, sizeof(path), "%s/.java_pid%d", tmp_path, nspid);

    struct stat stats;
    return stat(path, &stats) == 0 && S_ISSOCK(stats.st_mode) ? 0 : -1;
}

static int __start_attach(int pid, int nspid) {
    int result = 0;
    char path[PATH_LEN];
    snprintf(path, sizeof(path), "/proc/%u/cwd/.attach_pid%d", nspid, nspid);
    int fd = creat(path, 0660);
    if (fd == -1) {
        result = -1;
        fprintf(stderr, "[JVM_ATTACH]: tgid(%d) start attach failed when creat attach file.\n", pid);
        goto out;
    }

    kill(pid, SIGQUIT);
    sleep(60);
    struct timespec ts = {0, 20000000}; // 20 ms

    do {
        nanosleep(&ts, NULL);
        result = __check_attach_listener(nspid);
    } while (result != 0 && (ts.tv_nsec += 20000000) < 5000000000);

out:
    unlink(path);
    close(fd);
    return result;
}

static int __write_cmd(int fd, int argc, char** argv) {
    // Protocol version
    if (write(fd, "1", 2) <= 0) {
        return -1;
    }

    int i;
    for (i = 0; i < 4; i++) {
        const char* arg = i < argc ? argv[i] : "";
        if (write(fd, arg, strlen(arg) + 1) <= 0) {
            return -1;
        }
    }
    return 0;
}

static void __read_rsp(int fd, int argc, char** argv) {
    char buf[MAX_PATH_LEN];
    ssize_t bytes = read(fd, buf, sizeof(buf) - 1);
    if (bytes <= 0) {
        fprintf(stderr, "[JVM_ATTACH]Error reading response\n");
        return;
    }

    buf[bytes] = 0;

    printf("[JVM_ATTACH]: JVM response code = ");
    do {
        fwrite(buf, 1, bytes, stdout);
        bytes = read(fd, buf, sizeof(buf));
    } while (bytes > 0);

    return;
}

static int __connect_jvm(int nspid) {
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    int fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        return -1;
    }

    int bytes = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/.java_pid%d", tmp_path, nspid);
    if (bytes >= sizeof(addr.sun_path)) {
        addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        close(fd);
        return -1;
    }
    return fd;
}

int __jattach(int pid, int nspid, int argc, char** argv) {
    if (__check_attach_listener(nspid) != 0 && __start_attach(pid, nspid) != 0) {
        fprintf(stderr, "[JVM_ATTACH]: Could not start attach to JVM of pid %d\n", pid);
        return -1;
    }

    int fd = __connect_jvm(nspid);
    if (fd == -1) {
        fprintf(stderr, "[JVM_ATTACH]: Could not connect to socket of pid %d\n", pid);
        return -1;
    }

    printf("[JVM_ATTACH]: Connected to remote JVM of pid %d\n", pid);

    if (__write_cmd(fd, argc, argv) != 0) {
        fprintf(stderr, "[JVM_ATTACH]: Error writing to socket of pid %d\n", pid);
        close(fd);
        return -1;
    }

    __read_rsp(fd, argc, argv);
    
    close(fd);
    return 0;
}

int main(int argc, char** argv) {

    int ret;
    if (argc < 4) {
        fprintf(stderr, "[JVM_ATTACH]: wrong argv\n");
        return -1;
    }

    int pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "[JVM_ATTACH]: %s is not a valid process ID\n", argv[1]);
        return 1;
    }
    int cur_pid = pid;

    int nspid = atoi(argv[2]);
    if (nspid <= 0) {
        fprintf(stderr, "[JVM_ATTACH]: %s is not a valid ns process ID\n", argv[2]);
        return 1;
    }

    ret = __ns_enter(pid, nspid, "mnt", &cur_pid);
    if (ret != 0) {
        fprintf(stderr, "[JVM_ATTACH]: nsenter fail");
        return -1;
    }

    ret = get_tmp_path_r(cur_pid, tmp_path, sizeof(tmp_path));
    if (ret != 0) {
        fprintf(stderr, "[JVM_ATTACH]: get_tmp_path_r %s fail", tmp_path);
        return -1;
    }

    signal(SIGPIPE, SIG_IGN);

    return __jattach(pid, nspid, argc - 3, argv + 3);
}