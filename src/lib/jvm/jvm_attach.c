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
#include "syscall.h"
#include "common.h"

#define CONNECT_TIMEOUT 10  // unit: second

#define MAX_PATH_LEN 512
#define ARGS_NUM 4
char tmp_path[PATH_LEN];

int get_tmp_path_r(int cur_pid, char* buf, size_t bufsize)
{
    int ret = snprintf(buf, bufsize, "/proc/%d/root/tmp", cur_pid);
    if (ret < 0 || ret >= bufsize) {
        return -1;
    }

    // Check if the remote /tmp can be accessed via /proc/[pid]/root
    struct stat stats;
    if (stat(buf, &stats) != 0) {
        ret = snprintf(buf, bufsize, "/tmp");
        if (ret < 0 || ret >= bufsize) {
            return -1;
        }
    }

    return 0;
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
    (void)snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, type);
    (void)snprintf(selfpath, sizeof(selfpath), "/proc/self/ns/%s", type);

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

static int __check_attach_listener(int nspid)
{
    char path[MAX_PATH_LEN] = {0};
    (void)snprintf(path, sizeof(path), "%s/.java_pid%d", tmp_path, nspid);

    struct stat stats;
    return stat(path, &stats) == 0 && S_ISSOCK(stats.st_mode) ? 0 : -1;
}

static uid_t get_file_owner(const char* path) {
    struct stat stats;
    return stat(path, &stats) == 0 ? stats.st_uid : (uid_t)-1;
}

static int __start_attach(int pid, int nspid)
{
    int result = 0;
    char path[MAX_PATH_LEN];
    (void)snprintf(path, sizeof(path), "/proc/%d/cwd/.attach_pid%d", nspid, nspid);
    int fd = creat(path, 0660);

    // "/tmp" or "/proc/<pid>/cwd/" can be location for .attach_pid<pid>.
    if (fd == -1 || (close(fd) == 0 && get_file_owner(path) != geteuid())) {
        unlink(path);
        snprintf(path, sizeof(path), "%s/.attach_pid%d", tmp_path, nspid);
        fd = creat(path, 0660);
        if (fd == -1) {
            fprintf(stderr, "[JVM_ATTACH]: tgid(%d) start attach failed when creat attach file.\n", pid);
            return -1;
        }
        close(fd);
    }

    kill(pid, SIGQUIT);
    struct timespec ts = {0, 20000000}; // 20 ms

    do {
        nanosleep(&ts, NULL);
        result = __check_attach_listener(nspid);
    } while (result != 0 && (ts.tv_nsec += 20000000) < 5000000000); // 20000000 ns 检查一次直至 5000000000 ns

    unlink(path);
    return result;
}

static int __write_cmd(int fd, int argc, const char** argv)
{
    // Protocol version
    if (write(fd, "1", 2) <= 0) { // 2 = strlen + 1
        return -1;
    }

    int i;
    for (i = 0; i < ARGS_NUM; i++) {
        const char* arg = i < argc ? argv[i] : "";
        if (write(fd, arg, strlen(arg) + 1) <= 0) {
            return -1;
        }
    }
    return 0;
}

#define RET_CODE "return code:"
static int __read_rsp(int fd, int argc, char** argv)
{
    FILE *fp = fdopen(fd, "r");
    if (fp == NULL) {
        fprintf(stderr, "[JVM_ATTACH] Error reading response\n");
        close(fd);
        return -1;
    }

    char line[LINE_BUF_LEN];
    line[0] = 0;
    while (fgets(line, LINE_BUF_LEN, fp) != NULL) {
    }
    (void)fclose(fp);

    // split_newline_symbol
    int len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = 0;
    }

    return atoi(strstr(line, RET_CODE) != NULL ? line + sizeof(RET_CODE) : line);
}

static void alarm_handler(int signo) {}

static int __connect_jvm(int nspid)
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    int fd = socket(PF_UNIX, SOCK_STREAM, 0);
    struct sigaction sa;

    if (fd == -1) {
        return -1;
    }

    int bytes = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/.java_pid%d", tmp_path, nspid);
    if (bytes >= sizeof(addr.sun_path)) {
        addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
    }

    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT;
    if (sigaction(SIGALRM, &sa, NULL) < 0) {
        return -1;
    }

    alarm(CONNECT_TIMEOUT);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        alarm(0);
        close(fd);
        return -1;
    }
    alarm(0);
    return fd;
}

int __jattach(int pid, int nspid, int argc, char **argv)
{
    struct timeval timeout;

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

    if (__write_cmd(fd, argc, (const char **)argv) != 0) {
        fprintf(stderr, "[JVM_ATTACH]: Error writing to socket of pid %d\n", pid);
        close(fd);
        return -1;
    }

    timeout.tv_sec = CONNECT_TIMEOUT;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        fprintf(stderr, "[JVM_ATTACH]: Failed to set timeout to socket of pid %d\n", pid);
        close(fd);
        return -1;
    }

    int ret = __read_rsp(fd, argc, argv);

    close(fd);
    return ret;
}

void __get_euid_egid(int pid, uid_t *targetUid, gid_t *targetGid)
{
    uid_t eUid = geteuid();
    gid_t eGid = getegid();
    char path[PATH_LEN];

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE* status_file = fopen(path, "r");
    if (status_file == NULL) {
        goto out;
    }

    char* line = NULL;
    size_t size;
    while (getline(&line, &size, status_file) != -1) {
        if (strncmp(line, "Uid:", 4) == 0 && strtok(line + 4, "\t ") != NULL) {
            eUid = (uid_t)atoi(strtok(NULL, "\t "));
        } else if (strncmp(line, "Gid:", 4) == 0 && strtok(line + 4, "\t ") != NULL) {
            eGid = (gid_t)atoi(strtok(NULL, "\t "));
        }
    }

    if (line != NULL) {
        free(line);
    }
    fclose(status_file);

out:
    *targetUid = eUid;
    *targetGid = eGid;
}

int main(int argc, char** argv)
{
    int ret = 0;
    if (argc < ARGS_NUM) {
        fprintf(stderr, "[JVM_ATTACH]: wrong argv\n");
        ret = -1;
        goto out;
    }

    int pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "[JVM_ATTACH]: %s is not a valid process ID\n", argv[1]);
        ret = -1;
        goto out;
    }
    int cur_pid = pid;

    int nspid = atoi(argv[2]);
    if (nspid <= 0) {
        fprintf(stderr, "[JVM_ATTACH]: %s is not a valid ns process ID\n", argv[2]); // argv 2 is pid
        ret = -1;
        goto out;
    }

    uid_t targetUid;
    gid_t targetGid;
    __get_euid_egid(pid, &targetUid, &targetGid);

    ret = __ns_enter(pid, nspid, "mnt", &cur_pid);
    if (ret != 0) {
        fprintf(stderr, "[JVM_ATTACH]: nsenter fail\n");
        ret = -1;
        goto out;
    }

    if ((setegid(targetGid) != 0) || (seteuid(targetUid) != 0)) {
        fprintf(stderr, "[JVM_ATTACH]: setegid %d or seteuid %d fail\n", targetGid, targetUid);
        ret = -1;
        goto out;
    }

    ret = get_tmp_path_r(cur_pid, tmp_path, sizeof(tmp_path));
    if (ret != 0) {
        fprintf(stderr, "[JVM_ATTACH]: get_tmp_path_r %s fail\n", tmp_path);
        ret = -1;
        goto out;
    }

    (void)signal(SIGPIPE, SIG_IGN);

    ret = __jattach(pid, nspid, argc - 3, argv + 3); // argv 3 is cmd str

out:
/*
    ret error code may be：
    private static final int JNI_ENOMEM                 = -4
    private static final int ATTACH_ERROR_BADJAR        = 100
    private static final int ATTACH_ERROR_NOTONCP       = 101
    private static final int ATTACH_ERROR_STARTFAIL     = 102
*/
    printf("%d", ret);
    return ret;
}