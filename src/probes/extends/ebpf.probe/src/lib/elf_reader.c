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
 * Author: dowzyx
 * Create: 2021-12-08
 * Description: elf parse
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <gelf.h>
#include <sys/stat.h>
#include <errno.h>

#include "bpf.h"
#include "elf_reader.h"
#include "container.h"

#define DEFAULT_PATH_LIST   "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin"

#define COMMAND_REAL_PATH "/usr/bin/realpath %s"

#define COMMAND_GLIBC_PATH \
    "/usr/bin/ldd /bin/ls | grep \"libc.so\" | awk -F '=>' '{print $2}' | awk '{print $1}'"
#define COMMAND_ENV_PATH    "/usr/bin/env | grep PATH | awk -F '=' '{print $2}'"

#if BPF_ELF_DESC("get glibc path")
static int __get_link_path(const char* link, char *path, unsigned int len)
{
    char command[COMMAND_LEN];

    command[0] = 0;
    (void)snprintf(command, COMMAND_LEN, COMMAND_REAL_PATH, link);
    return exec_cmd(command, path, len);
}

static int __do_get_glibc_path_host(char *path, unsigned int len)
{
    int ret;
    FILE *f = NULL;
    char line[LINE_BUF_LEN];

    path[0] = 0;
    line[0] = 0;

    f = popen(COMMAND_GLIBC_PATH, "r");
    if (f == NULL)
        return -1;

    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        (void)pclose(f);
        return -1;
    }

    split_newline_symbol(line);
    ret = __get_link_path((const char *)line, path, len);
    if (ret < 0) {
        (void)pclose(f);
        return -1;
    }

    (void)pclose(f);
    return 0;
}

static int __do_get_glibc_path_container(const char *container_id, char *path, unsigned int len)
{
    int ret;
    char container_abs_path[PATH_LEN];
    char glibc_path[PATH_LEN];
    char glibc_abs_path[PATH_LEN];

    container_abs_path[0] = 0;
    glibc_path[0] = 0;
    glibc_abs_path[0] = 0;

    ret = get_container_merged_path(container_id, container_abs_path, PATH_LEN);
    if (ret < 0)
        return ret;

    ret = exec_container_command(container_id, COMMAND_GLIBC_PATH, glibc_path, PATH_LEN);
    if (ret < 0)
        return ret;

    (void)snprintf(glibc_abs_path, PATH_LEN, "%s/%s", container_abs_path, glibc_path);

    split_newline_symbol(glibc_abs_path);
    ret = __get_link_path((const char *)glibc_abs_path, path, len);
    if (ret < 0)
        return -1;

    return 0;
}

int get_glibc_path(const char *container_id, char *path, unsigned int len)
{
    if (container_id == NULL || container_id[0] == 0)
        return __do_get_glibc_path_host(path, len);

    return __do_get_glibc_path_container(container_id, path, len);
}
#endif

#if BPF_ELF_DESC("get exec path")
static bool __is_exec_file(const char *abs_path)
{
    struct stat st;

    if (stat(abs_path, &st) < 0)
        return false;

    if (st.st_mode & S_IEXEC)
        return true;

    return false;
}

static int __do_get_path_from_host(const char *binary_file, char **res_buf, int res_len)
{
    int r_len = 0;
    char *p = NULL;
    char *syspath_ptr = getenv("PATH");
    char syspath[PATH_LEN];

    if (syspath_ptr == NULL) {
        (void)snprintf((void *)syspath, PATH_LEN, "%s", DEFAULT_PATH_LIST);
        syspath_ptr = syspath;
    }

    p = strtok(syspath_ptr, ":");
    while (p != NULL) {
        char abs_path[PATH_LEN] = {0};
        (void)snprintf((char *)abs_path, PATH_LEN, "%s/%s", p, binary_file);
        if (__is_exec_file(abs_path)) {
            if (r_len >= res_len) {
                printf("host abs_path's num[%d] beyond res_buf's size[%d].\n", r_len, res_len);
                break;
            }
            res_buf[r_len] = (char *)malloc(PATH_LEN * sizeof(char));
            (void)snprintf(res_buf[r_len], PATH_LEN, "%s", abs_path);
            r_len++;
        }
        p = strtok(NULL, ":");
    }

    return r_len;
}

static int __do_get_path_from_container(const char *binary_file, const char *container_id, char **res_buf, int res_len)
{
    int ret = -1;
    int r_len = 0;
    char *p = NULL;
    char syspath[PATH_LEN] = {0};
    char container_abs_path[PATH_LEN] = {0};

    ret = get_container_merged_path(container_id, container_abs_path, PATH_LEN);
    if (ret < 0) {
        printf("get container merged_path fail.\n");
        return ret;
    }

    ret = exec_container_command(container_id, COMMAND_ENV_PATH, syspath, PATH_LEN);
    if (ret < 0) {
        printf("get container's env PATH fail.\n");
        return ret;
    }

    if (syspath[0] == 0)
        (void)snprintf((void *)syspath, PATH_LEN, "%s", DEFAULT_PATH_LIST);

    p = strtok((void *)syspath, ":");
    while (p != NULL) {
        char abs_path[PATH_LEN] = {0};
        (void)snprintf((char *)abs_path, PATH_LEN, "%s%s/%s", container_abs_path, p, binary_file);
        if (__is_exec_file(abs_path)) {
            if (r_len >= res_len) {
                printf("container abs_path's num[%d] beyond res_buf's size[%d].\n", r_len, res_len);
                break;
            }
            res_buf[r_len] = (char *)malloc(PATH_LEN * sizeof(char));
            (void)snprintf(res_buf[r_len], PATH_LEN, "%s", abs_path);
            r_len++;
        }
        p = strtok(NULL, ":");
    }

    return r_len;
}

int get_exec_file_path(const char *binary_file, const char *specified_path, const char *container_id,
                        char **res_buf, int res_len)
{
    int ret_path_num = -1;

    if (binary_file == NULL || !strcmp(binary_file, "NULL")) {
        printf("please input binary_file name.\n");
        return -1;
    }
    /* specified file path */
    if (specified_path != NULL && strlen(specified_path)) {
        if (!__is_exec_file(specified_path)) {
            printf("specified path check error[%d].\n", errno);
            return -1;
        }
        res_buf[0] = (char *)malloc(PATH_LEN * sizeof(char));
        (void)snprintf(res_buf[0], PATH_LEN, "%s", specified_path);
        return 1;
    }

    if (container_id == NULL || !strcmp(container_id, "NULL")) {
        /* exec file in host */
        ret_path_num = __do_get_path_from_host(binary_file, res_buf, res_len);
    } else {
        /* exec file in container */
        ret_path_num = __do_get_path_from_container(binary_file, container_id, res_buf, res_len);
    }

    if (ret_path_num == 0) {
        printf("no executable in system default path, please specify abs_path.\n");
        return -1;
    }
    return ret_path_num;
}

void free_exec_path_buf(char **ptr, int len)
{
    for (int i = 0; i < len; i++) {
        if (ptr[i] != NULL) {
            free(ptr[i]);
            ptr[i] = NULL;
        }
    }
}
#endif

