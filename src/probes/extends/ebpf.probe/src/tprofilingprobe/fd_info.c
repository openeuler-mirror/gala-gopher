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
 * Create: 2023-04-03
 * Description: enriching fd information of thread profiling event
 ******************************************************************************/
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "common.h"
#include "fd_info.h"

void HASH_add_fd_info(fd_info_t **fd_table, fd_info_t *fd_info)
{
    HASH_ADD_INT(*fd_table, fd, fd_info);
}

void HASH_del_fd_info(fd_info_t **fd_table, fd_info_t *fd_info)
{
    HASH_DEL(*fd_table, fd_info);
}

fd_info_t *HASH_find_fd_info(fd_info_t **fd_table, int fd)
{
    fd_info_t *fi;

    HASH_FIND_INT(*fd_table, &fd, fi);
    return fi;
}

unsigned int HASH_count_fd_table(fd_info_t **fd_table)
{
    return HASH_COUNT(*fd_table);
}

void HASH_add_fd_info_with_LRU(fd_info_t **fd_table, fd_info_t *fd_info)
{
    fd_info_t *fi, *tmp;

    if (HASH_COUNT(*fd_table) >= MAX_CACHE_FD_NUM) {
        HASH_ITER(hh, *fd_table, fi, tmp) {
            HASH_DEL(*fd_table, fi);
            free_fd_info(fi);
            break;
        }
    }

    HASH_add_fd_info(fd_table, fd_info);
}

fd_info_t *HASH_find_fd_info_with_LRU(fd_info_t **fd_table, int fd)
{
    fd_info_t *fi;

    fi = HASH_find_fd_info(fd_table, fd);
    if (fi) {
        HASH_del_fd_info(fd_table, fi);
        HASH_add_fd_info(fd_table, fi);
    }

    return fi;
}

static int fill_reg_file_info(fd_info_t *fd_info, const char *fd_path)
{
    int ret;

    fd_info->type = FD_TYPE_REG;
    ret = readlink(fd_path, fd_info->reg_info.name, sizeof(fd_info->reg_info.name));
    if (ret < 0 || ret >= sizeof(fd_info->reg_info.name)) {
        fprintf(stderr, "ERROR: read link of fd %s failed.\n", fd_path);
        return -1;
    }
    fd_info->reg_info.name[ret] = '\0';

    return 0;
}

static enum sock_type get_sock_type(char *sock_type_s)
{
    if (strcmp(sock_type_s, SOCK_TYPE_IPV4_STR) == 0) {
        return SOCK_TYPE_IPV4;
    } else if (strcmp(sock_type_s, SOCK_TYPE_IPV6_STR) == 0) {
        return SOCK_TYPE_IPV6;
    }

    return SOCK_TYPE_UNSUPPORTED;
}

static enum proto_type get_proto_type(char *proto_type_s)
{
    if (strcmp(proto_type_s, SOCK_PROTO_TYPE_TCP_STR) == 0) {
        return SOCK_PROTO_TYPE_TCP;
    } else if (strcmp(proto_type_s, SOCK_PROTO_TYPE_UDP_STR) == 0) {
        return SOCK_PROTO_TYPE_UDP;
    }

    return SOCK_PROTO_TYPE_UNSUPPORTED;
}

static int fill_sock_info(fd_info_t *fd_info, int tgid)
{
    char cmd[MAX_CMD_SIZE];
    char buf[64];
    char conn[64];
    char sock_type[8];
    char proto_type[8];
    FILE *file;
    sock_info_t *si = &fd_info->sock_info;
    int ret;

    conn[0] = 0;
    sock_type[0] = 0;
    proto_type[0] = 0;

    fd_info->type = FD_TYPE_SOCK;

    ret = snprintf(cmd, sizeof(cmd), CMD_LSOF_SOCK_INFO, fd_info->fd, tgid);
    if (ret < 0 || ret >= sizeof(cmd)) {
        fprintf(stderr, "ERROR: Failed to set lsof command.\n");
        return -1;
    }

    file = popen(cmd, "r");
    if (file == NULL) {
        fprintf(stderr, "ERROR: Failed to execute lsof command:%s\n", cmd);
        return -1;
    }

    while (fgets(buf, sizeof(buf), file) != NULL) {
        SPLIT_NEWLINE_SYMBOL(buf);
        switch (buf[0]) {
            case 't':
                (void)snprintf(sock_type, sizeof(sock_type), "%s", buf + 1);
                break;
            case 'P':
                (void)snprintf(proto_type, sizeof(proto_type), "%s", buf + 1);
                break;
            case 'n':
                (void)snprintf(conn, sizeof(conn), "%s", buf + 1);
                break;
            default:
                continue;
        }
    }

    si->type = get_sock_type(sock_type);
    if (si->type == SOCK_TYPE_IPV4 || si->type == SOCK_TYPE_IPV6) {
        si->ip_info.proto = get_proto_type(proto_type);
        (void)snprintf(si->ip_info.conn, sizeof(si->ip_info.conn), "%s", conn);
    }

    pclose(file);
    return 0;
}

int fill_fd_info(fd_info_t *fd_info, int tgid)
{
    char fd_path[MAX_PATH_SIZE];
    struct stat st;
    int ret;

    ret = snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", tgid, fd_info->fd);
    if (ret < 0 || ret >= sizeof(fd_path)) {
        fprintf(stderr, "ERROR: Failed to get fd path.\n");
        return -1;
    }

    if (stat(fd_path, &st)) {
        return -1;
    }

    switch (st.st_mode & S_IFMT) {
        case S_IFREG:
            return fill_reg_file_info(fd_info, fd_path);
        case S_IFSOCK:
            return fill_sock_info(fd_info, tgid);
        default:
            fprintf(stderr, "WARN: Unsupported file type of fd %s.\n", fd_path);
            fd_info->type = FD_TYPE_UNSUPPORTED;
            return 0;
    }
}

void free_fd_info(fd_info_t *fd_info)
{
    free(fd_info);
}

void free_fd_table(fd_info_t **fd_table)
{
    fd_info_t *fi, *tmp;

    HASH_ITER(hh, *fd_table, fi, tmp) {
        HASH_DEL(*fd_table, fi);
        free_fd_info(fi);
    }
}