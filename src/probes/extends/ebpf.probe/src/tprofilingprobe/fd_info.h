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
 * Description: header file for enriching fd information of thread profiling event
 ******************************************************************************/
#ifndef __FD_INFO_H__
#define __FD_INFO_H__

#include <uthash.h>

#define MAX_CACHE_FD_NUM 1024
#define MAX_PATH_SIZE 128
#define MAX_NET_CONN_INFO_SIZE 128

#define CMD_LSOF_SOCK_INFO "lsof -a -nP -d %d -p %d -FnPt"
#define MAX_CMD_SIZE 64

#define SOCK_TYPE_IPV4_STR "IPv4"
#define SOCK_TYPE_IPV6_STR "IPv6"
#define SOCK_PROTO_TYPE_TCP_STR "TCP"
#define SOCK_PROTO_TYPE_UDP_STR "UDP"

enum fd_type {
    FD_TYPE_REG,
    FD_TYPE_SOCK,
    FD_TYPE_UNSUPPORTED
};

enum sock_type {
    SOCK_TYPE_IPV4,
    SOCK_TYPE_IPV6,
    SOCK_TYPE_UNSUPPORTED
};

enum proto_type {
    SOCK_PROTO_TYPE_TCP,
    SOCK_PROTO_TYPE_UDP,
    SOCK_PROTO_TYPE_UNSUPPORTED
};

typedef struct {
    char name[MAX_PATH_SIZE];
} reg_info_t;

typedef struct {
    enum sock_type type;
    union {
        struct {
            enum proto_type proto;
            char conn[MAX_NET_CONN_INFO_SIZE];
        } ip_info;
    };
} sock_info_t;

typedef struct {
    int fd;
    enum fd_type type;
    union {
        reg_info_t reg_info;
        sock_info_t sock_info;
    };
    UT_hash_handle hh;
} fd_info_t;

void HASH_add_fd_info(fd_info_t **fd_table, fd_info_t *fd_info);
void HASH_del_fd_info(fd_info_t **fd_table, fd_info_t *fd_info);
fd_info_t *HASH_find_fd_info(fd_info_t **fd_table, int fd);
unsigned int HASH_count_fd_table(fd_info_t **fd_table);

void HASH_add_fd_info_with_LRU(fd_info_t **fd_table, fd_info_t *fd_info);
fd_info_t *HASH_find_fd_info_with_LRU(fd_info_t **fd_table, int fd);

int fill_fd_info(fd_info_t *fd_info, int tgid);

void free_fd_info(fd_info_t *fd_info);
void free_fd_table(fd_info_t **fd_table);

#endif